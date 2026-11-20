package main

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	mdnsLogBufferSize  = 4096
	mdnsLogSourceLimit = 4
	mdnsClassFlagBit   = 0x8000
)

type mdnsEventSink struct {
	events   chan mdnsLogEvent
	stop     chan struct{}
	done     chan struct{}
	dropped  uint64
	stopping uint32
	debug    bool
}

type mdnsLogEvent struct {
	SourceInterface string
	TargetInterface string
	SrcMAC          string
	Stage           string
	Reason          string
	Kind            string
	RecordType      string
	Name            string
	Value           string
	Details         string
}

type mdnsLogKey struct {
	sourceInterface string
	targetInterface string
	stage           string
	reason          string
	kind            string
	recordType      string
	name            string
	value           string
	details         string
}

type mdnsLogBucket struct {
	count   int
	sources map[string]struct{}
}

type mdnsLogAggregator struct {
	interval    time.Duration
	sourceLimit int
	events      map[mdnsLogKey]*mdnsLogBucket
	total       int
}

func startMDNSSummaryLogger(interval time.Duration, debug bool) *mdnsEventSink {
	sink := &mdnsEventSink{
		events: make(chan mdnsLogEvent, mdnsLogBufferSize),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		debug:  debug,
	}
	go runMDNSSummaryLogger(sink, interval)
	return sink
}

func runMDNSSummaryLogger(sink *mdnsEventSink, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(sink.done)

	aggregator := newMDNSLogAggregator(interval)
	if sink.debug {
		aggregator.sourceLimit = mdnsLogSourceLimit
	}
	for {
		select {
		case event := <-sink.events:
			aggregator.add(event)
		case <-ticker.C:
			dropped := atomic.SwapUint64(&sink.dropped, 0)
			aggregator.flush(dropped, log.Printf)
		case <-sink.stop:
			drainMDNSLogEvents(sink, aggregator)
			dropped := atomic.SwapUint64(&sink.dropped, 0)
			aggregator.flush(dropped, log.Printf)
			return
		}
	}
}

func drainMDNSLogEvents(sink *mdnsEventSink, aggregator *mdnsLogAggregator) {
	for {
		select {
		case event := <-sink.events:
			aggregator.add(event)
		default:
			return
		}
	}
}

func (sink *mdnsEventSink) emit(event mdnsLogEvent) {
	if sink == nil {
		return
	}
	if atomic.LoadUint32(&sink.stopping) != 0 {
		return
	}
	select {
	case sink.events <- event:
	default:
		atomic.AddUint64(&sink.dropped, 1)
	}
}

func (sink *mdnsEventSink) debugEnabled() bool {
	return sink != nil && sink.debug
}

func (sink *mdnsEventSink) stopAndFlush() {
	if sink == nil {
		return
	}
	if !atomic.CompareAndSwapUint32(&sink.stopping, 0, 1) {
		<-sink.done
		return
	}
	close(sink.stop)
	<-sink.done
}

func newMDNSLogAggregator(interval time.Duration) *mdnsLogAggregator {
	return &mdnsLogAggregator{
		interval: interval,
		events:   make(map[mdnsLogKey]*mdnsLogBucket),
	}
}

func (aggregator *mdnsLogAggregator) add(event mdnsLogEvent) {
	if event.Kind == "" || event.RecordType == "" || event.Name == "" {
		return
	}

	key := mdnsLogKey{
		sourceInterface: event.SourceInterface,
		targetInterface: event.TargetInterface,
		stage:           normalizeMDNSLogStage(event.Stage),
		reason:          event.Reason,
		kind:            event.Kind,
		recordType:      event.RecordType,
		name:            event.Name,
		value:           event.Value,
		details:         event.Details,
	}
	bucket := aggregator.events[key]
	if bucket == nil {
		bucket = &mdnsLogBucket{sources: make(map[string]struct{})}
		aggregator.events[key] = bucket
	}
	bucket.count++
	if event.SrcMAC != "" {
		bucket.sources[event.SrcMAC] = struct{}{}
	}
	aggregator.total++
}

func (aggregator *mdnsLogAggregator) flush(dropped uint64, logf func(string, ...interface{})) bool {
	if aggregator.total == 0 && dropped == 0 {
		return false
	}

	logf("mdns summary window=%s events=%d dropped_log_events=%d", aggregator.interval, aggregator.total, dropped)

	keys := make([]mdnsLogKey, 0, len(aggregator.events))
	for key := range aggregator.events {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return compareMDNSLogKeys(keys[i], keys[j]) < 0
	})

	for _, key := range keys {
		bucket := aggregator.events[key]
		sourceSamples := formatMDNSLogSourceSamples(bucket.sources, aggregator.sourceLimit)
		if sourceSamples != "" {
			logf("  %s count=%d sources=%d source_macs=%s", formatMDNSLogKey(key), bucket.count, len(bucket.sources), sourceSamples)
			continue
		}
		logf("  %s count=%d sources=%d", formatMDNSLogKey(key), bucket.count, len(bucket.sources))
	}

	aggregator.events = make(map[mdnsLogKey]*mdnsLogBucket)
	aggregator.total = 0
	return true
}

func compareMDNSLogKeys(a, b mdnsLogKey) int {
	if a.sourceInterface != b.sourceInterface {
		if a.sourceInterface < b.sourceInterface {
			return -1
		}
		return 1
	}
	if a.targetInterface != b.targetInterface {
		if a.targetInterface < b.targetInterface {
			return -1
		}
		return 1
	}
	fieldsA := []string{a.stage, a.reason, a.kind, a.recordType, a.name, a.value, a.details}
	fieldsB := []string{b.stage, b.reason, b.kind, b.recordType, b.name, b.value, b.details}
	for i := range fieldsA {
		if fieldsA[i] < fieldsB[i] {
			return -1
		}
		if fieldsA[i] > fieldsB[i] {
			return 1
		}
	}
	return 0
}

func normalizeMDNSLogStage(stage string) string {
	if stage == "" {
		return "forward"
	}
	return stage
}

func formatMDNSLogKey(key mdnsLogKey) string {
	record := fmt.Sprintf("%s %s %s", key.kind, key.recordType, key.name)
	if key.value != "" {
		record += " -> " + key.value
	}
	if key.details != "" {
		record += " " + key.details
	}

	switch key.stage {
	case "rx":
		return fmt.Sprintf("%s rx %s", key.sourceInterface, record)
	case "error":
		return fmt.Sprintf("%s -> %s error reason=%s %s", key.sourceInterface, key.targetInterface, key.reason, record)
	default:
		return fmt.Sprintf("%s -> %s %s", key.sourceInterface, key.targetInterface, record)
	}
}

func emitForwardedMDNSEvents(sink *mdnsEventSink, bonjourPacket *bonjourPacket, sourceInterface, targetInterface string, sourceMAC string) {
	if sink == nil || bonjourPacket == nil || bonjourPacket.dns == nil {
		return
	}
	for _, event := range mdnsEventsFromDNSWithDetails(bonjourPacket.dns, sourceInterface, targetInterface, sourceMAC, sink.debugEnabled()) {
		sink.emit(event)
	}
}

func emitDebugMDNSEvents(sink *mdnsEventSink, bonjourPacket *bonjourPacket, sourceInterface, targetInterface string, stage, reason, sourceMAC string) {
	if stage == "error" {
		log.Printf("mDNS forwarding error %s -> %s source=%s: %s", sourceInterface, targetInterface, sourceMAC, reason)
	}
	if !sink.debugEnabled() || bonjourPacket == nil || bonjourPacket.dns == nil {
		return
	}
	for _, event := range mdnsEventsFromDNSWithDetails(bonjourPacket.dns, sourceInterface, targetInterface, sourceMAC, true) {
		event.Stage = stage
		event.Reason = reason
		sink.emit(event)
	}
}

func mdnsEventsFromDNS(msg *dns.Msg, sourceInterface, targetInterface string, sourceMAC string) []mdnsLogEvent {
	return mdnsEventsFromDNSWithDetails(msg, sourceInterface, targetInterface, sourceMAC, false)
}

func mdnsEventsFromDNSWithDetails(msg *dns.Msg, sourceInterface, targetInterface string, sourceMAC string, includeDetails bool) []mdnsLogEvent {
	if msg == nil {
		return nil
	}

	if !msg.Response {
		events := make([]mdnsLogEvent, 0, len(msg.Question))
		for _, question := range msg.Question {
			events = append(events, mdnsLogEvent{
				SourceInterface: sourceInterface,
				TargetInterface: targetInterface,
				SrcMAC:          sourceMAC,
				Kind:            "query",
				RecordType:      dnsTypeName(question.Qtype),
				Name:            dnsName(question.Name),
				Details:         mdnsQuestionDetails(question, includeDetails),
			})
		}
		return events
	}

	events := []mdnsLogEvent{}
	events = appendMDNSRecordEvents(events, msg.Answer, sourceInterface, targetInterface, sourceMAC, includeDetails)
	events = appendMDNSRecordEvents(events, msg.Ns, sourceInterface, targetInterface, sourceMAC, includeDetails)
	events = appendMDNSRecordEvents(events, msg.Extra, sourceInterface, targetInterface, sourceMAC, includeDetails)
	return events
}

func appendMDNSRecordEvents(events []mdnsLogEvent, records []dns.RR, sourceInterface, targetInterface string, sourceMAC string, includeDetails bool) []mdnsLogEvent {
	for _, record := range records {
		header := record.Header()
		recordType := dnsTypeName(header.Rrtype)
		value, ok := dnsRecordValue(record)
		if !ok {
			continue
		}

		kind := "announce"
		if header.Ttl == 0 {
			kind = "goodbye"
		}

		events = append(events, mdnsLogEvent{
			SourceInterface: sourceInterface,
			TargetInterface: targetInterface,
			SrcMAC:          sourceMAC,
			Kind:            kind,
			RecordType:      recordType,
			Name:            dnsName(header.Name),
			Value:           value,
			Details:         mdnsRecordDetails(header, includeDetails),
		})
	}
	return events
}

func mdnsQuestionDetails(question dns.Question, includeDetails bool) string {
	if !includeDetails {
		return ""
	}

	responseMode := "QM"
	if dnsClassHasFlagBit(question.Qclass) {
		responseMode = "QU"
	}
	return fmt.Sprintf("q=%s class=%s", responseMode, dnsClassName(question.Qclass))
}

func mdnsRecordDetails(record *dns.RR_Header, includeDetails bool) string {
	if !includeDetails {
		return ""
	}
	return fmt.Sprintf("ttl=%d cache_flush=%t class=%s", record.Ttl, dnsClassHasFlagBit(record.Class), dnsClassName(record.Class))
}

func dnsRecordValue(record dns.RR) (string, bool) {
	switch r := record.(type) {
	case *dns.A:
		if len(r.A) > 0 {
			return r.A.String(), true
		}
	case *dns.AAAA:
		if len(r.AAAA) > 0 {
			return r.AAAA.String(), true
		}
	case *dns.PTR:
		return dnsName(r.Ptr), true
	case *dns.SRV:
		return fmt.Sprintf("%s:%d", dnsName(r.Target), r.Port), true
	case *dns.TXT:
		return summarizeTXT(r.Txt), true
	}
	return "", false
}

func dnsTypeName(dnsType uint16) string {
	switch dnsType {
	case dns.TypeA:
		return "A"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypePTR:
		return "PTR"
	case dns.TypeSRV:
		return "SRV"
	case dns.TypeTXT:
		return "TXT"
	default:
		return fmt.Sprintf("TYPE%d", uint16(dnsType))
	}
}

func dnsClassName(class uint16) string {
	return dns.Class(class &^ mdnsClassFlagBit).String()
}

func dnsClassHasFlagBit(class uint16) bool {
	return class&mdnsClassFlagBit != 0
}

func dnsName(name string) string {
	if name == "" || name == "." {
		return "."
	}
	if !strings.Contains(name, "\\") {
		return strings.TrimSuffix(name, ".")
	}
	// DNS 文本会转义空格和非 ASCII 字节；摘要继续显示原始设备名。
	var wire [255]byte
	n, err := dns.PackDomainName(name, wire[:], 0, nil, false)
	if err != nil {
		return name
	}
	var labels []string
	for i := 0; i < n && wire[i] != 0; {
		size := int(wire[i])
		labels = append(labels, string(wire[i+1:i+1+size]))
		i += 1 + size
	}
	return strings.Join(labels, ".")
}

func summarizeTXT(txts []string) string {
	if len(txts) == 0 {
		return "keys=0"
	}

	keys := make([]string, 0, len(txts))
	for _, key := range txts {
		if idx := strings.IndexByte(key, '='); idx >= 0 {
			key = key[:idx]
		}
		if key != "" {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return "keys=0"
	}
	sort.Strings(keys)
	return "keys=" + strings.Join(keys, ",")
}

func hardwareAddrString(addr *net.HardwareAddr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func formatMDNSLogSourceSamples(sources map[string]struct{}, limit int) string {
	if limit <= 0 || len(sources) == 0 {
		return ""
	}

	sourceMACs := make([]string, 0, len(sources))
	for source := range sources {
		sourceMACs = append(sourceMACs, source)
	}
	sort.Strings(sourceMACs)

	if len(sourceMACs) <= limit {
		return strings.Join(sourceMACs, ",")
	}
	return fmt.Sprintf("%s,+%d", strings.Join(sourceMACs[:limit], ","), len(sourceMACs)-limit)
}
