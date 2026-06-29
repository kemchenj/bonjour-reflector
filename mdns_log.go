package main

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/layers"
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
	SourcePool uint16
	TargetPool uint16
	SrcMAC     string
	Stage      string
	Reason     string
	Kind       string
	RecordType string
	Name       string
	Value      string
	Details    string
}

type mdnsLogKey struct {
	sourcePool uint16
	targetPool uint16
	stage      string
	reason     string
	kind       string
	recordType string
	name       string
	value      string
	details    string
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
		sourcePool: event.SourcePool,
		targetPool: event.TargetPool,
		stage:      normalizeMDNSLogStage(event.Stage),
		reason:     event.Reason,
		kind:       event.Kind,
		recordType: event.RecordType,
		name:       event.Name,
		value:      event.Value,
		details:    event.Details,
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
	if a.sourcePool != b.sourcePool {
		if a.sourcePool < b.sourcePool {
			return -1
		}
		return 1
	}
	if a.targetPool != b.targetPool {
		if a.targetPool < b.targetPool {
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
		return fmt.Sprintf("vlan%d rx %s", key.sourcePool, record)
	case "skip":
		if key.targetPool == 0 {
			return fmt.Sprintf("vlan%d skip reason=%s %s", key.sourcePool, key.reason, record)
		}
		return fmt.Sprintf("vlan%d -> vlan%d skip reason=%s %s", key.sourcePool, key.targetPool, key.reason, record)
	case "error":
		return fmt.Sprintf("vlan%d -> vlan%d error reason=%s %s", key.sourcePool, key.targetPool, key.reason, record)
	default:
		return fmt.Sprintf("vlan%d -> vlan%d %s", key.sourcePool, key.targetPool, record)
	}
}

func emitForwardedMDNSEvents(sink *mdnsEventSink, bonjourPacket *bonjourPacket, sourcePool, targetPool uint16, sourceMAC string) {
	if sink == nil || bonjourPacket == nil || bonjourPacket.dns == nil {
		return
	}
	for _, event := range mdnsEventsFromDNSWithDetails(bonjourPacket.dns, sourcePool, targetPool, sourceMAC, sink.debugEnabled()) {
		sink.emit(event)
	}
}

func emitDebugMDNSEvents(sink *mdnsEventSink, bonjourPacket *bonjourPacket, sourcePool, targetPool uint16, stage, reason, sourceMAC string) {
	if !sink.debugEnabled() || bonjourPacket == nil || bonjourPacket.dns == nil {
		return
	}
	for _, event := range mdnsEventsFromDNSWithDetails(bonjourPacket.dns, sourcePool, targetPool, sourceMAC, true) {
		event.Stage = stage
		event.Reason = reason
		sink.emit(event)
	}
}

func mdnsEventsFromDNS(dns *layers.DNS, sourcePool, targetPool uint16, sourceMAC string) []mdnsLogEvent {
	return mdnsEventsFromDNSWithDetails(dns, sourcePool, targetPool, sourceMAC, false)
}

func mdnsEventsFromDNSWithDetails(dns *layers.DNS, sourcePool, targetPool uint16, sourceMAC string, includeDetails bool) []mdnsLogEvent {
	if dns == nil {
		return nil
	}

	if !dns.QR {
		events := make([]mdnsLogEvent, 0, len(dns.Questions))
		for _, question := range dns.Questions {
			events = append(events, mdnsLogEvent{
				SourcePool: sourcePool,
				TargetPool: targetPool,
				SrcMAC:     sourceMAC,
				Kind:       "query",
				RecordType: dnsTypeName(question.Type),
				Name:       dnsName(question.Name),
				Details:    mdnsQuestionDetails(question, includeDetails),
			})
		}
		return events
	}

	events := []mdnsLogEvent{}
	events = appendMDNSRecordEvents(events, dns.Answers, sourcePool, targetPool, sourceMAC, includeDetails)
	events = appendMDNSRecordEvents(events, dns.Authorities, sourcePool, targetPool, sourceMAC, includeDetails)
	events = appendMDNSRecordEvents(events, dns.Additionals, sourcePool, targetPool, sourceMAC, includeDetails)
	return events
}

func appendMDNSRecordEvents(events []mdnsLogEvent, records []layers.DNSResourceRecord, sourcePool, targetPool uint16, sourceMAC string, includeDetails bool) []mdnsLogEvent {
	for _, record := range records {
		recordType := dnsTypeName(record.Type)
		value, ok := dnsRecordValue(record)
		if !ok {
			continue
		}

		kind := "announce"
		if record.TTL == 0 {
			kind = "goodbye"
		}

		events = append(events, mdnsLogEvent{
			SourcePool: sourcePool,
			TargetPool: targetPool,
			SrcMAC:     sourceMAC,
			Kind:       kind,
			RecordType: recordType,
			Name:       dnsName(record.Name),
			Value:      value,
			Details:    mdnsRecordDetails(record, includeDetails),
		})
	}
	return events
}

func mdnsQuestionDetails(question layers.DNSQuestion, includeDetails bool) string {
	if !includeDetails {
		return ""
	}

	responseMode := "QM"
	if dnsClassHasFlagBit(question.Class) {
		responseMode = "QU"
	}
	return fmt.Sprintf("q=%s class=%s", responseMode, dnsClassName(question.Class))
}

func mdnsRecordDetails(record layers.DNSResourceRecord, includeDetails bool) string {
	if !includeDetails {
		return ""
	}
	return fmt.Sprintf("ttl=%d cache_flush=%t class=%s", record.TTL, dnsClassHasFlagBit(record.Class), dnsClassName(record.Class))
}

func dnsRecordValue(record layers.DNSResourceRecord) (string, bool) {
	switch record.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		if len(record.IP) == 0 {
			return "", false
		}
		return record.IP.String(), true
	case layers.DNSTypePTR:
		return dnsName(record.PTR), true
	case layers.DNSTypeSRV:
		return fmt.Sprintf("%s:%d", dnsName(record.SRV.Name), record.SRV.Port), true
	case layers.DNSTypeTXT:
		return summarizeTXT(record.TXTs), true
	default:
		return "", false
	}
}

func dnsTypeName(dnsType layers.DNSType) string {
	switch dnsType {
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeSRV:
		return "SRV"
	case layers.DNSTypeTXT:
		return "TXT"
	default:
		return fmt.Sprintf("TYPE%d", uint16(dnsType))
	}
}

func dnsClassName(dnsClass layers.DNSClass) string {
	baseClass := layers.DNSClass(uint16(dnsClass) &^ mdnsClassFlagBit)
	switch baseClass {
	case layers.DNSClassIN:
		return "IN"
	case layers.DNSClassCS:
		return "CS"
	case layers.DNSClassCH:
		return "CH"
	case layers.DNSClassHS:
		return "HS"
	case layers.DNSClassAny:
		return "ANY"
	default:
		return fmt.Sprintf("CLASS%d", uint16(baseClass))
	}
}

func dnsClassHasFlagBit(dnsClass layers.DNSClass) bool {
	return uint16(dnsClass)&mdnsClassFlagBit != 0
}

func dnsName(name []byte) string {
	if len(name) == 0 {
		return "."
	}
	return string(name)
}

func summarizeTXT(txts [][]byte) string {
	if len(txts) == 0 {
		return "keys=0"
	}

	keys := make([]string, 0, len(txts))
	for _, txt := range txts {
		key := string(txt)
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
