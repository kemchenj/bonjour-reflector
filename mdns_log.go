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

const mdnsLogBufferSize = 4096

type mdnsEventSink struct {
	events  chan mdnsLogEvent
	dropped uint64
}

type mdnsLogEvent struct {
	SourcePool uint16
	TargetPool uint16
	SrcMAC     string
	Kind       string
	RecordType string
	Name       string
	Value      string
}

type mdnsLogKey struct {
	sourcePool uint16
	targetPool uint16
	kind       string
	recordType string
	name       string
	value      string
}

type mdnsLogBucket struct {
	count   int
	sources map[string]struct{}
}

type mdnsLogAggregator struct {
	interval time.Duration
	events   map[mdnsLogKey]*mdnsLogBucket
	total    int
}

func startMDNSSummaryLogger(interval time.Duration) *mdnsEventSink {
	sink := &mdnsEventSink{
		events: make(chan mdnsLogEvent, mdnsLogBufferSize),
	}
	go runMDNSSummaryLogger(sink, interval)
	return sink
}

func runMDNSSummaryLogger(sink *mdnsEventSink, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	aggregator := newMDNSLogAggregator(interval)
	for {
		select {
		case event := <-sink.events:
			aggregator.add(event)
		case <-ticker.C:
			dropped := atomic.SwapUint64(&sink.dropped, 0)
			aggregator.flush(dropped, log.Printf)
		}
	}
}

func (sink *mdnsEventSink) emit(event mdnsLogEvent) {
	if sink == nil {
		return
	}
	select {
	case sink.events <- event:
	default:
		atomic.AddUint64(&sink.dropped, 1)
	}
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
		kind:       event.Kind,
		recordType: event.RecordType,
		name:       event.Name,
		value:      event.Value,
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
		value := ""
		if key.value != "" {
			value = " -> " + key.value
		}
		logf("  vlan%d -> vlan%d %s %s %s%s count=%d sources=%d",
			key.sourcePool,
			key.targetPool,
			key.kind,
			key.recordType,
			key.name,
			value,
			bucket.count,
			len(bucket.sources),
		)
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
	fieldsA := []string{a.kind, a.recordType, a.name, a.value}
	fieldsB := []string{b.kind, b.recordType, b.name, b.value}
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

func emitForwardedMDNSEvents(sink *mdnsEventSink, bonjourPacket *bonjourPacket, sourcePool, targetPool uint16, sourceMAC string) {
	if sink == nil || bonjourPacket == nil || bonjourPacket.dns == nil {
		return
	}
	for _, event := range mdnsEventsFromDNS(bonjourPacket.dns, sourcePool, targetPool, sourceMAC) {
		sink.emit(event)
	}
}

func mdnsEventsFromDNS(dns *layers.DNS, sourcePool, targetPool uint16, sourceMAC string) []mdnsLogEvent {
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
			})
		}
		return events
	}

	events := []mdnsLogEvent{}
	events = appendMDNSRecordEvents(events, dns.Answers, sourcePool, targetPool, sourceMAC)
	events = appendMDNSRecordEvents(events, dns.Authorities, sourcePool, targetPool, sourceMAC)
	events = appendMDNSRecordEvents(events, dns.Additionals, sourcePool, targetPool, sourceMAC)
	return events
}

func appendMDNSRecordEvents(events []mdnsLogEvent, records []layers.DNSResourceRecord, sourcePool, targetPool uint16, sourceMAC string) []mdnsLogEvent {
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
		})
	}
	return events
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
