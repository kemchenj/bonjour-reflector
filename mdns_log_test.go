package main

import (
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

func TestMDNSEventsFromDNSQuery(t *testing.T) {
	dns := &layers.DNS{
		Questions: []layers.DNSQuestion{
			{
				Name: []byte("_airplay._tcp.local"),
				Type: layers.DNSTypePTR,
			},
		},
	}

	got := mdnsEventsFromDNS(dns, 10, 1, "aa:bb:cc:dd:ee:ff")
	want := []mdnsLogEvent{
		{
			SourcePool: 10,
			TargetPool: 1,
			SrcMAC:     "aa:bb:cc:dd:ee:ff",
			Kind:       "query",
			RecordType: "PTR",
			Name:       "_airplay._tcp.local",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mdnsEventsFromDNS() = %#v, want %#v", got, want)
	}
}

func TestMDNSEventsFromDNSResponse(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte("_airplay._tcp.local"),
				Type:  layers.DNSTypePTR,
				TTL:   120,
				PTR:   []byte("Living Room._airplay._tcp.local"),
				Class: layers.DNSClassIN,
			},
			{
				Name:  []byte("Living Room._airplay._tcp.local"),
				Type:  layers.DNSTypeSRV,
				TTL:   120,
				SRV:   layers.DNSSRV{Port: 7000, Name: []byte("appletv.local")},
				Class: layers.DNSClassIN,
			},
			{
				Name:  []byte("appletv.local"),
				Type:  layers.DNSTypeA,
				TTL:   120,
				IP:    net.IP{192, 168, 1, 23},
				Class: layers.DNSClassIN,
			},
		},
		Additionals: []layers.DNSResourceRecord{
			{
				Name:  []byte("Living Room._airplay._tcp.local"),
				Type:  layers.DNSTypeTXT,
				TTL:   120,
				TXTs:  [][]byte{[]byte("model=AppleTV"), []byte("flags")},
				Class: layers.DNSClassIN,
			},
		},
	}

	got := mdnsEventsFromDNS(dns, 1, 10, "aa:bb:cc:dd:ee:ff")
	want := []mdnsLogEvent{
		{
			SourcePool: 1,
			TargetPool: 10,
			SrcMAC:     "aa:bb:cc:dd:ee:ff",
			Kind:       "announce",
			RecordType: "PTR",
			Name:       "_airplay._tcp.local",
			Value:      "Living Room._airplay._tcp.local",
		},
		{
			SourcePool: 1,
			TargetPool: 10,
			SrcMAC:     "aa:bb:cc:dd:ee:ff",
			Kind:       "announce",
			RecordType: "SRV",
			Name:       "Living Room._airplay._tcp.local",
			Value:      "appletv.local:7000",
		},
		{
			SourcePool: 1,
			TargetPool: 10,
			SrcMAC:     "aa:bb:cc:dd:ee:ff",
			Kind:       "announce",
			RecordType: "A",
			Name:       "appletv.local",
			Value:      "192.168.1.23",
		},
		{
			SourcePool: 1,
			TargetPool: 10,
			SrcMAC:     "aa:bb:cc:dd:ee:ff",
			Kind:       "announce",
			RecordType: "TXT",
			Name:       "Living Room._airplay._tcp.local",
			Value:      "keys=flags,model",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mdnsEventsFromDNS() = %#v, want %#v", got, want)
	}
}

func TestMDNSEventsFromDNSGoodbye(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			{
				Name: []byte("old-speaker.local"),
				Type: layers.DNSTypeA,
				TTL:  0,
				IP:   net.IP{192, 168, 1, 30},
			},
		},
	}

	got := mdnsEventsFromDNS(dns, 1, 10, "aa:bb:cc:dd:ee:ff")
	if len(got) != 1 || got[0].Kind != "goodbye" {
		t.Fatalf("mdnsEventsFromDNS() = %#v, want one goodbye event", got)
	}
}

func TestMDNSEventsFromDNSDetails(t *testing.T) {
	dns := &layers.DNS{
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("_airplay._tcp.local"),
				Type:  layers.DNSTypePTR,
				Class: layers.DNSClass(uint16(layers.DNSClassIN) | mdnsClassFlagBit),
			},
		},
	}

	got := mdnsEventsFromDNSWithDetails(dns, 10, 1, "aa:bb:cc:dd:ee:ff", true)
	if len(got) != 1 || got[0].Details != "q=QU class=IN" {
		t.Fatalf("mdnsEventsFromDNSWithDetails() = %#v, want QU query details", got)
	}

	dns = &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte("appletv.local"),
				Type:  layers.DNSTypeA,
				TTL:   120,
				IP:    net.IP{192, 168, 1, 23},
				Class: layers.DNSClass(uint16(layers.DNSClassIN) | mdnsClassFlagBit),
			},
		},
	}

	got = mdnsEventsFromDNSWithDetails(dns, 1, 10, "aa:bb:cc:dd:ee:ff", true)
	if len(got) != 1 || got[0].Details != "ttl=120 cache_flush=true class=IN" {
		t.Fatalf("mdnsEventsFromDNSWithDetails() = %#v, want cache-flush response details", got)
	}
}

func TestMDNSLogAggregatorFlush(t *testing.T) {
	aggregator := newMDNSLogAggregator(30 * time.Second)
	aggregator.add(mdnsLogEvent{
		SourcePool: 1,
		TargetPool: 10,
		SrcMAC:     "aa:bb:cc:dd:ee:ff",
		Kind:       "announce",
		RecordType: "A",
		Name:       "appletv.local",
		Value:      "192.168.1.23",
	})
	aggregator.add(mdnsLogEvent{
		SourcePool: 1,
		TargetPool: 10,
		SrcMAC:     "11:22:33:44:55:66",
		Kind:       "announce",
		RecordType: "A",
		Name:       "appletv.local",
		Value:      "192.168.1.23",
	})

	lines := []string{}
	flushed := aggregator.flush(1, func(format string, args ...interface{}) {
		lines = append(lines, fmt.Sprintf(format, args...))
	})
	if !flushed {
		t.Fatal("flush() = false, want true")
	}

	want := []string{
		"mdns summary window=30s events=2 dropped_log_events=1",
		"  vlan1 -> vlan10 announce A appletv.local -> 192.168.1.23 count=2 sources=2",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("flush() logged %#v, want %#v", lines, want)
	}

	lines = nil
	flushed = aggregator.flush(0, func(format string, args ...interface{}) {
		lines = append(lines, fmt.Sprintf(format, args...))
	})
	if flushed || len(lines) != 0 {
		t.Fatalf("second flush logged %#v, want no output", lines)
	}
}

func TestMDNSLogAggregatorFlushSourceSamples(t *testing.T) {
	aggregator := newMDNSLogAggregator(30 * time.Second)
	aggregator.sourceLimit = 2
	for _, sourceMAC := range []string{"cc:cc:cc:cc:cc:cc", "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"} {
		aggregator.add(mdnsLogEvent{
			SourcePool: 10,
			SrcMAC:     sourceMAC,
			Stage:      "rx",
			Kind:       "query",
			RecordType: "PTR",
			Name:       "_airplay._tcp.local",
			Details:    "q=QM class=IN",
		})
	}

	lines := []string{}
	flushed := aggregator.flush(0, func(format string, args ...interface{}) {
		lines = append(lines, fmt.Sprintf(format, args...))
	})
	if !flushed {
		t.Fatal("flush() = false, want true")
	}

	want := []string{
		"mdns summary window=30s events=3 dropped_log_events=0",
		"  vlan10 rx query PTR _airplay._tcp.local q=QM class=IN count=3 sources=3 source_macs=aa:aa:aa:aa:aa:aa,bb:bb:bb:bb:bb:bb,+1",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("flush() logged %#v, want %#v", lines, want)
	}
}

func TestMDNSLogAggregatorFlushDebugStages(t *testing.T) {
	aggregator := newMDNSLogAggregator(30 * time.Second)
	aggregator.add(mdnsLogEvent{
		SourcePool: 10,
		SrcMAC:     "aa:bb:cc:dd:ee:ff",
		Stage:      "rx",
		Kind:       "query",
		RecordType: "PTR",
		Name:       "_airplay._tcp.local",
	})
	aggregator.add(mdnsLogEvent{
		SourcePool: 10,
		Stage:      "skip",
		Reason:     "no_target_pool",
		Kind:       "query",
		RecordType: "PTR",
		Name:       "_airplay._tcp.local",
	})
	aggregator.add(mdnsLogEvent{
		SourcePool: 10,
		TargetPool: 1,
		Stage:      "error",
		Reason:     "write_failed:test",
		Kind:       "query",
		RecordType: "PTR",
		Name:       "_airplay._tcp.local",
	})

	lines := []string{}
	flushed := aggregator.flush(0, func(format string, args ...interface{}) {
		lines = append(lines, fmt.Sprintf(format, args...))
	})
	if !flushed {
		t.Fatal("flush() = false, want true")
	}

	want := []string{
		"mdns summary window=30s events=3 dropped_log_events=0",
		"  vlan10 rx query PTR _airplay._tcp.local count=1 sources=1",
		"  vlan10 skip reason=no_target_pool query PTR _airplay._tcp.local count=1 sources=0",
		"  vlan10 -> vlan1 error reason=write_failed:test query PTR _airplay._tcp.local count=1 sources=0",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("flush() logged %#v, want %#v", lines, want)
	}
}

func TestEmitDebugMDNSEventsRequiresDebug(t *testing.T) {
	dns := &layers.DNS{
		Questions: []layers.DNSQuestion{
			{
				Name: []byte("_airplay._tcp.local"),
				Type: layers.DNSTypePTR,
			},
		},
	}
	packet := &bonjourPacket{dns: dns}

	disabled := &mdnsEventSink{events: make(chan mdnsLogEvent, 1)}
	emitDebugMDNSEvents(disabled, packet, 10, 0, "rx", "", "aa:bb:cc:dd:ee:ff")
	if len(disabled.events) != 0 {
		t.Fatalf("emitDebugMDNSEvents() emitted with debug disabled")
	}

	enabled := &mdnsEventSink{events: make(chan mdnsLogEvent, 1), debug: true}
	emitDebugMDNSEvents(enabled, packet, 10, 0, "rx", "", "aa:bb:cc:dd:ee:ff")
	if len(enabled.events) != 1 {
		t.Fatalf("emitDebugMDNSEvents() emitted %d events, want 1", len(enabled.events))
	}
	event := <-enabled.events
	if event.Stage != "rx" || event.SourcePool != 10 || event.Name != "_airplay._tcp.local" {
		t.Fatalf("emitDebugMDNSEvents() event = %#v", event)
	}
}
