package main

import (
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestMDNSEventsFromDNSQuery(t *testing.T) {
	msg := &dns.Msg{
		Question: []dns.Question{
			{Name: "_airplay._tcp.local.", Qtype: dns.TypePTR}},
	}

	got := mdnsEventsFromDNS(msg, "en0", "en6", "aa:bb:cc:dd:ee:ff")
	want := []mdnsLogEvent{
		{
			SourceInterface: "en0",
			TargetInterface: "en6",
			SrcMAC:          "aa:bb:cc:dd:ee:ff",
			Kind:            "query",
			RecordType:      "PTR",
			Name:            "_airplay._tcp.local",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mdnsEventsFromDNS() = %#v, want %#v", got, want)
	}
}

func TestMDNSEventsFromDNSResponse(t *testing.T) {
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.PTR{Hdr: dns.RR_Header{Name: "_airplay._tcp.local.", Rrtype: dns.TypePTR, Ttl: 120, Class: dns.ClassINET}, Ptr: "Living\\ Room._airplay._tcp.local."},
			&dns.SRV{Hdr: dns.RR_Header{Name: "Living Room._airplay._tcp.local.", Rrtype: dns.TypeSRV, Ttl: 120, Class: dns.ClassINET}, Target: "appletv.local.", Port: 7000},
			&dns.A{Hdr: dns.RR_Header{Name: "appletv.local.", Rrtype: dns.TypeA, Ttl: 120, Class: dns.ClassINET}, A: net.IP{192, 168, 1, 23}},
		},
		Extra: []dns.RR{
			&dns.TXT{Hdr: dns.RR_Header{Name: "Living Room._airplay._tcp.local.", Rrtype: dns.TypeTXT, Ttl: 120, Class: dns.ClassINET}, Txt: []string{"model=AppleTV", "flags"}},
		},
	}

	got := mdnsEventsFromDNS(msg, "en6", "en0", "aa:bb:cc:dd:ee:ff")
	want := []mdnsLogEvent{
		{
			SourceInterface: "en6",
			TargetInterface: "en0",
			SrcMAC:          "aa:bb:cc:dd:ee:ff",
			Kind:            "announce",
			RecordType:      "PTR",
			Name:            "_airplay._tcp.local",
			Value:           "Living Room._airplay._tcp.local",
		},
		{
			SourceInterface: "en6",
			TargetInterface: "en0",
			SrcMAC:          "aa:bb:cc:dd:ee:ff",
			Kind:            "announce",
			RecordType:      "SRV",
			Name:            "Living Room._airplay._tcp.local",
			Value:           "appletv.local:7000",
		},
		{
			SourceInterface: "en6",
			TargetInterface: "en0",
			SrcMAC:          "aa:bb:cc:dd:ee:ff",
			Kind:            "announce",
			RecordType:      "A",
			Name:            "appletv.local",
			Value:           "192.168.1.23",
		},
		{
			SourceInterface: "en6",
			TargetInterface: "en0",
			SrcMAC:          "aa:bb:cc:dd:ee:ff",
			Kind:            "announce",
			RecordType:      "TXT",
			Name:            "Living Room._airplay._tcp.local",
			Value:           "keys=flags,model",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mdnsEventsFromDNS() = %#v, want %#v", got, want)
	}
}

func TestMDNSEventsFromDNSGoodbye(t *testing.T) {
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "old-speaker.local.", Rrtype: dns.TypeA, Ttl: 0, Class: dns.ClassINET}, A: net.IP{192, 168, 1, 30}},
		},
	}

	got := mdnsEventsFromDNS(msg, "en6", "en0", "aa:bb:cc:dd:ee:ff")
	if len(got) != 1 || got[0].Kind != "goodbye" {
		t.Fatalf("mdnsEventsFromDNS() = %#v, want one goodbye event", got)
	}
}

func TestMDNSEventsFromDNSDetails(t *testing.T) {
	msg := &dns.Msg{
		Question: []dns.Question{
			{Name: "_airplay._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET | mdnsClassFlagBit},
		},
	}

	got := mdnsEventsFromDNSWithDetails(msg, "en0", "en6", "aa:bb:cc:dd:ee:ff", true)
	if len(got) != 1 || got[0].Details != "q=QU class=IN" {
		t.Fatalf("mdnsEventsFromDNSWithDetails() = %#v, want QU query details", got)
	}

	msg = &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "appletv.local.", Rrtype: dns.TypeA, Ttl: 120, Class: dns.ClassINET | mdnsClassFlagBit}, A: net.IP{192, 168, 1, 23}},
		},
	}

	got = mdnsEventsFromDNSWithDetails(msg, "en6", "en0", "aa:bb:cc:dd:ee:ff", true)
	if len(got) != 1 || got[0].Details != "ttl=120 cache_flush=true class=IN" {
		t.Fatalf("mdnsEventsFromDNSWithDetails() = %#v, want cache-flush response details", got)
	}
}

func TestMDNSLogAggregatorFlush(t *testing.T) {
	aggregator := newMDNSLogAggregator(30 * time.Second)
	aggregator.add(mdnsLogEvent{
		SourceInterface: "en6",
		TargetInterface: "en0",
		SrcMAC:          "aa:bb:cc:dd:ee:ff",
		Kind:            "announce",
		RecordType:      "A",
		Name:            "appletv.local",
		Value:           "192.168.1.23",
	})
	aggregator.add(mdnsLogEvent{
		SourceInterface: "en6",
		TargetInterface: "en0",
		SrcMAC:          "11:22:33:44:55:66",
		Kind:            "announce",
		RecordType:      "A",
		Name:            "appletv.local",
		Value:           "192.168.1.23",
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
		"  en6 -> en0 announce A appletv.local -> 192.168.1.23 count=2 sources=2",
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
			SourceInterface: "en0",
			SrcMAC:          sourceMAC,
			Stage:           "rx",
			Kind:            "query",
			RecordType:      "PTR",
			Name:            "_airplay._tcp.local",
			Details:         "q=QM class=IN",
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
		"  en0 rx query PTR _airplay._tcp.local q=QM class=IN count=3 sources=3 source_macs=aa:aa:aa:aa:aa:aa,bb:bb:bb:bb:bb:bb,+1",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("flush() logged %#v, want %#v", lines, want)
	}
}

func TestMDNSLogAggregatorFlushDebugStages(t *testing.T) {
	aggregator := newMDNSLogAggregator(30 * time.Second)
	aggregator.add(mdnsLogEvent{
		SourceInterface: "en0",
		SrcMAC:          "aa:bb:cc:dd:ee:ff",
		Stage:           "rx",
		Kind:            "query",
		RecordType:      "PTR",
		Name:            "_airplay._tcp.local",
	})
	aggregator.add(mdnsLogEvent{
		SourceInterface: "en0",
		TargetInterface: "en6",
		Stage:           "error",
		Reason:          "write_failed:test",
		Kind:            "query",
		RecordType:      "PTR",
		Name:            "_airplay._tcp.local",
	})

	lines := []string{}
	flushed := aggregator.flush(0, func(format string, args ...interface{}) {
		lines = append(lines, fmt.Sprintf(format, args...))
	})
	if !flushed {
		t.Fatal("flush() = false, want true")
	}

	want := []string{
		"mdns summary window=30s events=2 dropped_log_events=0",
		"  en0 rx query PTR _airplay._tcp.local count=1 sources=1",
		"  en0 -> en6 error reason=write_failed:test query PTR _airplay._tcp.local count=1 sources=0",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("flush() logged %#v, want %#v", lines, want)
	}
}

func TestEmitDebugMDNSEventsRequiresDebug(t *testing.T) {
	msg := &dns.Msg{
		Question: []dns.Question{
			{Name: "_airplay._tcp.local.", Qtype: dns.TypePTR}},
	}
	packet := &bonjourPacket{dns: msg}

	disabled := &mdnsEventSink{events: make(chan mdnsLogEvent, 1)}
	emitDebugMDNSEvents(disabled, packet, "en0", "", "rx", "", "aa:bb:cc:dd:ee:ff")
	if len(disabled.events) != 0 {
		t.Fatalf("emitDebugMDNSEvents() emitted with debug disabled")
	}

	enabled := &mdnsEventSink{events: make(chan mdnsLogEvent, 1), debug: true}
	emitDebugMDNSEvents(enabled, packet, "en0", "", "rx", "", "aa:bb:cc:dd:ee:ff")
	if len(enabled.events) != 1 {
		t.Fatalf("emitDebugMDNSEvents() emitted %d events, want 1", len(enabled.events))
	}
	event := <-enabled.events
	if event.Stage != "rx" || event.SourceInterface != "en0" || event.Name != "_airplay._tcp.local" {
		t.Fatalf("emitDebugMDNSEvents() event = %#v", event)
	}
}
