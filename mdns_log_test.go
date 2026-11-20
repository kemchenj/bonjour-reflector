package main

import (
	"bytes"
	"log"
	"net"
	"reflect"
	"strings"
	"testing"

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
			Kind:            "response",
			RecordType:      "PTR",
			Name:            "_airplay._tcp.local",
			Value:           "Living Room._airplay._tcp.local",
		},
		{
			SourceInterface: "en6",
			TargetInterface: "en0",
			SrcMAC:          "aa:bb:cc:dd:ee:ff",
			Kind:            "response",
			RecordType:      "SRV",
			Name:            "Living Room._airplay._tcp.local",
			Value:           "appletv.local:7000",
		},
		{
			SourceInterface: "en6",
			TargetInterface: "en0",
			SrcMAC:          "aa:bb:cc:dd:ee:ff",
			Kind:            "response",
			RecordType:      "A",
			Name:            "appletv.local",
			Value:           "192.168.1.23",
		},
		{
			SourceInterface: "en6",
			TargetInterface: "en0",
			SrcMAC:          "aa:bb:cc:dd:ee:ff",
			Kind:            "response",
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

func TestMDNSLogEventFormat(t *testing.T) {
	event := mdnsLogEvent{SourceInterface: "en6", TargetInterface: "en0", SrcMAC: "aa:bb:cc:dd:ee:ff", Kind: "response", RecordType: "A", Name: "appletv.local", Value: "192.168.1.23"}
	if got := event.format(false, mdnsLogAddr("fe80::1", "5353"), ""); got != "en6 (fe80::1) -> en0    response A appletv.local -> 192.168.1.23" {
		t.Fatal(got)
	}
	event.TargetInterface = ""
	event.Details = "ttl=120"
	if got := event.format(true, mdnsLogAddr("192.168.1.23", "5353"), mdnsLogAddr("224.0.0.251", "5353")); got != "en6 rx (192.168.1.23 -> 224.0.0.251)    response A appletv.local -> 192.168.1.23 ttl=120 src_mac=aa:bb:cc:dd:ee:ff" {
		t.Fatal(got)
	}
}

func TestLogMDNSReceiveRequiresDebug(t *testing.T) {
	msg := &dns.Msg{
		Question: []dns.Question{
			{Name: "_airplay._tcp.local.", Qtype: dns.TypePTR}},
	}
	var output bytes.Buffer
	previous := log.Writer()
	defer log.SetOutput(previous)
	log.SetOutput(&output)

	logMDNS(false, msg, "en0", "", "aa:bb:cc:dd:ee:ff", mdnsLogAddr("192.168.1.23", "49152"), "224.0.0.251")
	if output.Len() != 0 {
		t.Fatal("unexpected receive log with debug disabled")
	}
	logMDNS(true, msg, "en0", "", "aa:bb:cc:dd:ee:ff", mdnsLogAddr("192.168.1.23", "49152"), "224.0.0.251")
	if !strings.Contains(output.String(), "en0 rx (192.168.1.23:49152 -> 224.0.0.251)    query PTR _airplay._tcp.local") {
		t.Fatal(output.String())
	}
}
