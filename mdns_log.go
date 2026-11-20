package main

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

const mdnsClassFlagBit = 0x8000

type mdnsLogEvent struct {
	SourceInterface string
	TargetInterface string
	SrcMAC          string
	Kind            string
	RecordType      string
	Name            string
	Value           string
	Details         string
}

func (event mdnsLogEvent) format(debug bool) string {
	record := fmt.Sprintf("%s %s %s", event.Kind, event.RecordType, event.Name)
	if event.Value != "" {
		record += " -> " + event.Value
	}
	if event.Details != "" {
		record += " " + event.Details
	}
	if debug && event.SrcMAC != "" {
		record += " src_mac=" + event.SrcMAC
	}
	if event.TargetInterface == "" {
		return fmt.Sprintf("%s rx %s", event.SourceInterface, record)
	}
	return fmt.Sprintf("%s -> %s %s", event.SourceInterface, event.TargetInterface, record)
}

func logMDNS(debug bool, msg *dns.Msg, sourceInterface, targetInterface, sourceMAC, endpoints string) {
	if targetInterface == "" && !debug {
		return
	}
	for _, event := range mdnsEventsFromDNSWithDetails(msg, sourceInterface, targetInterface, sourceMAC, debug) {
		log.Printf("%s %s", event.format(debug), endpoints)
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
				RecordType:      dns.Type(question.Qtype).String(),
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
		value, ok := dnsRecordValue(record)
		if !ok {
			continue
		}

		kind := "response"
		if header.Ttl == 0 {
			kind = "goodbye"
		}

		events = append(events, mdnsLogEvent{
			SourceInterface: sourceInterface,
			TargetInterface: targetInterface,
			SrcMAC:          sourceMAC,
			Kind:            kind,
			RecordType:      dns.Type(header.Rrtype).String(),
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
	// DNS 文本会转义空格和非 ASCII 字节；日志显示原始设备名。
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
