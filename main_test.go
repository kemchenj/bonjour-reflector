package main

import (
	"net"
	"testing"
)

func TestBuildMDNSBPFFilter(t *testing.T) {
	localMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	got := buildMDNSBPFFilter(localMAC)
	want := "not (ether src 00:11:22:33:44:55) and udp dst port 5353 and (ip dst host 224.0.0.251 or ip6 dst host ff02::fb)"
	if got != want {
		t.Errorf("buildMDNSBPFFilter() = %q, want %q", got, want)
	}
}
