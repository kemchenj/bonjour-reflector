package main

import (
	"net"
	"testing"
)

func TestBuildMDNSBPFFilter(t *testing.T) {
	localMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	got := buildMDNSBPFFilter([]net.HardwareAddr{localMAC}, false)
	want := "not (ether src 00:11:22:33:44:55) and udp dst port 5353 and (ether dst 01:00:5e:00:00:fb or ether dst 33:33:00:00:00:fb)"
	if got != want {
		t.Errorf("buildMDNSBPFFilter() = %q, want %q", got, want)
	}
}

func TestBuildMDNSBPFFilterExcludesAllLocalMACs(t *testing.T) {
	localMACs := []net.HardwareAddr{
		{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}

	got := buildMDNSBPFFilter(localMACs, false)
	want := "not (ether src 00:11:22:33:44:55 or ether src aa:bb:cc:dd:ee:ff) and udp dst port 5353 and (ether dst 01:00:5e:00:00:fb or ether dst 33:33:00:00:00:fb)"
	if got != want {
		t.Errorf("buildMDNSBPFFilter() = %q, want %q", got, want)
	}
}

func TestBuildMDNSBPFFilterRequiresVLAN(t *testing.T) {
	localMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	got := buildMDNSBPFFilter([]net.HardwareAddr{localMAC}, true)
	want := "not (ether src 00:11:22:33:44:55) and vlan and udp dst port 5353 and (ether dst 01:00:5e:00:00:fb or ether dst 33:33:00:00:00:fb)"
	if got != want {
		t.Errorf("buildMDNSBPFFilter() = %q, want %q", got, want)
	}
}
