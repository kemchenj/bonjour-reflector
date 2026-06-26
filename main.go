package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type ingressPacket struct {
	packet bonjourPacket
	pool   uint16
}

type egressInterface struct {
	handle *pcap.Handle
	mac    net.HardwareAddr
}

const mdnsMulticastFilter = "udp dst port 5353 and (ether dst 01:00:5e:00:00:fb or ether dst 33:33:00:00:00:fb)"

func buildMDNSBPFFilter(localMACs []net.HardwareAddr, requireVLAN bool) string {
	parts := []string{}
	if localMACFilter := buildLocalMACFilter(localMACs); localMACFilter != "" {
		parts = append(parts, localMACFilter)
	}
	if requireVLAN {
		parts = append(parts, "vlan")
	}
	parts = append(parts, mdnsMulticastFilter)
	return strings.Join(parts, " and ")
}

func buildLocalMACFilter(localMACs []net.HardwareAddr) string {
	srcFilters := []string{}
	for _, localMAC := range localMACs {
		if len(localMAC) == 0 {
			continue
		}
		srcFilters = append(srcFilters, fmt.Sprintf("ether src %s", localMAC))
	}
	if len(srcFilters) == 0 {
		return ""
	}
	return fmt.Sprintf("not (%s)", strings.Join(srcFilters, " or "))
}

func main() {
	// Read config file and generate mDNS forwarding maps
	configPath := flag.String("config", "", "Config file in TOML format")
	debug := flag.Bool("debug", false, "Enable pprof server on /debug/pprof/")
	flag.Parse()

	// Start debug server
	if *debug {
		go debugServer(6060)
	}

	cfg, err := readConfig(*configPath)
	if err != nil {
		log.Fatalf("Could not read configuration: %v", err)
	}
	poolsMap := mapByPool(cfg.Devices)
	mirrorPeers := buildMirrorPeers(cfg.MirrorGroups)

	if len(cfg.Interfaces) > 0 {
		runWithMappedInterfaces(cfg, poolsMap, mirrorPeers)
		return
	}
	runWithTaggedInterface(cfg, poolsMap, mirrorPeers)
}

func debugServer(port int) {
	err := http.ListenAndServe(fmt.Sprintf("localhost:%d", port), nil)
	if err != nil {
		log.Fatalf("The application was started with -debug flag but could not listen on port %v: \n %s", port, err)
	}
}

func runWithTaggedInterface(cfg brconfig, poolsMap, mirrorPeers map[uint16][]uint16) {
	// Get a handle on the network interface
	rawTraffic, err := pcap.OpenLive(cfg.NetInterface, 65536, true, time.Second)
	if err != nil {
		log.Fatalf("Could not find network interface: %v", cfg.NetInterface)
	}

	// Get the local MAC address, to filter out Bonjour packet generated locally
	intf, err := net.InterfaceByName(cfg.NetInterface)
	if err != nil {
		log.Fatal(err)
	}
	brMACAddress := intf.HardwareAddr

	// Filter tagged bonjour traffic
	err = rawTraffic.SetBPFFilter(buildMDNSBPFFilter([]net.HardwareAddr{brMACAddress}, true))
	if err != nil {
		log.Fatalf("Could not apply filter on network interface: %v", err)
	}

	// Get a channel of Bonjour packets to process
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	source := gopacket.NewPacketSource(rawTraffic, decoder)
	bonjourPackets := parsePacketsLazily(source)

	// Process Bonjours packets
	for bonjourPacket := range bonjourPackets {
		if bonjourPacket.vlanTag == nil {
			continue
		}
		processPacket(cfg, poolsMap, mirrorPeers, *bonjourPacket.vlanTag, rawTraffic, brMACAddress, &bonjourPacket)
	}
}

func runWithMappedInterfaces(cfg brconfig, poolsMap, mirrorPeers map[uint16][]uint16) {
	interfacesByPool := make(map[uint16]egressInterface)
	interfaceMACs := make(map[string]net.HardwareAddr)
	localMACs := []net.HardwareAddr{}
	ingress := make(chan ingressPacket, 100)

	for _, configuredInterface := range cfg.Interfaces {
		intf, err := net.InterfaceByName(configuredInterface.Name)
		if err != nil {
			log.Fatalf("Could not get interface details %v: %v", configuredInterface.Name, err)
		}
		interfaceMACs[configuredInterface.Name] = intf.HardwareAddr
		localMACs = append(localMACs, intf.HardwareAddr)
	}

	filter := buildMDNSBPFFilter(localMACs, false)

	for _, configuredInterface := range cfg.Interfaces {
		handle, err := pcap.OpenLive(configuredInterface.Name, 65536, true, time.Second)
		if err != nil {
			log.Fatalf("Could not find network interface: %v", configuredInterface.Name)
		}
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatalf("Could not apply filter on network interface %v: %v", configuredInterface.Name, err)
		}
		if _, exists := interfacesByPool[configuredInterface.Pool]; exists {
			log.Fatalf("Duplicate pool %d in interfaces config; each pool must map to exactly one interface", configuredInterface.Pool)
		}
		interfacesByPool[configuredInterface.Pool] = egressInterface{
			handle: handle,
			mac:    interfaceMACs[configuredInterface.Name],
		}

		decoder := gopacket.DecodersByLayerName["Ethernet"]
		source := gopacket.NewPacketSource(handle, decoder)
		packets := parsePacketsLazily(source)
		go func(pool uint16, in chan bonjourPacket) {
			for p := range in {
				ingress <- ingressPacket{packet: p, pool: pool}
			}
		}(configuredInterface.Pool, packets)
	}

	for incoming := range ingress {
		processPacketWithPoolMap(cfg, poolsMap, mirrorPeers, incoming.pool, interfacesByPool, &incoming.packet)
	}
}

func processPacket(
	cfg brconfig,
	poolsMap map[uint16][]uint16,
	mirrorPeers map[uint16][]uint16,
	sourcePool uint16,
	defaultHandle *pcap.Handle,
	defaultMAC net.HardwareAddr,
	bonjourPacket *bonjourPacket,
) {
	if bonjourPacket.isDNSQuery {
		tags := mergeDedupeUint16(poolsMap[sourcePool], mirrorPeers[sourcePool])
		for _, tag := range tags {
			sendBonjourPacket(defaultHandle, bonjourPacket, tag, defaultMAC)
		}
		return
	}

	var tags []uint16
	if device, ok := cfg.Devices[macAddress(bonjourPacket.srcMAC.String())]; ok {
		tags = device.SharedPools
	} else {
		tags = mirrorPeers[sourcePool]
	}
	for _, tag := range tags {
		sendBonjourPacket(defaultHandle, bonjourPacket, tag, defaultMAC)
	}
}

func processPacketWithPoolMap(
	cfg brconfig,
	poolsMap map[uint16][]uint16,
	mirrorPeers map[uint16][]uint16,
	sourcePool uint16,
	interfacesByPool map[uint16]egressInterface,
	bonjourPacket *bonjourPacket,
) {
	var tags []uint16
	if bonjourPacket.isDNSQuery {
		tags = mergeDedupeUint16(poolsMap[sourcePool], mirrorPeers[sourcePool])
	} else if device, ok := cfg.Devices[macAddress(bonjourPacket.srcMAC.String())]; ok {
		tags = device.SharedPools
	} else {
		tags = mirrorPeers[sourcePool]
	}

	for _, targetPool := range tags {
		outgoing, ok := interfacesByPool[targetPool]
		if !ok {
			continue
		}
		sendBonjourPacket(outgoing.handle, bonjourPacket, targetPool, outgoing.mac)
	}
}
