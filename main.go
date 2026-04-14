package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
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
	filterTemplate := "not (ether src %s) and vlan and dst net (224.0.0.251 or ff02::fb) and udp dst port 5353"
	err = rawTraffic.SetBPFFilter(fmt.Sprintf(filterTemplate, brMACAddress))
	if err != nil {
		log.Fatalf("Could not apply filter on network interface: %v", err)
	}

	// Get a channel of Bonjour packets to process
	decoder := gopacket.DecodersByLayerName["Ethernet"]
	source := gopacket.NewPacketSource(rawTraffic, decoder)
	bonjourPackets := parsePacketsLazily(source)

	// Process Bonjours packets
	for bonjourPacket := range bonjourPackets {
		fmt.Println(bonjourPacket.packet.String())
		if bonjourPacket.vlanTag == nil {
			continue
		}
		processPacket(cfg, poolsMap, mirrorPeers, *bonjourPacket.vlanTag, rawTraffic, brMACAddress, &bonjourPacket)
	}
}

func runWithMappedInterfaces(cfg brconfig, poolsMap, mirrorPeers map[uint16][]uint16) {
	interfacesByPool := make(map[uint16]egressInterface)
	ingress := make(chan ingressPacket, 100)
	filterTemplate := "not (ether src %s) and dst net (224.0.0.251 or ff02::fb) and udp dst port 5353"

	for _, configuredInterface := range cfg.Interfaces {
		handle, err := pcap.OpenLive(configuredInterface.Name, 65536, true, time.Second)
		if err != nil {
			log.Fatalf("Could not find network interface: %v", configuredInterface.Name)
		}
		intf, err := net.InterfaceByName(configuredInterface.Name)
		if err != nil {
			log.Fatalf("Could not get interface details %v: %v", configuredInterface.Name, err)
		}
		err = handle.SetBPFFilter(fmt.Sprintf(filterTemplate, intf.HardwareAddr))
		if err != nil {
			log.Fatalf("Could not apply filter on network interface %v: %v", configuredInterface.Name, err)
		}
		interfacesByPool[configuredInterface.Pool] = egressInterface{
			handle: handle,
			mac:    intf.HardwareAddr,
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
		fmt.Println(incoming.packet.packet.String())
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
