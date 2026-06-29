package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
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

const mdnsTrafficFilter = "udp dst port 5353"

func buildMDNSBPFFilter(localMACs []net.HardwareAddr, requireVLAN bool) string {
	parts := []string{}
	if localMACFilter := buildLocalMACFilter(localMACs); localMACFilter != "" {
		parts = append(parts, localMACFilter)
	}
	if requireVLAN {
		parts = append(parts, "vlan")
	}
	parts = append(parts, mdnsTrafficFilter)
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
	mdnsDebug := flag.Bool("mdns-debug", false, "Enable aggregated mDNS receive and forwarding diagnostics")
	runDuration := flag.Duration("run-duration", 0, "Run for this duration before flushing logs and exiting; 0 means run until stopped")
	logFilePath := flag.String("log-file", "", "Write logs to this file in addition to stderr, overwriting existing contents")
	flag.Parse()

	logFile := configureLogFile(*logFilePath)

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
	mdnsEvents := startMDNSSummaryLogger(30*time.Second, *mdnsDebug)
	scheduleTimedExit(*runDuration, mdnsEvents, logFile)

	if len(cfg.Interfaces) > 0 {
		runWithMappedInterfaces(cfg, poolsMap, mirrorPeers, mdnsEvents)
		return
	}
	runWithTaggedInterface(cfg, poolsMap, mirrorPeers, mdnsEvents)
}

func configureLogFile(logFilePath string) *os.File {
	if logFilePath == "" {
		return nil
	}

	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("Could not open log file %s: %v", logFilePath, err)
	}
	log.SetOutput(io.MultiWriter(os.Stderr, logFile))
	log.Printf("Writing logs to %s", logFilePath)
	return logFile
}

func scheduleTimedExit(runDuration time.Duration, mdnsEvents *mdnsEventSink, logFile *os.File) {
	if runDuration <= 0 {
		return
	}

	go func() {
		<-time.After(runDuration)
		log.Printf("Run duration %s elapsed; flushing logs and exiting", runDuration)
		mdnsEvents.stopAndFlush()
		if logFile != nil {
			if err := logFile.Sync(); err != nil {
				log.Printf("Could not sync log file: %v", err)
			}
			if err := logFile.Close(); err != nil {
				log.Printf("Could not close log file: %v", err)
			}
		}
		os.Exit(0)
	}()
}

func debugServer(port int) {
	err := http.ListenAndServe(fmt.Sprintf("localhost:%d", port), nil)
	if err != nil {
		log.Fatalf("The application was started with -debug flag but could not listen on port %v: \n %s", port, err)
	}
}

func runWithTaggedInterface(cfg brconfig, poolsMap, mirrorPeers map[uint16][]uint16, mdnsEvents *mdnsEventSink) {
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
	filter := buildMDNSBPFFilter([]net.HardwareAddr{brMACAddress}, true)
	if mdnsEvents.debugEnabled() {
		log.Printf("mdns debug interface=%s mode=tagged mac=%s filter=%q", cfg.NetInterface, brMACAddress, filter)
	}
	err = rawTraffic.SetBPFFilter(filter)
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
		processPacket(cfg, poolsMap, mirrorPeers, *bonjourPacket.vlanTag, rawTraffic, brMACAddress, &bonjourPacket, mdnsEvents)
	}
}

func runWithMappedInterfaces(cfg brconfig, poolsMap, mirrorPeers map[uint16][]uint16, mdnsEvents *mdnsEventSink) {
	interfacesByPool := make(map[uint16]egressInterface)
	ingress := make(chan ingressPacket, 100)

	for _, configuredInterface := range cfg.Interfaces {
		handle, err := pcap.OpenLive(configuredInterface.Name, 65536, true, time.Second)
		if err != nil {
			log.Fatalf("Could not find network interface: %v", configuredInterface.Name)
		}
		intf, err := net.InterfaceByName(configuredInterface.Name)
		if err != nil {
			log.Fatalf("Could not get interface details %v: %v", configuredInterface.Name, err)
		}
		filter := buildMDNSBPFFilter([]net.HardwareAddr{intf.HardwareAddr}, false)
		if mdnsEvents.debugEnabled() {
			log.Printf("mdns debug interface=%s pool=%d mac=%s filter=%q", configuredInterface.Name, configuredInterface.Pool, intf.HardwareAddr, filter)
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
		processPacketWithPoolMap(cfg, poolsMap, mirrorPeers, incoming.pool, interfacesByPool, &incoming.packet, mdnsEvents)
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
	mdnsEvents *mdnsEventSink,
) {
	sourceMAC := hardwareAddrString(bonjourPacket.srcMAC)
	emitDebugMDNSEvents(mdnsEvents, bonjourPacket, sourcePool, 0, "rx", "", sourceMAC)
	if bonjourPacket.isDNSQuery {
		tags := mergeDedupeUint16(poolsMap[sourcePool], mirrorPeers[sourcePool])
		if len(tags) == 0 {
			emitDebugMDNSEvents(mdnsEvents, bonjourPacket, sourcePool, 0, "skip", "no_target_pool", sourceMAC)
		}
		for _, tag := range tags {
			if err := sendBonjourPacket(defaultHandle, bonjourPacket, tag, defaultMAC); err == nil {
				emitForwardedMDNSEvents(mdnsEvents, bonjourPacket, sourcePool, tag, sourceMAC)
			} else {
				emitDebugMDNSEvents(mdnsEvents, bonjourPacket, sourcePool, tag, "error", "write_failed:"+err.Error(), sourceMAC)
			}
		}
		return
	}

	var tags []uint16
	if device, ok := cfg.Devices[macAddress(bonjourPacket.srcMAC.String())]; ok {
		tags = device.SharedPools
	} else {
		tags = mirrorPeers[sourcePool]
	}
	if len(tags) == 0 {
		emitDebugMDNSEvents(mdnsEvents, bonjourPacket, sourcePool, 0, "skip", "no_target_pool", sourceMAC)
	}
	for _, tag := range tags {
		if err := sendBonjourPacket(defaultHandle, bonjourPacket, tag, defaultMAC); err == nil {
			emitForwardedMDNSEvents(mdnsEvents, bonjourPacket, sourcePool, tag, sourceMAC)
		} else {
			emitDebugMDNSEvents(mdnsEvents, bonjourPacket, sourcePool, tag, "error", "write_failed:"+err.Error(), sourceMAC)
		}
	}
}

func processPacketWithPoolMap(
	cfg brconfig,
	poolsMap map[uint16][]uint16,
	mirrorPeers map[uint16][]uint16,
	sourcePool uint16,
	interfacesByPool map[uint16]egressInterface,
	bonjourPacket *bonjourPacket,
	mdnsEvents *mdnsEventSink,
) {
	sourceMAC := hardwareAddrString(bonjourPacket.srcMAC)
	emitDebugMDNSEvents(mdnsEvents, bonjourPacket, sourcePool, 0, "rx", "", sourceMAC)

	var tags []uint16
	if bonjourPacket.isDNSQuery {
		tags = mergeDedupeUint16(poolsMap[sourcePool], mirrorPeers[sourcePool])
	} else if device, ok := cfg.Devices[macAddress(bonjourPacket.srcMAC.String())]; ok {
		tags = device.SharedPools
	} else {
		tags = mirrorPeers[sourcePool]
	}

	if len(tags) == 0 {
		emitDebugMDNSEvents(mdnsEvents, bonjourPacket, sourcePool, 0, "skip", "no_target_pool", sourceMAC)
	}
	for _, targetPool := range tags {
		outgoing, ok := interfacesByPool[targetPool]
		if !ok {
			emitDebugMDNSEvents(mdnsEvents, bonjourPacket, sourcePool, targetPool, "skip", "missing_target_interface", sourceMAC)
			continue
		}
		if err := sendBonjourPacket(outgoing.handle, bonjourPacket, targetPool, outgoing.mac); err == nil {
			emitForwardedMDNSEvents(mdnsEvents, bonjourPacket, sourcePool, targetPool, sourceMAC)
		} else {
			emitDebugMDNSEvents(mdnsEvents, bonjourPacket, sourcePool, targetPool, "error", "write_failed:"+err.Error(), sourceMAC)
		}
	}
}
