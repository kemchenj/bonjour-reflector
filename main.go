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

type mdnsInterface struct {
	name        string
	handle      *pcap.Handle
	mac         net.HardwareAddr
	maxFrameLen int
}

const mdnsTrafficFilter = "udp dst port 5353 and (ip dst host 224.0.0.251 or ip6 dst host ff02::fb)"

func buildMDNSBPFFilter(mac net.HardwareAddr) string {
	return fmt.Sprintf("not (ether src %s) and %s", mac, mdnsTrafficFilter)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lmsgprefix)
	log.SetPrefix("   ")
	configPath := flag.String("config", "", "Config file in TOML format")
	debug := flag.Bool("debug", false, "Enable pprof server on /debug/pprof/")
	mdnsDebug := flag.Bool("mdns-debug", false, "Include received mDNS records, source MACs and DNS details in live logs")
	flag.Parse()

	names, err := readConfig(*configPath)
	if err != nil {
		log.Fatalf("Could not read configuration %q: %v", *configPath, err)
	}

	// Start debug server
	if *debug {
		go debugServer(6060)
	}

	a := openInterface(names[0], *mdnsDebug)
	b := openInterface(names[1], *mdnsDebug)
	log.Printf("reflecting mDNS: %s <-> %s", a.name, b.name)
	go forward(a, b, *mdnsDebug)
	forward(b, a, *mdnsDebug)
}

func debugServer(port int) {
	err := http.ListenAndServe(fmt.Sprintf("localhost:%d", port), nil)
	if err != nil {
		log.Fatalf("The application was started with -debug flag but could not listen on port %v: \n %s", port, err)
	}
}

func openMDNSCapture(device string) (*pcap.Handle, error) {
	capture, err := pcap.NewInactiveHandle(device)
	if err != nil {
		return nil, err
	}
	defer capture.CleanUp()

	if err := capture.SetSnapLen(65536); err != nil {
		return nil, err
	}
	if err := capture.SetPromisc(true); err != nil {
		return nil, err
	}
	if err := capture.SetTimeout(time.Second); err != nil {
		return nil, err
	}
	// 低流量时也立即交付 mDNS 查询和响应，不等待抓包缓冲。
	if err := capture.SetImmediateMode(true); err != nil {
		return nil, fmt.Errorf("enable immediate mode: %w", err)
	}
	return capture.Activate()
}

func openInterface(name string, debug bool) mdnsInterface {
	intf, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatal(err)
	}
	if len(intf.HardwareAddr) != 6 {
		log.Fatalf("Interface %s must have an Ethernet MAC address", name)
	}
	handle, err := openMDNSCapture(name)
	if err != nil {
		log.Fatalf("Could not open capture on %s: %v", name, err)
	}
	filter := buildMDNSBPFFilter(intf.HardwareAddr)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("Could not apply filter on %s: %v", name, err)
	}
	if debug {
		log.Printf("mdns debug interface=%s mac=%s filter=%q", name, intf.HardwareAddr, filter)
	}
	return mdnsInterface{name: name, handle: handle, mac: intf.HardwareAddr, maxFrameLen: intf.MTU + 14}
}

func forward(src, dst mdnsInterface, debug bool) {
	source := gopacket.NewPacketSource(src.handle, gopacket.DecodersByLayerName["Ethernet"])
	source.DecodeOptions.Lazy = true
	for raw := range source.Packets() {
		packet, ok := parseBonjourPacket(raw)
		if !ok {
			continue
		}
		sourceMAC := hardwareAddrString(packet.srcMAC)
		ips := raw.NetworkLayer().NetworkFlow()
		ports := raw.TransportLayer().TransportFlow()
		endpoints := "src=" + net.JoinHostPort(ips.Src().String(), ports.Src().String()) +
			" dst=" + net.JoinHostPort(ips.Dst().String(), ports.Dst().String())
		logMDNS(debug, packet.dns, src.name, "", sourceMAC, endpoints)
		if err := sendBonjourPacket(dst.handle, &packet, dst.mac, dst.maxFrameLen); err != nil {
			log.Printf("mDNS forwarding error %s -> %s %s src_mac=%s: %v", src.name, dst.name, endpoints, sourceMAC, err)
			continue
		}
		logMDNS(debug, packet.dns, src.name, dst.name, sourceMAC, endpoints)
	}
	log.Fatalf("Capture stopped on %s", src.name)
}
