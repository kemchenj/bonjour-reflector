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

func (e mdnsInterface) WritePacketData(frame []byte) error {
	return writeMDNSFrames(e.handle, frame, e.maxFrameLen)
}

const mdnsTrafficFilter = "udp dst port 5353 and (ip dst host 224.0.0.251 or ip6 dst host ff02::fb)"

func buildMDNSBPFFilter(mac net.HardwareAddr) string {
	return fmt.Sprintf("not (ether src %s) and %s", mac, mdnsTrafficFilter)
}

func main() {
	configPath := flag.String("config", "", "Config file in TOML format")
	debug := flag.Bool("debug", false, "Enable pprof server on /debug/pprof/")
	mdnsDebug := flag.Bool("mdns-debug", false, "Enable aggregated mDNS receive and forwarding diagnostics")
	runDuration := flag.Duration("run-duration", 0, "Run for this duration before flushing logs and exiting; 0 means run until stopped")
	logFilePath := flag.String("log-file", "", "Write logs to this file in addition to stderr, overwriting existing contents")
	flag.Parse()

	names, err := readConfig(*configPath)
	if err != nil {
		log.Fatalf("Could not read configuration %q: %v", *configPath, err)
	}

	logFile := configureLogFile(*logFilePath)
	// Start debug server
	if *debug {
		go debugServer(6060)
	}

	mdnsEvents := startMDNSSummaryLogger(30*time.Second, *mdnsDebug)
	scheduleTimedExit(*runDuration, mdnsEvents, logFile)

	a := openInterface(names[0], mdnsEvents)
	b := openInterface(names[1], mdnsEvents)
	go forward(a, b, mdnsEvents)
	forward(b, a, mdnsEvents)
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

func openInterface(name string, events *mdnsEventSink) mdnsInterface {
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
	if events.debugEnabled() {
		log.Printf("mdns debug interface=%s mac=%s filter=%q", name, intf.HardwareAddr, filter)
	}
	return mdnsInterface{name: name, handle: handle, mac: intf.HardwareAddr, maxFrameLen: intf.MTU + 14}
}

func forward(src, dst mdnsInterface, events *mdnsEventSink) {
	source := gopacket.NewPacketSource(src.handle, gopacket.DecodersByLayerName["Ethernet"])
	for packet := range parsePacketsLazily(source) {
		sourceMAC := hardwareAddrString(packet.srcMAC)
		emitDebugMDNSEvents(events, &packet, src.name, "", "rx", "", sourceMAC)
		if err := sendBonjourPacket(dst, &packet, dst.mac); err != nil {
			emitDebugMDNSEvents(events, &packet, src.name, dst.name, "error", "write_failed:"+err.Error(), sourceMAC)
			continue
		}
		emitForwardedMDNSEvents(events, &packet, src.name, dst.name, sourceMAC)
	}
	log.Fatalf("Capture stopped on %s", src.name)
}
