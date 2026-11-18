package main

import (
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

type bonjourPacket struct {
	packet     gopacket.Packet
	srcMAC     *net.HardwareAddr
	dstMAC     *net.HardwareAddr
	isIPv6     bool
	vlanTag    *uint16
	dns        *layers.DNS
	dnsPayload []byte
	isDNSQuery bool
}

func parsePacketsLazily(source *gopacket.PacketSource) chan bonjourPacket {
	// Process packets, and forward Bonjour traffic to the returned channel

	// Set decoding to Lazy
	source.DecodeOptions = gopacket.DecodeOptions{Lazy: true}

	packetChan := make(chan bonjourPacket, 100)

	go func() {
		for packet := range source.Packets() {
			tag := parseVLANTag(packet)

			// Get source and destination mac addresses
			srcMAC, dstMAC := parseEthernetLayer(packet)

			// Check IP protocol version
			isIPv6 := parseIPLayer(packet)

			// Get UDP payload
			payload := parseUDPLayer(packet)

			dns, isDNSQuery, ok := parseDNSPayload(payload)
			if !ok {
				// Ignore malformed or non-DNS UDP payloads to avoid misrouting.
				continue
			}

			// Pass on the packet for its next adventure
			packetChan <- bonjourPacket{
				packet:     packet,
				vlanTag:    tag,
				srcMAC:     srcMAC,
				dstMAC:     dstMAC,
				isIPv6:     isIPv6,
				isDNSQuery: isDNSQuery,
				dns:        dns,
			}
		}
	}()

	return packetChan
}

func parseEthernetLayer(packet gopacket.Packet) (srcMAC, dstMAC *net.HardwareAddr) {
	if parsedEth := packet.Layer(layers.LayerTypeEthernet); parsedEth != nil {
		srcMAC = &parsedEth.(*layers.Ethernet).SrcMAC
		dstMAC = &parsedEth.(*layers.Ethernet).DstMAC
	}
	return
}

func parseVLANTag(packet gopacket.Packet) (tag *uint16) {
	if parsedTag := packet.Layer(layers.LayerTypeDot1Q); parsedTag != nil {
		tag = &parsedTag.(*layers.Dot1Q).VLANIdentifier
	}
	return
}

func parseIPLayer(packet gopacket.Packet) (isIPv6 bool) {
	if parsedIP := packet.Layer(layers.LayerTypeIPv4); parsedIP != nil {
		isIPv6 = false
	}
	if parsedIP := packet.Layer(layers.LayerTypeIPv6); parsedIP != nil {
		isIPv6 = true
	}
	return
}

func parseUDPLayer(packet gopacket.Packet) (payload []byte) {
	if parsedUDP := packet.Layer(layers.LayerTypeUDP); parsedUDP != nil {
		payload = parsedUDP.(*layers.UDP).Payload
	}
	return
}

func parseDNSPayload(payload []byte) (dns *layers.DNS, isDNSQuery bool, ok bool) {
	packet := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default)
	if parsedDNS := packet.Layer(layers.LayerTypeDNS); parsedDNS != nil {
		dns = parsedDNS.(*layers.DNS)
		isDNSQuery = !dns.QR
		ok = true
	}
	return
}

type packetWriter interface {
	WritePacketData([]byte) error
}

func sendBonjourPacket(handle packetWriter, bonjourPacket *bonjourPacket, tag uint16, brMACAddress net.HardwareAddr) error {
	if err := prepareDNSForForwarding(bonjourPacket); err != nil {
		return err
	}

	if bonjourPacket.vlanTag != nil {
		*bonjourPacket.vlanTag = tag
	}
	*bonjourPacket.srcMAC = brMACAddress

	// 抓包过滤器只接收发往 mDNS 组播 IP 的报文，确保目的 MAC 与该 IP 匹配。
	if bonjourPacket.isIPv6 {
		*bonjourPacket.dstMAC = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0xFB}
	} else {
		*bonjourPacket.dstMAC = net.HardwareAddr{0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB}
	}

	buf := gopacket.NewSerializeBuffer()
	if bonjourPacket.dnsPayload != nil {
		if err := serializeBonjourPacketWithDNS(buf, bonjourPacket); err != nil {
			return err
		}
	} else if err := gopacket.SerializePacket(buf, gopacket.SerializeOptions{}, bonjourPacket.packet); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

func prepareDNSForForwarding(bonjourPacket *bonjourPacket) error {
	if bonjourPacket == nil || bonjourPacket.packet == nil {
		return errors.New("cannot prepare DNS without packet data")
	}
	if bonjourPacket.dnsPayload != nil {
		return nil
	}

	var message dns.Msg
	if err := message.Unpack(parseUDPLayer(bonjourPacket.packet)); err != nil {
		return fmt.Errorf("decode DNS for forwarding: %w", err)
	}

	changed := false
	if !message.Response {
		for i := range message.Question {
			if message.Question[i].Qclass&mdnsClassFlagBit != 0 {
				message.Question[i].Qclass &^= mdnsClassFlagBit
				changed = true
			}
		}
	}
	for _, records := range []*[]dns.RR{&message.Answer, &message.Ns, &message.Extra} {
		kept := (*records)[:0]
		for _, record := range *records {
			if record.Header().Rrtype == dns.TypeAAAA {
				changed = true
				continue
			}
			if nsec, ok := record.(*dns.NSEC); ok {
				previousLen := len(nsec.TypeBitMap)
				nsec.TypeBitMap = slices.DeleteFunc(nsec.TypeBitMap, func(recordType uint16) bool {
					return recordType == dns.TypeAAAA
				})
				changed = changed || len(nsec.TypeBitMap) != previousLen
			}
			kept = append(kept, record)
		}
		*records = kept
	}
	if !changed {
		return nil
	}

	// 由 DNS 库重建压缩指针，保留 NSEC 等 gopacket 无法重新编码的记录。
	message.Compress = true
	payload, err := message.Pack()
	if err != nil {
		return fmt.Errorf("encode DNS for forwarding: %w", err)
	}
	forwardedDNS, _, ok := parseDNSPayload(payload)
	if !ok {
		return errors.New("could not decode forwarded DNS for logging")
	}
	if bonjourPacket.dns == nil {
		bonjourPacket.dns = forwardedDNS
	} else {
		*bonjourPacket.dns = *forwardedDNS
	}
	bonjourPacket.dnsPayload = payload
	return nil
}

func writeMDNSFrames(handle packetWriter, frame []byte, maxFrameLen int) error {
	if len(frame) <= maxFrameLen {
		if err := handle.WritePacketData(frame); err != nil {
			return fmt.Errorf("write %d-byte frame (limit %d): %w", len(frame), maxFrameLen, err)
		}
		return nil
	}

	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	payload := parseUDPLayer(packet)
	maxDNSLen := maxFrameLen - (len(frame) - len(payload))
	var message dns.Msg
	if err := message.Unpack(payload); err != nil {
		return fmt.Errorf("decode %d-byte frame for splitting: %w", len(frame), err)
	}
	parts, err := splitMDNSMessage(message, maxDNSLen)
	if err != nil {
		return fmt.Errorf("split %d-byte frame (limit %d): %w", len(frame), maxFrameLen, err)
	}

	frames := make([][]byte, 0, len(parts))
	for _, part := range parts {
		buf := gopacket.NewSerializeBuffer()
		if err := serializeBonjourPacketWithDNS(buf, &bonjourPacket{packet: packet, dnsPayload: part}); err != nil {
			return err
		}
		if len(buf.Bytes()) > maxFrameLen {
			return fmt.Errorf("split frame is %d bytes (limit %d)", len(buf.Bytes()), maxFrameLen)
		}
		frames = append(frames, buf.Bytes())
	}
	for i, part := range frames {
		if err := handle.WritePacketData(part); err != nil {
			return fmt.Errorf("write split frame %d/%d (%d bytes): %w", i+1, len(frames), len(part), err)
		}
	}
	return nil
}

func splitMDNSMessage(message dns.Msg, maxDNSLen int) ([][]byte, error) {
	part := dns.Msg{MsgHdr: message.MsgHdr, Compress: true}
	if message.Response {
		part.Truncated = false
	}
	base := part
	part.Question = message.Question
	sections := [][]dns.RR{message.Answer, message.Ns, message.Extra}
	if !message.Response {
		// Probe 记录和附加记录留在首包；后续查询包只带 Known Answers。
		part.Ns, part.Extra = message.Ns, message.Extra
		sections = sections[:1]
	}

	payload, err := part.Pack()
	if err != nil {
		return nil, err
	}
	if len(payload) > maxDNSLen {
		return nil, fmt.Errorf("DNS questions and query metadata exceed %d-byte budget", maxDNSLen)
	}

	var parts [][]byte
	for i, records := range sections {
		section := []*[]dns.RR{&part.Answer, &part.Ns, &part.Extra}[i]
		for _, record := range records {
			*section = append(*section, record)
			next, err := part.Pack()
			if err != nil {
				return nil, err
			}
			if len(next) > maxDNSLen {
				if !message.Response {
					// RFC 6762 §7.2：TC 表示还有后续的 Known Answers。
					payload[2] |= 0x02
				}
				parts = append(parts, payload)
				part = base
				*section = []dns.RR{record}
				next, err = part.Pack()
				if err != nil {
					return nil, err
				}
				if len(next) > maxDNSLen {
					// shortcut: 单条记录过大时显式失败，有实际需求时再支持 IP 分片。
					return nil, fmt.Errorf("single DNS record exceeds %d-byte budget", maxDNSLen)
				}
			}
			payload = next
		}
	}
	return append(parts, payload), nil
}

func serializeBonjourPacketWithDNS(buf gopacket.SerializeBuffer, bonjourPacket *bonjourPacket) error {
	if bonjourPacket == nil {
		return errors.New("cannot serialize nil Bonjour packet")
	}
	if bonjourPacket.packet == nil {
		return errors.New("cannot serialize Bonjour packet without packet data")
	}
	if bonjourPacket.dnsPayload == nil {
		return gopacket.SerializePacket(buf, gopacket.SerializeOptions{}, bonjourPacket.packet)
	}

	serializableLayers := []gopacket.SerializableLayer{}
	if ethLayer := bonjourPacket.packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		serializableLayers = append(serializableLayers, ethLayer.(*layers.Ethernet))
	} else {
		return gopacket.SerializePacket(buf, gopacket.SerializeOptions{}, bonjourPacket.packet)
	}
	if vlanLayer := bonjourPacket.packet.Layer(layers.LayerTypeDot1Q); vlanLayer != nil {
		serializableLayers = append(serializableLayers, vlanLayer.(*layers.Dot1Q))
	}

	var networkLayer gopacket.NetworkLayer
	if ipv4Layer := bonjourPacket.packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		networkLayer = ipv4
		serializableLayers = append(serializableLayers, ipv4)
	} else if ipv6Layer := bonjourPacket.packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		networkLayer = ipv6
		serializableLayers = append(serializableLayers, ipv6)
	} else {
		return gopacket.SerializePacket(buf, gopacket.SerializeOptions{}, bonjourPacket.packet)
	}

	udpLayer := bonjourPacket.packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return gopacket.SerializePacket(buf, gopacket.SerializeOptions{}, bonjourPacket.packet)
	}
	udp := udpLayer.(*layers.UDP)
	if networkLayer != nil {
		if err := udp.SetNetworkLayerForChecksum(networkLayer); err != nil {
			return err
		}
	}
	serializableLayers = append(serializableLayers, udp, gopacket.Payload(bonjourPacket.dnsPayload))

	return gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, serializableLayers...)
}
