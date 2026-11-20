package main

import (
	"encoding/binary"
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
	dns        *dns.Msg
	dnsPayload []byte
}

func parseBonjourPacket(packet gopacket.Packet) (bonjourPacket, bool) {
	dns, ok := parseDNSPayload(parseUDPLayer(packet))
	if !ok {
		return bonjourPacket{}, false
	}
	srcMAC, dstMAC := parseEthernetLayer(packet)
	return bonjourPacket{packet: packet, srcMAC: srcMAC, dstMAC: dstMAC, isIPv6: parseIPLayer(packet), dns: dns}, true
}

func parseEthernetLayer(packet gopacket.Packet) (srcMAC, dstMAC *net.HardwareAddr) {
	if parsedEth := packet.Layer(layers.LayerTypeEthernet); parsedEth != nil {
		srcMAC = &parsedEth.(*layers.Ethernet).SrcMAC
		dstMAC = &parsedEth.(*layers.Ethernet).DstMAC
	}
	return
}

func parseIPLayer(packet gopacket.Packet) bool {
	_, ipv6 := packet.NetworkLayer().(*layers.IPv6)
	return ipv6
}

func parseUDPLayer(packet gopacket.Packet) (payload []byte) {
	if parsedUDP := packet.Layer(layers.LayerTypeUDP); parsedUDP != nil {
		payload = parsedUDP.(*layers.UDP).Payload
	}
	return
}

func parseDNSPayload(payload []byte) (*dns.Msg, bool) {
	var msg dns.Msg
	if err := msg.Unpack(payload); err != nil {
		return nil, false
	}
	// Unpack 容许不完整的 section；不要把头部计数不符的报文转发出去。
	for i, count := range []int{len(msg.Question), len(msg.Answer), len(msg.Ns), len(msg.Extra)} {
		if int(binary.BigEndian.Uint16(payload[4+2*i:])) != count {
			return nil, false
		}
	}
	return &msg, true
}

type packetWriter interface {
	WritePacketData([]byte) error
}

func sendBonjourPacket(handle packetWriter, bonjourPacket *bonjourPacket, brMACAddress net.HardwareAddr, maxFrameLen int) error {
	if err := prepareDNSForForwarding(bonjourPacket); err != nil {
		return err
	}

	*bonjourPacket.srcMAC = brMACAddress

	// 抓包过滤器只接收发往 mDNS 组播 IP 的报文，确保目的 MAC 与该 IP 匹配。
	if bonjourPacket.isIPv6 {
		*bonjourPacket.dstMAC = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0xFB}
	} else {
		*bonjourPacket.dstMAC = net.HardwareAddr{0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB}
	}

	var frame []byte
	payload := bonjourPacket.dnsPayload
	if payload == nil {
		// 只替换以太网地址，保留原始 DNS 压缩指针和校验和。
		frame = slices.Clone(bonjourPacket.packet.Data())
		copy(frame[:6], *bonjourPacket.dstMAC)
		copy(frame[6:12], brMACAddress)
		payload = parseUDPLayer(bonjourPacket.packet)
	} else {
		buf := gopacket.NewSerializeBuffer()
		if err := serializeBonjourPacketWithDNS(buf, bonjourPacket.packet, payload); err != nil {
			return err
		}
		frame = buf.Bytes()
	}
	return writeMDNSFrames(handle, bonjourPacket, frame, len(payload), maxFrameLen)
}

func prepareDNSForForwarding(bonjourPacket *bonjourPacket) error {
	if bonjourPacket == nil || bonjourPacket.packet == nil || bonjourPacket.dns == nil {
		return errors.New("cannot prepare DNS without packet data")
	}
	if bonjourPacket.dnsPayload != nil {
		return nil
	}

	message := bonjourPacket.dns

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
	bonjourPacket.dnsPayload = payload
	return nil
}

func writeMDNSFrames(handle packetWriter, packet *bonjourPacket, frame []byte, payloadLen, maxFrameLen int) error {
	if len(frame) <= maxFrameLen {
		if err := handle.WritePacketData(frame); err != nil {
			return fmt.Errorf("write %d-byte frame (limit %d): %w", len(frame), maxFrameLen, err)
		}
		return nil
	}

	maxDNSLen := maxFrameLen - (len(frame) - payloadLen)
	parts, err := splitMDNSMessage(*packet.dns, maxDNSLen)
	if err != nil {
		return fmt.Errorf("split %d-byte frame (limit %d): %w", len(frame), maxFrameLen, err)
	}

	frames := make([][]byte, 0, len(parts))
	for _, part := range parts {
		buf := gopacket.NewSerializeBuffer()
		if err := serializeBonjourPacketWithDNS(buf, packet.packet, part); err != nil {
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

func serializeBonjourPacketWithDNS(buf gopacket.SerializeBuffer, packet gopacket.Packet, payload []byte) error {
	eth, ok := packet.LinkLayer().(*layers.Ethernet)
	if !ok {
		return errors.New("cannot serialize without Ethernet layer")
	}
	network := packet.NetworkLayer()
	ip, ok := network.(gopacket.SerializableLayer)
	if !ok {
		return errors.New("cannot serialize without IP layer")
	}
	udp, ok := packet.TransportLayer().(*layers.UDP)
	if !ok {
		return errors.New("cannot serialize without UDP layer")
	}
	if err := udp.SetNetworkLayerForChecksum(network); err != nil {
		return err
	}
	return gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload))
}
