package main

import (
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type bonjourPacket struct {
	packet     gopacket.Packet
	srcMAC     *net.HardwareAddr
	dstMAC     *net.HardwareAddr
	isIPv6     bool
	vlanTag    *uint16
	dns        *layers.DNS
	isDNSQuery bool
}

const mdnsQUBit layers.DNSClass = 0x8000

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
	serializeDNS := prepareDNSQueryForForwarding(bonjourPacket)

	if bonjourPacket.vlanTag != nil {
		*bonjourPacket.vlanTag = tag
	}
	*bonjourPacket.srcMAC = brMACAddress

	// Network devices may set dstMAC to the local MAC address
	// Rewrite dstMAC to ensure that it is set to the appropriate multicast MAC address
	if bonjourPacket.isIPv6 {
		*bonjourPacket.dstMAC = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0xFB}
	} else {
		*bonjourPacket.dstMAC = net.HardwareAddr{0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB}
	}

	buf := gopacket.NewSerializeBuffer()
	if serializeDNS {
		if err := serializeBonjourPacketWithDNS(buf, bonjourPacket); err != nil {
			return err
		}
	} else if err := gopacket.SerializePacket(buf, gopacket.SerializeOptions{}, bonjourPacket.packet); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

func prepareDNSQueryForForwarding(bonjourPacket *bonjourPacket) bool {
	if bonjourPacket == nil || !bonjourPacket.isDNSQuery {
		return false
	}

	hasDNS := false
	if bonjourPacket.dns != nil {
		clearDNSQuestionsQUBit(bonjourPacket.dns)
		hasDNS = true
	}
	if bonjourPacket.packet != nil {
		if dnsLayer := bonjourPacket.packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			clearDNSQuestionsQUBit(dnsLayer.(*layers.DNS))
			hasDNS = true
		}
	}
	return hasDNS
}

func clearDNSQuestionsQUBit(dns *layers.DNS) bool {
	changed := false
	for i := range dns.Questions {
		if dns.Questions[i].Class&mdnsQUBit != 0 {
			dns.Questions[i].Class &^= mdnsQUBit
			changed = true
		}
	}
	return changed
}

func serializeBonjourPacketWithDNS(buf gopacket.SerializeBuffer, bonjourPacket *bonjourPacket) error {
	if bonjourPacket == nil {
		return errors.New("cannot serialize nil Bonjour packet")
	}
	if bonjourPacket.packet == nil {
		return errors.New("cannot serialize Bonjour packet without packet data")
	}
	if bonjourPacket.dns == nil {
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
	serializableLayers = append(serializableLayers, udp, bonjourPacket.dns)

	return gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, serializableLayers...)
}
