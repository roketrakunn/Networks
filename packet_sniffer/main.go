package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	iface := flag.String("i", "", "Network interface to sniff (default: first non-loopback)")
	listIfaces := flag.Bool("list", false, "List available interfaces")
	flag.Parse()

	if *listIfaces {
		listInterfaces()
		return
	}

	if *iface == "" {
		*iface = defaultIface()
	}

	handle, err := pcap.OpenLive(*iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Could not open interface %s: %v", *iface, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp"); err != nil {
		log.Fatalf("Could not set BPF filter: %v", err)
	}

	fmt.Printf("Sniffing TCP on [%s] ...\n\n", *iface)

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range src.Packets() {
		printPacket(packet)
	}
}

func printPacket(packet gopacket.Packet) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ethLayer == nil || ipLayer == nil || tcpLayer == nil {
		return
	}

	eth := ethLayer.(*layers.Ethernet)
	ip := ipLayer.(*layers.IPv4)
	tcp := tcpLayer.(*layers.TCP)

	flags := tcpFlags(tcp)

	fmt.Println("─────────────────────────────────────────────────")
	fmt.Printf("  MAC   %s  →  %s\n", eth.SrcMAC, eth.DstMAC)
	fmt.Printf("  IP    %-20s →  %s\n", ip.SrcIP, ip.DstIP)
	fmt.Printf("  Port  %-6d                →  %d\n", tcp.SrcPort, tcp.DstPort)
	fmt.Printf("  Flags [%s]\n", flags)
	fmt.Printf("  Seq   %-12d   Ack  %d\n", tcp.Seq, tcp.Ack)
	fmt.Printf("  Size  %d bytes\n", len(packet.Data()))
}

func tcpFlags(tcp *layers.TCP) string {
	var f []string
	if tcp.SYN { f = append(f, "SYN") }
	if tcp.ACK { f = append(f, "ACK") }
	if tcp.FIN { f = append(f, "FIN") }
	if tcp.RST { f = append(f, "RST") }
	if tcp.PSH { f = append(f, "PSH") }
	if tcp.URG { f = append(f, "URG") }
	if len(f) == 0 {
		return "NONE"
	}
	return strings.Join(f, " | ")
}

func defaultIface() string {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Name != "lo" && len(iface.Addresses) > 0 {
			return iface.Name
		}
	}
	log.Fatal("No usable network interface found. Use -list to see available ones.")
	return ""
}

func listInterfaces() {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Available interfaces:")
	for _, iface := range ifaces {
		fmt.Printf("  %-12s", iface.Name)
		for _, addr := range iface.Addresses {
			fmt.Printf("  %s", addr.IP)
		}
		fmt.Println()
	}
}
