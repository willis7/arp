package arp

import (
	"bytes"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Device holds information about a device with a mac address, and
// an action which should be performed when an ARP request is made
type Device struct {
	Name   string
	Mac    string
	Action Actioner
}

// Actioner is a single method interface which defines the action
// to be executed when an ARP request is detected
type Actioner interface {
	action()
}

// The ActionerFunc type is an adapter to allow the use of
// ordinary functions as actions. If f is a function
// with the appropriate signature, ActionerFunc(f) is a
// Actioner that calls f.
type ActionerFunc func()

func (f ActionerFunc) action() {
	f()
}

// Sniff takes a list of devices and a network interface.
// Upon detection of a device its Actioner action is called.
func Sniff(devices []Device, nic string) {
	log.Printf("Starting up on interface[%v]...", nic)

	h, err := pcap.OpenLive(nic, 65536, true, pcap.BlockForever)
	if err != nil || h == nil {
		log.Fatalf("Error opening interface: %s\nPerhaps you need to run as root?\n", err)
	}
	defer h.Close()

	var filter = "arp and ("
	for _, dev := range devices {
		mac, err := net.ParseMAC(dev.Mac)
		if err != nil {
			log.Fatal(err)
		}
		filter += "(ether src host " + mac.String() + ")"
	}
	filter += ")"

	err = h.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Unable to set filter! %s\n", err)
	}
	log.Println("Listening for Dash buttons...")

	packetSource := gopacket.NewPacketSource(h, h.LinkType())

	// Since we're using a BPF filter to limit packets to only our buttons, we don't need to worry about anything besides MAC here...
	for packet := range packetSource.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		for _, dev := range devices {
			mac, err := net.ParseMAC(dev.Mac)
			if err != nil {
				log.Fatal(err)
			}
			if bytes.Equal(ethernetPacket.SrcMAC, mac) {
				log.Printf("Button [%v] was pressed.", dev.Name)
				dev.Action.action()
			} else {
				log.Printf("Received dev press, but don't know how to handle MAC[%v]", ethernetPacket.SrcMAC)
			}
		}
	}
}
