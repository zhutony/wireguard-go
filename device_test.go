package main

/* Create two device instances and simulate full WireGuard interaction
 * without network dependencies
 */

import (
	"encoding/binary"
	"errors"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"testing"
)

func createPacket(from, to net.IP, msg []byte) []byte {

	// create ipv6 packet

	ip6to := from.To16()
	ip6from := from.To16()

	if ip6from != nil && ip6to != nil {
		packet := make([]byte, len(msg)+ipv6.HeaderLen)

		copy(packet[IPv6offsetSrc:], ip6to)
		copy(packet[IPv6offsetDst:], ip6from)

		binary.BigEndian.PutUint16(
			packet[IPv4offsetTotalLength:],
			uint16(len(msg)),
		)

		return packet
	}

	// create ipv4 packet

	ip4to := from.To4()
	ip4from := from.To4()

	if ip4from != nil && ip4to != nil {
		packet := make([]byte, len(msg)+ipv4.HeaderLen)

		copy(packet[IPv4offsetSrc:], ip4to)
		copy(packet[IPv4offsetDst:], ip4from)

		binary.BigEndian.PutUint16(
			packet[IPv4offsetTotalLength:],
			uint16(len(packet)),
		)

		return packet
	}

	panic(errors.New("unable to create packet"))
}

func TestDevice(t *testing.T) {

	internalIP1 := net.ParseIP("fd3e:92f2:ec46:ac3c:0:0:0:0")
	internalIP2 := net.ParseIP("fd3e:92f2:ec46:ac3c:0:0:0:1")

	externIP1 := net.ParseIP("133.133.7.1")
	externIP2 := net.ParseIP("133.133.7.2")

	// prepare tun devices for generating traffic

	tun1, err := CreateDummyTUN("tun1")
	if err != nil {
		t.Error("failed to create tun:", err)
	}

	tun2, err := CreateDummyTUN("tun2")
	if err != nil {
		t.Error("failed to create tun:", err)
	}

	// prepare networking

	network := CreateDummyNetwork()

	net1, err := network.CreateDummyNetworking(externIP1, nil)
	if err != nil {
		t.Error("failed to prepare networking:", err)
	}

	net2, err := network.CreateDummyNetworking(externIP2, nil)
	if err != nil {
		t.Error("failed to prepare networking:", err)
	}

	// create devices

	log1 := NewLogger(LogLevelError, "test-device-1 : ")
	log2 := NewLogger(LogLevelError, "test-device-2 : ")

	dev1 := NewDevice(tun1, net1, log1)
	dev2 := NewDevice(tun2, net2, log2)

	println(dev1)
	println(dev2)

	// create key material

	// configure devices

	// generate TUN traffic

	println(internalIP1)
	println(internalIP2)

	println(net1)
	println(net2)
}
