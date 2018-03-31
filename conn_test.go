package main

import (
	"errors"
	"net"
	"sync"
)

/* Fixed size IP type used as routing map keys
 */
type fIPv4 [net.IPv4len]byte
type fIPv6 [net.IPv6len]byte

/* Represents an instance of "the internet" for our tests
 */
type DummyNetwork struct {
	mutex  sync.RWMutex
	route4 map[fIPv4]*DummyNetworking // map ipv4 to interface
	route6 map[fIPv6]*DummyNetworking // map ipv6 to interface

	// benchmark fields

	// network modifier (change latency, throughput, ...)
}

/* Represents an "interface" on the dummy network
 */
type DummyNetworking struct {
	mutex  sync.RWMutex
	world  *DummyNetwork
	binds  map[uint16]*DummyBind
	source net.IP
}

/* This is the opaque interface exposed to the device implementation½
 */
var _ Networking = (*DummyNetworking)(nil)

func (world *DummyNetwork) CreateDummyNetworking(
	ipv4 net.IP,
	ipv6 net.IP,
) (Networking, error) {

	world.mutex.Lock()
	defer world.mutex.Unlock()

	intr := &DummyNetworking{
		world: world,
		binds: make(map[uint16]*DummyBind),
	}

	if v4 := ipv4.To4(); v4 != nil {
		var key fIPv4
		copy(key[:], v4)
		if _, ok := world.route4[key]; ok {
			return nil, errors.New("IPv4 already assigned")
		}
		world.route4[key] = intr
		intr.source = ipv4
	}

	if v6 := ipv6.To16(); v6 != nil {
		var key fIPv6
		copy(key[:], v6)
		if _, ok := world.route6[key]; ok {
			return nil, errors.New("IPv6 already assigned")
		}
		world.route6[key] = intr
		intr.source = ipv6
	}

	return intr, nil
}

func (_ DummyNetworking) CreateEndpoint(addr string) (Endpoint, error) {
	return nil, errors.New("not used in unit tests")
}

func (world DummyNetwork) send(
	contents []byte,
	src net.UDPAddr,
	to Endpoint,
) error {

	// create src endpoint for delivery

	endpoint := &DummyEndpoint{
		dst: src, // dst from recipients perspective
		src: to.(*DummyEndpoint).dst,
	}

	datagram := DummyDatagram{
		contents: contents,
		endpoint: endpoint,
	}

	// extract IP address from "to" and deliver to interface

	ip := to.DstIP()

	if v6 := ip.To16(); v6 != nil {
		var key fIPv6
		copy(key[:], v6)
		if intr, ok := world.route6[key]; ok {
			return intr.recv6(datagram, endpoint.src)
		} else {
			return errors.New("No route (ipv6)")
		}
	}

	if v4 := ip.To4(); v4 != nil {
		var key fIPv4
		copy(key[:], v4)
		if intr, ok := world.route4[key]; ok {
			return intr.recv4(datagram, endpoint.src)
		} else {
			return errors.New("No route (ipv4)")
		}
	}

	return errors.New("Unable to parse IP")
}

func (intr DummyNetworking) recv6(
	datagram DummyDatagram,
	dst net.UDPAddr,
) error {
	bind := intr.binds[uint16(dst.Port)]
	bind.in6 <- datagram
	return nil
}

func (intr DummyNetworking) recv4(
	datagram DummyDatagram,
	dst net.UDPAddr,
) error {
	bind := intr.binds[uint16(dst.Port)]
	bind.in4 <- datagram
	return nil
}

func (intr DummyNetworking) send(
	msg []byte, // packet contents
	port uint16, // source port
	to Endpoint, // remote destination
) error {
	var addr net.UDPAddr
	addr.IP = intr.source
	addr.Port = int(port)
	return intr.world.send(msg, addr, to)
}

func (intr DummyNetworking) CreateBind(port uint16) (Bind, uint16, error) {

	intr.mutex.Lock()
	defer intr.mutex.Unlock()

	bind := &DummyBind{
		in6:    make(chan DummyDatagram, 100),
		in4:    make(chan DummyDatagram, 100),
		closed: false,
	}

	if port == 0 {
		for port = 1; true; port++ {
			if _, ok := intr.binds[port]; !ok {
				break
			}
		}
	}

	intr.binds[port] = bind

	return bind, port, nil
}

func CreateDummyNetwork() *DummyNetwork {
	var world DummyNetwork
	world.route6 = make(map[fIPv6]*DummyNetworking)
	world.route4 = make(map[fIPv4]*DummyNetworking)
	return &world
}
