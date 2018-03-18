package main

import (
	"errors"
	"net"
)

// represents an instance of a "networking interface" for our tests

type DummyNetworking struct {
	world DummyNetwork
}

var _ Networking = (*DummyNetworking)(nil)

func CreateDummyNetworking() (Networking, error) {
	return DummyNetworking{}, nil
}

func (_ DummyNetworking) CreateEndpoint(addr string) (Endpoint, error) {
	return nil, nil
}

func (_ DummyNetworking) CreateBind(port uint16) (Bind, uint16, error) {
	return nil, 0, nil
}

//

func (_ DummyNetworking) deliver(packet []byte, from Endpoint) {

}

// represents an instance of "the internet" for our tests

type DummyNetwork struct {
	route6 map[[16]byte]DummyNetworking
}

func (network *DummyNetwork) Send(from Networking, to Endpoint) {
	if len(to) != 16 {
		panic(errors.New("Only ipv6 supported by dummy network"))
	}

	var addr [16]byte
	copy(addr[:], to)
	network.route6[addr].


}

func (network *DummyNetwork) AddInterface() (net.IP, Networking) {
	return nil, nil
}
