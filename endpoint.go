package main

import (
	"errors"
	"net"
)

/* An Endpoint maintains the source/destination caching for a peer
 *
 * dst : the remote address of a peer ("endpoint" in uapi terminology)
 * src : the local address from which datagrams originate going to the peer
 */
type Endpoint interface {
	ClearSrc()           // clears the source address
	SrcToString() string // returns the local source address (ip:port)
	DstToString() string // returns the destination address (ip:port)
	DstToBytes() []byte  // used for mac2 cookie calculations
	DstIP() net.IP
	SrcIP() net.IP
}

func parseEndpoint(s string) (*net.UDPAddr, error) {

	// ensure that the host is an IP address (e.g. not a domain name)

	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip == nil {
		return nil, errors.New("Failed to parse IP address: " + host)
	}

	// parse address and port

	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	return addr, err
}
