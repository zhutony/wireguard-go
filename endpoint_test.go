package main

import (
	"net"
)

type DummyEndpoint struct {
	src net.UDPAddr
	dst net.UDPAddr
}

func CreateDummyEndpoint(
	src net.UDPAddr,
	dst net.UDPAddr,
) *DummyEndpoint {
	return &DummyEndpoint{
		src: src,
		dst: dst,
	}
}

func (e *DummyEndpoint) ClearSrc() {
	e.src.Port = 0
	e.src.IP = nil
}

func (e *DummyEndpoint) SrcToString() string {
	return e.src.String()
}

func (e *DummyEndpoint) DstToString() string {
	return e.dst.String()
}

func (e *DummyEndpoint) DstToBytes() []byte {
	return e.dst.IP
}

func (e *DummyEndpoint) SrcToBytes() []byte {
	return e.src.IP
}

func (e *DummyEndpoint) DstIP() net.IP {
	return e.dst.IP
}

func (e *DummyEndpoint) SrcIP() net.IP {
	return e.src.IP
}
