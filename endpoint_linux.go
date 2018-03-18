package main

import (
	"golang.org/x/sys/unix"
	"net"
	"unsafe"
)

/* Supports source address caching
 *
 * Currently there is no way to achieve this within the net package:
 * See e.g. https://github.com/golang/go/issues/17930
 * So this code is remains platform dependent.
 */
type NativeEndpoint struct {
	src unix.RawSockaddrInet6
	dst unix.RawSockaddrInet6
}

var _ Endpoint = (*NativeEndpoint)(nil)

func (end *NativeEndpoint) SrcIP() net.IP {
	return rawAddrToIP(end.src)
}

func (end *NativeEndpoint) DstIP() net.IP {
	return rawAddrToIP(end.dst)
}

func (end *NativeEndpoint) DstToBytes() []byte {
	ptr := unsafe.Pointer(&end.src)
	arr := (*[unix.SizeofSockaddrInet6]byte)(ptr)
	return arr[:]
}

func (end *NativeEndpoint) SrcToString() string {
	return sockaddrToString(end.src)
}

func (end *NativeEndpoint) DstToString() string {
	return sockaddrToString(end.dst)
}

func (end *NativeEndpoint) ClearDst() {
	end.dst = unix.RawSockaddrInet6{}
}

func (end *NativeEndpoint) ClearSrc() {
	end.src = unix.RawSockaddrInet6{}
}
