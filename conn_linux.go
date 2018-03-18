package main

import (
	"errors"
	"golang.org/x/sys/unix"
	"unsafe"
)

type NativeNetworking struct{}

var _ Networking = (*NativeNetworking)(nil)

func CreateNetworking() (Networking, error) {
	return NativeNetworking{}, nil
}

func (_ NativeNetworking) CreateEndpoint(s string) (Endpoint, error) {
	var end NativeEndpoint
	addr, err := parseEndpoint(s)
	if err != nil {
		return nil, err
	}

	ipv4 := addr.IP.To4()
	if ipv4 != nil {
		dst := (*unix.RawSockaddrInet4)(unsafe.Pointer(&end.dst))
		dst.Family = unix.AF_INET
		dst.Port = htons(uint16(addr.Port))
		dst.Zero = [8]byte{}
		copy(dst.Addr[:], ipv4)
		end.ClearSrc()
		return &end, nil
	}

	ipv6 := addr.IP.To16()
	if ipv6 != nil {
		zone, err := zoneToUint32(addr.Zone)
		if err != nil {
			return nil, err
		}
		dst := &end.dst
		dst.Family = unix.AF_INET6
		dst.Port = htons(uint16(addr.Port))
		dst.Flowinfo = 0
		dst.Scope_id = zone
		copy(dst.Addr[:], ipv6[:])
		end.ClearSrc()
		return &end, nil
	}

	return nil, errors.New("Failed to recognize IP address format")
}

func (_ NativeNetworking) CreateBind(port uint16) (Bind, uint16, error) {
	var err error
	var bind NativeBind

	bind.sock6, port, err = create6(port)
	if err != nil {
		return nil, port, err
	}

	bind.sock4, port, err = create4(port)
	if err != nil {
		unix.Close(bind.sock6)
	}
	return bind, port, err
}
