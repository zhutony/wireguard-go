package main

import "errors"

type DummyDatagram struct {
	contents []byte
	endpoint Endpoint
}

type DummyBind struct {
	in6    chan DummyDatagram // inbound queue of ipv6 packages
	in4    chan DummyDatagram // inbound queue of ipv4 packages
	intr   DummyNetworking    // interface (used for outbound packages)
	closed bool               // bind closed? (no more sending)
}

func (b *DummyBind) SetMark(v uint32) error {
	return nil
}

func (b *DummyBind) ReceiveIPv6(buff []byte) (int, Endpoint, error) {
	datagram, ok := <-b.in6
	if !ok {
		return 0, nil, errors.New("closed")
	}
	copy(buff, datagram.contents)
	return len(datagram.contents), datagram.endpoint, nil
}

func (b *DummyBind) ReceiveIPv4(buff []byte) (int, Endpoint, error) {
	datagram, ok := <-b.in4
	if !ok {
		return 0, nil, errors.New("closed")
	}
	copy(buff, datagram.contents)
	return len(datagram.contents), datagram.endpoint, nil
}

func (b *DummyBind) Close() error {
	close(b.in6)
	close(b.in4)
	b.closed = true
	return nil
}

func (b *DummyBind) Send(buff []byte, end Endpoint) error {
	return nil
}
