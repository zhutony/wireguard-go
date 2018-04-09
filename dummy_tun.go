package main

import (
	"os"
	"sync/atomic"
)

type DummyTUN struct {
	name     string
	mtu      int32
	inbound  chan []byte //
	outbound chan []byte //
	events   chan TUNEvent
}

func (tun *DummyTUN) File() *os.File {
	return nil
}

func (tun *DummyTUN) Name() string {
	return tun.name
}

func (tun *DummyTUN) MTU() (int, error) {
	mtu := atomic.LoadInt32(&tun.mtu)
	return int(mtu), nil
}

func (tun *DummyTUN) Write(d []byte, offset int) (int, error) {
	tun.outbound <- d[offset:]
	return len(d), nil
}

func (tun *DummyTUN) Close() error {
	return nil
}

func (tun *DummyTUN) Events() chan TUNEvent {
	return tun.events
}

func (tun *DummyTUN) Read(d []byte, offset int) (int, error) {
	t := <-tun.inbound
	copy(d[offset:], t)
	return len(t), nil
}

func CreateDummyTUN(name string) (*DummyTUN, error) {
	var dummy DummyTUN
	dummy.mtu = 1600
	dummy.events = make(chan TUNEvent, 10)
	dummy.inbound = make(chan []byte, 100)
	dummy.outbound = make(chan []byte, 100)
	return &dummy, nil
}

// extension

func (tun *DummyTUN) SetMTU(mtu int) {
	atomic.StoreInt32(&tun.mtu, int32(mtu))
}

func (tun *DummyTUN) Inbound() <-chan []byte {
	return tun.inbound
}

func (tun *DummyTUN) Outbound() chan<- []byte {
	return tun.outbound
}
