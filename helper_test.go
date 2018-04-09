package main

import (
	"bytes"
	"testing"
)

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a []byte, b []byte) {
	if bytes.Compare(a, b) != 0 {
		t.Fatal(a, "!=", b)
	}
}

func randDevice(t *testing.T) *Device {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tun, _ := CreateDummyTUN("dummy")
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun, nil, logger)
	device.SetPrivateKey(sk)
	return device
}
