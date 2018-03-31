package main

/* Create two device instances and simulate full WireGuard interaction
 * without network dependencies
 */

import "testing"

func TestDevice(t *testing.T) {

	// prepare tun devices for generating traffic

	tun1, err := CreateDummyTUN("tun1")
	if err != nil {
		t.Error("failed to create tun:", err)
	}

	tun2, err := CreateDummyTUN("tun2")
	if err != nil {
		t.Error("failed to create tun:", err)
	}

	println(tun1)
	println(tun2)

	var network DummyNetwork

	// prepare networking

	net1, err := CreateDummyNetworking(&network)
	if err != nil {
		t.Error("failed to prepare networking:", err)
	}

	net2, err := CreateDummyNetworking(&network)
	if err != nil {
		t.Error("failed to prepare networking:", err)
	}

	println(net1)
	println(net2)

	// create binds

}
