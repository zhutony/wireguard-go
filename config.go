package main

import (
	"net"
)

// Get Device State

func (device *Device) GetPrivateKey() NoisePrivateKey {
	device.noise.mutex.Lock()
	defer device.noise.mutex.Unlock()
	return device.noise.privateKey
}

func (device *Device) GetPublicKey() NoisePublicKey {
	device.noise.mutex.Lock()
	defer device.noise.mutex.Unlock()
	return device.noise.publicKey
}

func (device *Device) GetListenPort() uint16 {
	device.net.mutex.Lock()
	defer device.net.mutex.Unlock()
	return device.net.port
}

func (device *Device) GetFWMark() uint32 {
	device.net.mutex.Lock()
	defer device.net.mutex.Unlock()
	return device.net.fwmark
}

func (device *Device) GetAllowedIPs(peer *Peer) []net.IPNet {
	device.routing.mutex.RLock()
	defer device.routing.mutex.RUnlock()
	return device.routing.table.AllowedIPs(peer)
}

func (device *Device) GetPeers() []*Peer {
	device.peers.mutex.Lock()
	defer device.peers.mutex.Unlock()

	// extract a list of peers

	peers := make([]*Peer, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peers = append(peers, peer)
	}
	return peers
}

// Update Device State

func (device *Device) SetPort(port uint16) {
	device.net.mutex.Lock()
	device.net.port = port
	device.net.mutex.Unlock()
}

func (device *Device) SetMark(mark uint32) error {

	device.net.mutex.Lock()
	defer device.net.mutex.Unlock()

	// check if modified

	if device.net.fwmark == mark {
		return nil
	}

	// update fwmark on existing bind

	device.net.fwmark = mark
	if device.isUp.Get() && device.net.bind != nil {
		if err := device.net.bind.SetMark(mark); err != nil {
			return err
		}
	}

	return nil
}

func (device *Device) ReplaceAllowedIPs(peer *Peer) {
	device.routing.mutex.Lock()
	device.routing.table.RemovePeer(peer)
	device.routing.mutex.Unlock()
}

func (device *Device) AddAllowedIP(ip net.IP, prefix uint, peer *Peer) {
	device.routing.mutex.Lock()
	device.routing.table.Insert(ip, prefix, peer)
	device.routing.mutex.Unlock()
}
