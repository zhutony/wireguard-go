// SPDX-License-Identifier: MIT

package device

import (
	"fmt"

	"golang.org/x/xerrors"

	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/wgcfg"
)

func (device *Device) Config() *wgcfg.Config {
	// Lock everything.
	device.net.Lock()
	device.net.Unlock()
	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()
	device.peers.Lock()
	defer device.peers.Unlock()

	cfg := &wgcfg.Config{
		Interface: wgcfg.Interface{
			PrivateKey: device.staticIdentity.privateKey,
			ListenPort: device.net.port,
		},
	}
	for _, peer := range device.peers.keyMap {
		peer.RLock()
		p := wgcfg.Peer{
			PublicKey:           peer.handshake.remoteStatic,
			PresharedKey:        peer.handshake.presharedKey,
			PersistentKeepalive: peer.persistentKeepaliveInterval,
		}
		if peer.endpoint != nil {
			remoteAddr := peer.endpoint.RemoteAddr()
			p.Endpoint = wgcfg.Endpoint{
				Host: remoteAddr.IP.String(),
				Port: uint16(remoteAddr.Port),
			}
		}
		for _, ipnet := range device.allowedips.EntriesForPeer(peer) {
			ones, _ := ipnet.Mask.Size()
			cidr := wgcfg.CIDR{
				Mask: uint8(ones),
			}
			copy(cidr.IP.Addr[:], ipnet.IP.To16())
			p.AllowedIPs = append(p.AllowedIPs, cidr)
		}
		peer.RUnlock()

		cfg.Peers = append(cfg.Peers, p)
	}

	return cfg
}

// Reconfig replaces the existing device configuration with cfg.
func (device *Device) Reconfig(cfg *wgcfg.Config) (err error) {
	defer func() {
		if err != nil {
			device.RemoveAllPeers()
		}
	}()

	device.peers.RLock()
	oldPeers := make(map[wgcfg.Key]bool)
	for k := range device.peers.keyMap {
		oldPeers[k] = true
	}
	device.peers.RUnlock()

	device.RemoveAllPeers()
	if err := device.SetPrivateKey(cfg.Interface.PrivateKey); err != nil {
		return err
	}

	device.net.Lock()
	device.net.port = cfg.Interface.ListenPort
	device.net.Unlock()

	if err := device.BindUpdate(); err != nil {
		return ErrPortInUse
	}

	// TODO(crawshaw): UAPI supports an fwmark field

	for _, p := range cfg.Peers {
		if device.LookupPeer(p.PublicKey) != nil {
			return fmt.Errorf("wireguard: peer appears multiple times in config: %v", p.PublicKey)
		}
		peer, err := device.NewPeer(p.PublicKey)
		if err != nil {
			return err
		}

		if !p.PresharedKey.IsZero() {
			peer.handshake.mutex.Lock()
			peer.handshake.presharedKey = p.PresharedKey
			peer.handshake.mutex.Unlock()
		}

		var ep Endpoint
		if !p.Endpoint.IsEmpty() {
			ep, err = CreateEndpoint(p.Endpoint.String())
			if err != nil {
				return err
			}
		}

		peer.Lock()
		peer.endpoint = ep
		peer.persistentKeepaliveInterval = p.PersistentKeepalive
		peer.Unlock()

		// Send immediate keepalive if we're turning it on and before it wasn't on.
		if p.PersistentKeepalive != 0 && oldPeers[p.PublicKey] && device.isUp.Get() {
			peer.SendKeepalive()
		}

		for _, allowedIP := range p.AllowedIPs {
			ones := uint(allowedIP.Mask)
			device.allowedips.Insert(allowedIP.IP.IP(), ones, peer)
		}
	}

	return nil
}

var ErrPortInUse = xerrors.Errorf("wireguard: local port in use: %w", &IPCError{ipc.IpcErrorPortInUse})
