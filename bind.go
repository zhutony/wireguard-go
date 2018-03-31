package main

import (
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

/* A Bind handles listening on a port for both IPv6 and IPv4 UDP traffic
 * - Similar to a net.UDPConn interface.
 */
type Bind interface {
	SetMark(value uint32) error
	ReceiveIPv6(buff []byte) (int, Endpoint, error)
	ReceiveIPv4(buff []byte) (int, Endpoint, error)
	Send(buff []byte, end Endpoint) error
	Close() error
}

/* Must hold device and net lock
 */
func unsafeCloseBind(device *Device) error {
	var err error
	netc := &device.net
	if netc.bind != nil {
		err = netc.bind.Close()
		netc.bind = nil
	}
	return err
}

func (device *Device) BindSetMark(mark uint32) error {

	device.net.mutex.Lock()
	defer device.net.mutex.Unlock()

	device.peers.mutex.Lock()
	defer device.peers.mutex.Unlock()

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

func (device *Device) BindUpdate() error {

	device.net.mutex.Lock()
	defer device.net.mutex.Unlock()

	device.peers.mutex.Lock()
	defer device.peers.mutex.Unlock()

	// close existing sockets

	if err := unsafeCloseBind(device); err != nil {
		return err
	}

	// open new sockets

	if device.isUp.Get() {

		// bind to new port

		var err error
		netc := &device.net
		netc.bind, netc.port, err = device.net.network.CreateBind(netc.port)
		if err != nil {
			netc.bind = nil
			netc.port = 0
			return err
		}

		// set fwmark

		if netc.fwmark != 0 {
			err = netc.bind.SetMark(netc.fwmark)
			if err != nil {
				return err
			}
		}

		// clear cached source addresses

		for _, peer := range device.peers.keyMap {
			peer.mutex.Lock()
			defer peer.mutex.Unlock()
			if peer.endpoint != nil {
				peer.endpoint.ClearSrc()
			}
		}

		// start receiving routines

		go device.RoutineReceiveIncoming(ipv4.Version, netc.bind)
		go device.RoutineReceiveIncoming(ipv6.Version, netc.bind)

		device.log.Debug.Println("UDP bind has been updated")
	}

	return nil
}

func (device *Device) BindClose() error {
	device.net.mutex.Lock()
	err := unsafeCloseBind(device)
	device.net.mutex.Unlock()
	return err
}
