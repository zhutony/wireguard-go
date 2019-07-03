/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/tun/wintun"
)

const (
	packetExchangeAlignment = 16                               // Number of bytes packets are aligned to in exchange buffers
	packetSizeMax           = 0xf000 - packetExchangeAlignment // Maximum packet size
	packetExchangeSize      = 0x100000                         // Exchange buffer size (1 MB)
	writeExchanges          = 128                              // Number of simultaneous flushes
	retryRate               = 4                                // Number of retries per second to reopen device pipe
	retryTimeout            = 30                               // Number of seconds to tolerate adapter unavailable
)

type exchgBufRead struct {
	file   *os.File
	data   [packetExchangeSize]byte
	offset uint32
	avail  uint32
}

type exchgBufWrite struct {
	fd       windows.Handle
	data     [packetExchangeSize]byte
	offset   uint32
	flushing sync.Mutex
}

type NativeTun struct {
	wt            *wintun.Wintun
	tunLock       sync.Mutex
	close         bool
	events        chan Event
	errors        chan error
	forcedMTU     int
	currentWrBuff int
	rdBuff        exchgBufRead
	wrBuffs       [writeExchanges]exchgBufWrite
}

func packetAlign(size uint32) uint32 {
	return (size + (packetExchangeAlignment - 1)) &^ (packetExchangeAlignment - 1)
}

var shouldRetryOpen = windows.RtlGetVersion().MajorVersion < 10

func maybeRetry(x int) int {
	if shouldRetryOpen {
		return x
	}
	return 0
}

//
// CreateTUN creates a Wintun adapter with the given name. Should a Wintun
// adapter with the same name exist, it is reused.
//
func CreateTUN(ifname string) (Device, error) {
	return CreateTUNWithRequestedGUID(ifname, nil)
}

//
// CreateTUNWithRequestedGUID creates a Wintun adapter with the given name and
// a requested GUID. Should a Wintun adapter with the same name exist, it is reused.
//
func CreateTUNWithRequestedGUID(ifname string, requestedGUID *windows.GUID) (Device, error) {
	var err error
	var wt *wintun.Wintun

	// Does an interface with this name already exist?
	wt, err = wintun.GetInterface(ifname)
	if err == nil {
		// If so, we delete it, in case it has weird residual configuration.
		_, err = wt.DeleteInterface()
		if err != nil {
			return nil, fmt.Errorf("Unable to delete already existing Wintun interface: %v", err)
		}
	} else if err == windows.ERROR_ALREADY_EXISTS {
		return nil, fmt.Errorf("Foreign network interface with the same name exists")
	}
	wt, _, err = wintun.CreateInterface("WireGuard Tunnel Adapter", requestedGUID)
	if err != nil {
		return nil, fmt.Errorf("Unable to create Wintun interface: %v", err)
	}

	err = wt.SetInterfaceName(ifname)
	if err != nil {
		wt.DeleteInterface()
		return nil, fmt.Errorf("Unable to set name of Wintun interface: %v", err)
	}

	return &NativeTun{
		wt:        wt,
		events:    make(chan Event, 10),
		errors:    make(chan error, 1),
		forcedMTU: 1500,
	}, nil
}

func (tun *NativeTun) openTUN() error {
	retries := maybeRetry(retryTimeout * retryRate)
	if tun.close {
		return os.ErrClosed
	}

	var err error
	name := tun.wt.DataFileName()
	for tun.rdBuff.file == nil {
		tun.rdBuff.file, err = os.OpenFile(name, os.O_RDONLY, 0)
		if err != nil {
			if retries > 0 && !tun.close {
				time.Sleep(time.Second / retryRate)
				retries--
				continue
			}
			return err
		}
	}
	for i := range tun.wrBuffs {
		for tun.wrBuffs[i].fd == 0 {
			tun.wrBuffs[i].fd, err = windows.CreateFile(windows.StringToUTF16Ptr(name), windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED, 0)
			if err != nil {
				if retries > 0 && !tun.close {
					time.Sleep(time.Second / retryRate)
					retries--
					continue
				}
				return err
			}
			firstSize := (*uint32)(unsafe.Pointer(&tun.wrBuffs[i].data[0]))
			saved := *firstSize
			*firstSize = 0
			// Set the maximum buffer length with an invalid write.
			var o windows.Overlapped
			if windows.WriteFile(tun.wrBuffs[i].fd, tun.wrBuffs[i].data[:], nil, &o) == windows.ERROR_IO_PENDING {
				var done uint32
				windows.GetOverlappedResult(tun.wrBuffs[i].fd, &o, &done, true)
			}
			*firstSize = saved
		}
	}

	return nil
}

func (tun *NativeTun) closeTUN() (err error) {
	for tun.rdBuff.file != nil {
		tun.tunLock.Lock()
		if tun.rdBuff.file == nil {
			tun.tunLock.Unlock()
			break
		}
		t := tun.rdBuff.file
		tun.rdBuff.file = nil
		windows.CancelIoEx(windows.Handle(t.Fd()), nil)
		err = t.Close()
		tun.tunLock.Unlock()
		break
	}
	for i := range tun.wrBuffs {
		for tun.wrBuffs[i].fd != 0 {
			tun.tunLock.Lock()
			if tun.wrBuffs[i].fd == 0 {
				tun.tunLock.Unlock()
				break
			}
			t := tun.wrBuffs[i].fd
			tun.wrBuffs[i].fd = 0
			windows.CancelIoEx(t, nil)
			err2 := windows.Close(t)
			tun.tunLock.Unlock()
			if err == nil {
				err = err2
			}
			break
		}
	}
	return
}

func (tun *NativeTun) getTUN() (read *os.File, write windows.Handle, err error) {
	wrBuff := &tun.wrBuffs[tun.currentWrBuff]
	read, write = tun.rdBuff.file, wrBuff.fd
	if read == nil || write == 0 {
		read, write = nil, 0
		tun.tunLock.Lock()
		wrBuff = &tun.wrBuffs[tun.currentWrBuff]
		if tun.rdBuff.file != nil && wrBuff.fd != 0 {
			read, write = tun.rdBuff.file, wrBuff.fd
			tun.tunLock.Unlock()
			return
		}
		err = tun.closeTUN()
		if err != nil {
			tun.tunLock.Unlock()
			return
		}
		err = tun.openTUN()
		if err == nil {
			read, write = tun.rdBuff.file, wrBuff.fd
		}
		tun.tunLock.Unlock()
		return
	}
	return
}

func (tun *NativeTun) Name() (string, error) {
	return tun.wt.InterfaceName()
}

func (tun *NativeTun) File() *os.File {
	return nil
}

func (tun *NativeTun) Events() chan Event {
	return tun.events
}

func (tun *NativeTun) Close() error {
	tun.close = true
	err1 := tun.closeTUN()

	if tun.events != nil {
		close(tun.events)
	}

	_, err2 := tun.wt.DeleteInterface()
	if err1 == nil {
		err1 = err2
	}

	return err1
}

func (tun *NativeTun) MTU() (int, error) {
	return tun.forcedMTU, nil
}

// TODO: This is a temporary hack. We really need to be monitoring the interface in real time and adapting to MTU changes.
func (tun *NativeTun) ForceMTU(mtu int) {
	tun.forcedMTU = mtu
}

func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
	}

	retries := maybeRetry(1000)
	for {
		if tun.rdBuff.offset+packetExchangeAlignment <= tun.rdBuff.avail {
			// Get packet from the exchange buffer.
			packet := tun.rdBuff.data[tun.rdBuff.offset:]
			size := *(*uint32)(unsafe.Pointer(&packet[0]))
			pSize := packetAlign(packetExchangeAlignment + size)
			if packetSizeMax < size || tun.rdBuff.avail < tun.rdBuff.offset+pSize {
				// Invalid packet size.
				tun.rdBuff.avail = 0
				continue
			}
			packet = packet[packetExchangeAlignment : packetExchangeAlignment+size]

			// Copy data.
			copy(buff[offset:], packet)
			tun.rdBuff.offset += pSize
			return int(size), nil
		}

		// Get TUN data pipe.
		file, _, err := tun.getTUN()
		if err != nil {
			return 0, err
		}

		n, err := file.Read(tun.rdBuff.data[:])
		if err != nil {
			tun.rdBuff.offset = 0
			tun.rdBuff.avail = 0
			pe, ok := err.(*os.PathError)
			if tun.close {
				return 0, os.ErrClosed
			}
			if retries > 0 && ok && (pe.Err == windows.ERROR_HANDLE_EOF || pe.Err == windows.ERROR_OPERATION_ABORTED) {
				retries--
				tun.closeTUN()
				time.Sleep(time.Millisecond * 2)
				continue
			}
			return 0, err
		}
		if n == 0 {
			if retries == 0 {
				return 0, io.ErrShortBuffer
			}
			retries--
			continue
		}
		tun.rdBuff.offset = 0
		tun.rdBuff.avail = uint32(n)
	}
}

// Note: flush() and putTunPacket() assume the caller comes only from a single thread; there's no locking.

func (tun *NativeTun) Flush() error {
	wrBuff := &tun.wrBuffs[tun.currentWrBuff]
	if wrBuff.offset == 0 {
		return nil
	}
	_, _, err := tun.getTUN()
	if err != nil {
		return err
	}
	wrBuff.flushing.Lock()
	o := &windows.Overlapped{}
	err = windows.WriteFile(wrBuff.fd, wrBuff.data[:wrBuff.offset], nil, o)
	if err == windows.ERROR_IO_PENDING {
		go func(o *windows.Overlapped, wrBuff *exchgBufWrite) {
			var done uint32
			err := windows.GetOverlappedResult(wrBuff.fd, o, &done, true)
			wrBuff.offset = 0
			wrBuff.flushing.Unlock()
			if err != nil {
				retries := maybeRetry(1000)
				if tun.close {
					tun.errors <- os.ErrClosed
				}
				if retries > 0 && err == windows.ERROR_OPERATION_ABORTED { // Adapter is paused or in low-power state.
					return
				}
				if retries > 0 && err == windows.ERROR_HANDLE_EOF { // Adapter is going down.
					tun.closeTUN()
					return
				}
				tun.errors <- err
			}
		}(o, wrBuff)
	} else if err == nil {
		wrBuff.offset = 0
		wrBuff.flushing.Unlock()
		return nil
	} else {
		return err
	}
	tun.currentWrBuff = (tun.currentWrBuff + 1) % writeExchanges
	wrBuff = &tun.wrBuffs[tun.currentWrBuff]
	wrBuff.flushing.Lock()
	wrBuff.flushing.Unlock()
	return nil
}

func (tun *NativeTun) putTunPacket(buff []byte) error {
	size := uint32(len(buff))
	if size == 0 {
		return errors.New("Empty packet")
	}
	if size > packetSizeMax {
		return errors.New("Packet too big")
	}
	pSize := packetAlign(packetExchangeAlignment + size)
	wrBuff := &tun.wrBuffs[tun.currentWrBuff]

	if wrBuff.offset+pSize >= packetExchangeSize {
		// Exchange buffer is full -> flush first.
		err := tun.Flush()
		if err != nil {
			return err
		}
	}

	// Write packet to the exchange buffer.
	packet := wrBuff.data[wrBuff.offset : wrBuff.offset+pSize]
	*(*uint32)(unsafe.Pointer(&packet[0])) = size
	packet = packet[packetExchangeAlignment : packetExchangeAlignment+size]
	copy(packet, buff)

	wrBuff.offset += pSize

	return nil
}

func (tun *NativeTun) Write(buff []byte, offset int) (int, error) {
	err := tun.putTunPacket(buff[offset:])
	if err != nil {
		return 0, err
	}
	return len(buff) - offset, nil
}

//
// LUID returns Windows adapter instance ID.
//
func (tun *NativeTun) LUID() uint64 {
	return tun.wt.LUID()
}
