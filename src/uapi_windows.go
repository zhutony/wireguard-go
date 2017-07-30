package main

/* UAPI on windows uses a bidirectional named pipe
 *
 *
 */

import (
	"net"
	"fmt"
	"github.com/Microsoft/go-winio"
)

const (
	ipcErrorIO           = int64(1)
	ipcErrorNoPeer       = int64(1)
	ipcErrorNoKeyValue   = int64(1)
	ipcErrorInvalidKey   = int64(1)
	ipcErrorInvalidValue = int64(1)
)

const PipeNameFmt = "\\\\.\\pipe\\wireguard-ipc-%s"

type UAPIListener struct {
	listener net.Listener
}

func (uapi *UAPIListener) Accept() (net.Conn, error) {
	return nil, nil
}

func (uapi *UAPIListener) Close() error {
	return uapi.listener.Close()
}

func (uapi *UAPIListener) Addr() net.Addr {
	return nil
}

func NewUAPIListener(name string) (net.Listener, error) {
	path := fmt.Sprintf(PipeNameFmt, name)
	return winio.ListenPipe(path, &winio.PipeConfig{
		InputBufferSize: 2048,
		OutputBufferSize: 2048,
	})
}