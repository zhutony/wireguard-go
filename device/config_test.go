package device

import (
	"io"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgcfg"
)

func TestConfig(t *testing.T) {
	pk1, err := wgcfg.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ip1, err := wgcfg.ParseCIDR("10.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}

	pk2, err := wgcfg.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ip2, err := wgcfg.ParseCIDR("10.0.0.2/32")
	if err != nil {
		t.Fatal(err)
	}

	pk3, err := wgcfg.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ip3, err := wgcfg.ParseCIDR("10.0.0.3/32")
	if err != nil {
		t.Fatal(err)
	}

	cfg1 := &wgcfg.Config{
		Interface: wgcfg.Interface{
			PrivateKey: pk1,
		},
		Peers: []wgcfg.Peer{{
			PublicKey:  pk2.Public(),
			AllowedIPs: []wgcfg.CIDR{*ip2},
		}},
	}

	cfg2 := &wgcfg.Config{
		Interface: wgcfg.Interface{
			PrivateKey: pk2,
		},
		Peers: []wgcfg.Peer{{
			PublicKey:           pk1.Public(),
			AllowedIPs:          []wgcfg.CIDR{*ip1},
			PersistentKeepalive: 5,
		}},
	}

	device1 := NewDevice(newNilTun(), NewLogger(LogLevelDebug, "device1"))
	device2 := NewDevice(newNilTun(), NewLogger(LogLevelDebug, "device2"))
	defer device1.Close()
	defer device2.Close()

	t.Run("device1 config", func(t *testing.T) {
		if err := device1.Reconfig(cfg1); err != nil {
			t.Fatal(err)
		}
		if got, want := device1.Config().ToWgQuick(), cfg1.ToWgQuick(); got != want {
			t.Errorf("reconfig:\n%s\n----- want:\n\n%s", got, want)
		}
	})

	t.Run("device2 config", func(t *testing.T) {
		if err := device2.Reconfig(cfg2); err != nil {
			t.Fatal(err)
		}
		if got, want := device2.Config().ToWgQuick(), cfg2.ToWgQuick(); got != want {
			t.Errorf("reconfig:\n%s\n----- want:\n\n%s", got, want)
		}
	})

	t.Run("device1 modify peer", func(t *testing.T) {
		cfg1.Peers[0].Endpoint = wgcfg.Endpoint{
			Host: "1.2.3.4",
			Port: 12345,
		}
		if err := device1.Reconfig(cfg1); err != nil {
			t.Fatal(err)
		}
		if got, want := device1.Config().ToWgQuick(), cfg1.ToWgQuick(); got != want {
			t.Errorf("reconfig:\n%s\n----- want:\n\n%s", got, want)
		}
	})

	t.Run("device1 add new peer", func(t *testing.T) {
		cfg1.Peers = append(cfg1.Peers, wgcfg.Peer{
			PublicKey:  pk3.Public(),
			AllowedIPs: []wgcfg.CIDR{*ip3},
		})

		device1.peers.RLock()
		originalPeer0 := device1.peers.keyMap[pk2.Public()]
		device1.peers.RUnlock()

		if err := device1.Reconfig(cfg1); err != nil {
			t.Fatal(err)
		}
		if got, want := device1.Config().ToWgQuick(), cfg1.ToWgQuick(); got != want {
			t.Errorf("reconfig:\n%s\n----- want:\n\n%s", got, want)
		}

		device1.peers.RLock()
		newPeer0 := device1.peers.keyMap[pk2.Public()]
		device1.peers.RUnlock()

		if originalPeer0 != newPeer0 {
			t.Error("reconfig modified old peer")
		}
	})
}

// TODO: replace with a loopback tunnel
type nilTun struct {
	events chan tun.Event
	closed chan struct{}
}

func newNilTun() tun.Device {
	return &nilTun{
		events: make(chan tun.Event),
		closed: make(chan struct{}),
	}
}

func (t *nilTun) File() *os.File         { return nil }
func (t *nilTun) Flush() error           { return nil }
func (t *nilTun) MTU() (int, error)      { return 1420, nil }
func (t *nilTun) Name() (string, error)  { return "niltun", nil }
func (t *nilTun) Events() chan tun.Event { return t.events }

func (t *nilTun) Read(data []byte, offset int) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *nilTun) Write(data []byte, offset int) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *nilTun) Close() error {
	close(t.events)
	close(t.closed)
	return nil
}
