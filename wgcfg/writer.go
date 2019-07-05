/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wgcfg

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

func (conf *Config) ToWgQuick() string {
	output := new(strings.Builder)
	output.WriteString("[Interface]\n")

	fmt.Fprintf(output, "PrivateKey = %s\n", conf.Interface.PrivateKey.String())

	if conf.Interface.ListenPort > 0 {
		fmt.Fprintf(output, "ListenPort = %d\n", conf.Interface.ListenPort)
	}

	if len(conf.Interface.Addresses) > 0 {
		addrStrings := make([]string, len(conf.Interface.Addresses))
		for i, address := range conf.Interface.Addresses {
			addrStrings[i] = address.String()
		}
		fmt.Fprintf(output, "Address = %s\n", strings.Join(addrStrings[:], ", "))
	}

	if len(conf.Interface.Dns) > 0 {
		addrStrings := make([]string, len(conf.Interface.Dns))
		for i, address := range conf.Interface.Dns {
			addrStrings[i] = address.String()
		}
		fmt.Fprintf(output, "DNS = %s\n", strings.Join(addrStrings[:], ", "))
	}

	if conf.Interface.Mtu > 0 {
		fmt.Fprintf(output, "MTU = %d\n", conf.Interface.Mtu)
	}

	for _, peer := range conf.Peers {
		output.WriteString("\n[Peer]\n")

		fmt.Fprintf(output, "PublicKey = %s\n", peer.PublicKey.String())

		if !peer.PresharedKey.IsZero() {
			fmt.Fprintf(output, "PresharedKey = %s\n", peer.PresharedKey.String())
		}

		if len(peer.AllowedIPs) > 0 {
			addrStrings := make([]string, len(peer.AllowedIPs))
			for i, address := range peer.AllowedIPs {
				addrStrings[i] = address.String()
			}
			fmt.Fprintf(output, "AllowedIPs = %s\n", strings.Join(addrStrings[:], ", "))
		}

		if !peer.Endpoint.IsEmpty() {
			fmt.Fprintf(output, "Endpoint = %s\n", peer.Endpoint.String())
		}

		if peer.PersistentKeepalive > 0 {
			fmt.Fprintf(output, "PersistentKeepalive = %d\n", peer.PersistentKeepalive)
		}
	}
	return output.String()
}

func (conf *Config) ToUAPI() (string, error) {
	output := new(strings.Builder)
	fmt.Fprintf(output, "private_key=%s\n", conf.Interface.PrivateKey.HexString())

	if conf.Interface.ListenPort > 0 {
		fmt.Fprintf(output, "listen_port=%d\n", conf.Interface.ListenPort)
	}

	output.WriteString("replace_peers=true\n")

	for _, peer := range conf.Peers {
		fmt.Fprintf(output, "public_key=%s\n", peer.PublicKey.HexString())

		if !peer.PresharedKey.IsZero() {
			fmt.Fprintf(output, "preshared_key = %s\n", peer.PresharedKey.String())
		}

		if !peer.Endpoint.IsEmpty() {
			ips, err := net.LookupIP(peer.Endpoint.Host)
			if err != nil {
				return "", err
			}
			var ip net.IP
			for _, iterip := range ips {
				iterip = iterip.To4()
				if iterip != nil {
					ip = iterip
					break
				}
				if ip == nil {
					ip = iterip
				}
			}
			if ip == nil {
				return "", errors.New("Unable to resolve IP address of endpoint")
			}
			resolvedEndpoint := Endpoint{ip.String(), peer.Endpoint.Port}
			fmt.Fprintf(output, "endpoint=%s\n", resolvedEndpoint.String())
		}

		fmt.Fprintf(output, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)

		output.WriteString("replace_allowed_ips=true\n")
		if len(peer.AllowedIPs) > 0 {
			for _, address := range peer.AllowedIPs {
				fmt.Fprintf(output, "allowed_ip=%s\n", address.String())
			}
		}
	}
	return output.String(), nil
}
