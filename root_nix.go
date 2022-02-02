//go:build !windows
// +build !windows

package dnsresolver

import (
	"net"

	"github.com/miekg/dns"
)

func (r *Resolver) discoverSystemServers() ([]string, error) {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}

	var addrs []string
	for _, addr := range config.Servers {
		addrs = append(addrs, net.JoinHostPort(addr, "53"))
	}

	return addrs, nil
}
