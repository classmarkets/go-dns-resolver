//go:build !windows
// +build !windows

package dnsresolver

import (
	"net"

	"github.com/miekg/dns"
)

func (r *Resolver) discoverSystemServers() ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.systemServerAddrs == nil {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}

		for _, addr := range config.Servers {
			r.systemServerAddrs = append(r.systemServerAddrs, net.JoinHostPort(addr, r.defaultPort))
		}
	}

	addrs := make([]string, len(r.systemServerAddrs))
	copy(addrs, r.systemServerAddrs)

	return addrs, nil
}
