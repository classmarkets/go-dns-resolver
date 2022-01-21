//go:build !windows
// +build !windows

package dnsresolver

import (
	"errors"
	"log"
	"net"

	"github.com/miekg/dns"
)

type discoveredNsSet struct {
	err   error
	addrs []string
}

var _ nsSet = (*discoveredNsSet)(nil)

func (set *discoveredNsSet) Err() error {
	if set.err != nil {
		return set.err
	}
	if len(set.addrs) == 0 {
		return errors.New("system resolvers not discovered")
	}
	return nil
}

func (set *discoveredNsSet) Addrs() []dns.RR {
	var rrs []dns.RR

	for _, addr := range set.addrs {
		if ip := net.ParseIP(addr); ip != nil {
			rrs = append(rrs, ipRR(ip))
		} else {
			rrs = append(rrs, &dns.NS{Ns: dns.CanonicalName(addr)})
		}
	}

	return rrs
}

func (r *Resolver) discoverSystemServers() nsSet {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.systemServerAddrs) > 0 {
		return hardCodedNSSet(r.systemServerAddrs)
	}

	set := &discoveredNsSet{}

	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		set.err = err
		return set
	}

	for _, addr := range config.Servers {
		r.systemServerAddrs = append(r.systemServerAddrs, addr)
		set.addrs = append(set.addrs, addr)
	}
	log.Println(set.addrs)

	return set
}
