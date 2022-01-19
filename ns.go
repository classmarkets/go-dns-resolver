package dnsresolver

import (
	"log"
	"net"

	"github.com/miekg/dns"
)

type nsSet interface {
	Err() error
	Addrs() []string
}

type hardCodedNSSet []string

var _ nsSet = (hardCodedNSSet)(nil)

func (set hardCodedNSSet) Err() error      { return nil }
func (set hardCodedNSSet) Addrs() []string { return set }

type nsResponseSet QueryResult

var _ nsSet = nsResponseSet{}

func (set nsResponseSet) Err() error { return set.Error }
func (set nsResponseSet) Addrs() []string {
	var ips []string

	for _, rr := range append(set.Response.Answer, set.Response.Ns...) {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}

		value := ns.Ns
		log.Println(value, net.ParseIP(value))
		if net.ParseIP(value) != nil {
			ips = append(ips, value)
			continue
		}

		ips = append(ips, set.tryMapIPs(value)...)
	}

	return ips // TODO: de-dup
}

// tryMapIPs maps domain names to IP addresses using the ADDITIONAL section of
// the NS response. If no mapping exists, name is returned as-is.
func (set nsResponseSet) tryMapIPs(name string) []string {
	var ips []string
	for _, rr := range set.Response.Extra {
		if rr.Header().Name != name {
			continue
		}

		switch rr := rr.(type) {
		case *dns.A:
			ips = append(ips, rr.A.String())
		case *dns.AAAA:
			ips = append(ips, rr.AAAA.String())
		}
	}

	if len(ips) == 0 {
		return []string{name}
	}

	return ips
}
