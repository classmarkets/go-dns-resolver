package dnsresolver

import (
	"net"

	"github.com/miekg/dns"
)

type nsSet interface {
	Err() error
	Addrs() []dns.RR
}

type hardCodedNSSet []string

var _ nsSet = (hardCodedNSSet)(nil)

func (set hardCodedNSSet) Err() error { return nil }
func (set hardCodedNSSet) Addrs() []dns.RR {
	var rrs []dns.RR
	for _, addr := range set {
		// TODO dns.SRV
		if rr := ipRR(net.ParseIP(addr)); rr != nil {
			rrs = append(rrs, rr)
		}
	}
	return rrs
}

func ipRR(ip net.IP) dns.RR {
	if ip.To4() != nil {
		return &dns.A{A: ip}
	} else if ip.To16() != nil {
		return &dns.AAAA{AAAA: ip}
	} else {
		return nil
	}
}

type nsResponseSet queryResult

var _ nsSet = nsResponseSet{}

func (set nsResponseSet) Err() error { return set.Error }
func (set nsResponseSet) Addrs() []dns.RR {
	var rrs []dns.RR

	for _, rr := range append(set.Response.Answer, set.Response.Ns...) {
		switch rr := rr.(type) {
		case *dns.A:
			rrs = append(rrs, rr)
		case *dns.AAAA:
			rrs = append(rrs, rr)
		case *dns.CNAME:
			rrs = append(rrs, set.tryMapIPs(rr, rr.Target)...)
		case *dns.NS:
			value := rr.Ns
			if net.ParseIP(value) != nil {
				rrs = append(rrs, rr)
				continue
			}

			rrs = append(rrs, set.tryMapIPs(rr, rr.Ns)...)
		}

	}

	return rrs // TODO: de-dup
}

// tryMapIPs maps domain names to IP addresses using the ADDITIONAL section of
// the NS response. If no mapping exists, name is returned as-is.
func (set nsResponseSet) tryMapIPs(rr dns.RR, value string) []dns.RR {
	var rrs []dns.RR
	for _, rr := range set.Response.Extra {
		if rr.Header().Name != value {
			continue
		}

		switch rr := rr.(type) {
		case *dns.A:
			rrs = append(rrs, rr)
		case *dns.AAAA:
			rrs = append(rrs, rr)
		}
	}

	if len(rrs) == 0 {
		return []dns.RR{rr}
	}

	return rrs
}
