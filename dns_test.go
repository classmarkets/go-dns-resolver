package dnsresolver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func RR(t *testing.T, typ uint16, name string, ttl uint32) dns.RR {
	ctor, ok := dns.TypeToRR[typ]
	if !ok {
		t.Fatalf("invalid record type: %d", typ)
	}

	rr := ctor()
	hdr := rr.Header()
	hdr.Name = name
	hdr.Rrtype = typ
	hdr.Ttl = ttl

	return rr
}

func A(t *testing.T, name string, ttl uint32, ipStr string) *dns.A {
	ip := net.ParseIP(ipStr)
	if ip.To4() == nil {
		t.Fatal("invalid ipv4: " + ipStr)
	}

	rr := RR(t, dns.TypeA, name, ttl).(*dns.A)
	rr.A = ip

	return rr
}

func AAAA(t *testing.T, name string, ttl uint32, ipStr string) *dns.AAAA {
	ip := net.ParseIP(ipStr)
	if ip.To16() == nil {
		t.Fatal("invalid ipv6: " + ipStr)
	}

	rr := RR(t, dns.TypeAAAA, name, ttl).(*dns.AAAA)
	rr.AAAA = ip

	return rr
}

func NS(t *testing.T, name string, ttl uint32, target string) *dns.NS {
	rr := RR(t, dns.TypeNS, name, ttl).(*dns.NS)
	rr.Ns = target

	return rr
}
func CNAME(t *testing.T, name string, ttl uint32, target string) *dns.CNAME {
	rr := RR(t, dns.TypeCNAME, name, ttl).(*dns.CNAME)
	rr.Target = target

	return rr
}
