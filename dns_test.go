package dnsresolver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func RR(t *testing.T, typ uint16, name string, ttl uint32) dns.RR {
	ctor, ok := dns.TypeToRR[typ]
	if !ok {
		t.Fatalf("invalid record type: %d", typ)
	}

	rr := ctor()
	hdr := rr.Header()
	hdr.Name = name
	hdr.Class = dns.ClassINET
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

func PTR(t *testing.T, name string, ttl uint32, ptr string) *dns.PTR {
	rr := RR(t, dns.TypePTR, name, ttl).(*dns.PTR)
	rr.Ptr = ptr

	return rr
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		answer     []dns.RR
		authority  []dns.RR
		additional []dns.RR

		want []dns.RR
	}{
		{
			answer: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				A(t, "ns1.example.com.", 300, "192.0.2.2"),
			},
			authority: []dns.RR{
				A(t, "ns2.example.com.", 300, "192.0.2.3"),
			},
			additional: []dns.RR{
				A(t, "ns3.example.com.", 300, "192.0.2.4"),
			},
			want: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				A(t, "ns1.example.com.", 300, "192.0.2.2"),
				A(t, "ns2.example.com.", 300, "192.0.2.3"),
			},
		},
		{
			answer: []dns.RR{
				CNAME(t, "ns1.", 300, "ns1.example.com."),
			},
			additional: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
			},
			want: []dns.RR{
				A(t, "ns1.", 300, "192.0.2.1"),
			},
		},
		{
			answer: []dns.RR{
				CNAME(t, "ns1.", 300, "ns1.example.com."),
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
			},
			want: []dns.RR{
				A(t, "ns1.", 300, "192.0.2.1"),
			},
		},
		{
			answer: []dns.RR{
				CNAME(t, "ns1.", 300, "ns1.example.com."),
				CNAME(t, "ns1.example.com.", 300, "ns2.example.com."),
			},
			additional: []dns.RR{
				A(t, "ns2.example.com.", 300, "192.0.2.1"),
			},
			want: []dns.RR{
				A(t, "ns1.", 300, "192.0.2.1"),
			},
		},
		{
			answer: []dns.RR{
				CNAME(t, "ns1.", 300, "ns1.example.com."),
				CNAME(t, "ns1.example.com.", 300, "ns2.example.com."),
				A(t, "ns2.example.com.", 300, "192.0.2.1"),
			},
			want: []dns.RR{
				A(t, "ns1.", 300, "192.0.2.1"),
			},
		},
		{
			answer: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
				A(t, "ns1.", 300, "192.0.2.3"),
			},
			additional: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				A(t, "ns1.example.com.", 300, "192.0.2.2"),
			},
			want: []dns.RR{
				A(t, "ns1.", 300, "192.0.2.1"),
				A(t, "ns1.", 300, "192.0.2.2"),
				A(t, "ns1.", 300, "192.0.2.3"),
			},
		},
		{
			answer: []dns.RR{
				NS(t, "ns1.", 300, "ns.example.com."),
				NS(t, "ns2.", 111, "ns.example.com."),
			},
			additional: []dns.RR{
				A(t, "ns.example.com.", 300, "192.0.2.1"),
			},
			want: []dns.RR{
				A(t, "ns1.", 300, "192.0.2.1"),
				A(t, "ns2.", 111, "192.0.2.1"),
			},
		},
		{
			answer: []dns.RR{
				A(t, "foo.", 300, "192.0.2.1"),
			},
			authority: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
			},
			additional: []dns.RR{
				CNAME(t, "ns1.example.com.", 300, "ns2.example.com."),
				CNAME(t, "ns2.example.com.", 300, "ns1.example.com."),
			},
			want: []dns.RR{
				A(t, "foo.", 300, "192.0.2.1"),
			},
		},
		{
			answer: []dns.RR{
				CNAME(t, "ns1.", 300, "ns2."),
				CNAME(t, "ns2.", 111, "ns3."),
				CNAME(t, "ns3.", 222, "ns4."),
			},
			want: []dns.RR{
				CNAME(t, "ns1.", 111, "ns4."),
			},
		},
		{
			answer: []dns.RR{
				NS(t, "ns1.", 300, "ns.example.com."),
				NS(t, "ns2.", 111, "ns.example.com."),
			},
			additional: []dns.RR{
				A(t, "ns.example.com.", 300, "192.0.2.1"),
				A(t, "unrelated.", 300, "192.0.2.1"),
			},
			want: []dns.RR{
				A(t, "ns1.", 300, "192.0.2.1"),
				A(t, "ns2.", 111, "192.0.2.1"),
			},
		},
		{
			answer: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
				NS(t, "ns2.", 300, "ns2.example.com."),
			},
			want: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
				NS(t, "ns2.", 300, "ns2.example.com."),
			},
		},
		{
			authority: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
				NS(t, "ns2.", 300, "ns2.example.com."),
			},
			want: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
				NS(t, "ns2.", 300, "ns2.example.com."),
			},
		},
	}

	t.Parallel()
	for _, tc := range cases {
		tc := tc
		t.Run("", func(t *testing.T) {

			given := &dns.Msg{
				Answer: tc.answer,
				Ns:     tc.authority,
				Extra:  tc.additional,
			}

			before := given.String()

			got := &dns.Msg{
				Answer: normalize(given),
			}

			after := given.String()
			require.Equal(t, before, after, "input has been modified")

			want := &dns.Msg{
				Answer: tc.want,
			}

			t.Logf("given:\n%s\n\n", given.String())
			t.Logf("want:\n%s\n\n", want.String())
			t.Logf("got:\n%s\n\n", got.String())

			assert.Equal(t, want.String(), got.String())
		})
	}
}

func TestIsPublicSuffix(t *testing.T) {
	cases := []struct {
		fqdn string
		want bool
	}{
		{".", true},
		{"com.", true},
		{"foo.com.", false},
		{"uk.", true},
		{"co.uk.", true},
		{"foo.co.uk.", false},
		{"aero.", true},
		{"airline.aero.", true},
		{"foo.airline.aero.", false},
		{"in-addr.arpa.", true},
		{"ip6.arpa.", true},
	}

	for _, tc := range cases {
		t.Run(tc.fqdn, func(t *testing.T) {
			assert.Equal(t, tc.want, isPublicSuffix(tc.fqdn), tc.fqdn)
		})
	}
}
