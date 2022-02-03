package dnsresolver

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

func empty(m *dns.Msg) bool {
	return m == nil ||
		len(m.Answer)+len(m.Ns)+len(m.Extra) == 0
}

func rrValue(rr dns.RR) string {
	return strings.TrimPrefix(rr.String(), rr.Header().String())
}

func isAuthoritative(m *dns.Msg) bool {
	return m != nil && m.Authoritative
}

func trimTrailingDot(s string) string {
	if s == "." {
		return s
	}
	return strings.TrimSuffix(s, ".")
}

// normalize returns a copy of m's records with CNAME and NS records replaced
// with matching records in m.Extra if possible. CNAME and NS records without a
// match are left as-is. Circular references and duplicate records are removed.
func normalize(m *dns.Msg) []dns.RR {
	all := append(append(m.Answer, m.Ns...), m.Extra...)

	mapped := map[string][]string{}
	for _, rr := range all {
		switch rr := rr.(type) {
		case *dns.CNAME:
			mapped[rr.Target] = append(mapped[rr.Target], rr.Hdr.Name)
		case *dns.NS:
			mapped[rr.Ns] = append(mapped[rr.Ns], rr.Hdr.Name)
		}
	}

	var xs []dns.RR
	copyRecord := func(rr dns.RR, ttl *uint32, newName string) {
		x, err := dns.NewRR(rr.String())
		if err != nil {
			panic(err)
		}
		hdr := x.Header()
		if ttl != nil && *ttl < hdr.Ttl {
			hdr.Ttl = *ttl
		}
		if newName != "" {
			hdr.Name = newName
		}
		xs = append(xs, x)
	}

	var findReplacements func(string, uint32, map[string]bool) ([]dns.RR, uint32, bool)
	findReplacements = func(name string, ttl uint32, seen map[string]bool) ([]dns.RR, uint32, bool) {
		if seen[name] {
			return nil, ttl, true
		}
		seen[name] = true

		var rrs []dns.RR

		for _, rr := range all {
			hdr := rr.Header()
			if hdr.Name != name {
				continue
			}

			if hdr.Ttl < ttl {
				ttl = rr.Header().Ttl
			}
			if cname, ok := rr.(*dns.CNAME); ok {
				xs, newTtl, cycle := findReplacements(cname.Target, ttl, seen)
				if cycle {
					return nil, ttl, true
				}
				ttl = newTtl
				if len(xs) > 0 {
					rrs = append(rrs, xs...)
				} else {
					rrs = append(rrs, rr)
				}
			} else {
				rrs = append(rrs, rr)
			}
		}

		return rrs, ttl, false
	}

	for _, rr := range append(append(m.Answer, m.Ns...)) {
		if _, ok := mapped[rr.Header().Name]; ok {
			continue
		}

		var target string
		var newHeader dns.RR_Header

		switch rr := rr.(type) {
		case *dns.NS:
			target = rr.Ns
			newHeader = rr.Hdr
		case *dns.CNAME:
			target = rr.Target
			newHeader = rr.Hdr
		default:
			copyRecord(rr, nil, "")
			continue
		}

		replacements, newTtl, cycle := findReplacements(target, newHeader.Ttl, map[string]bool{})
		if cycle {
			continue
		}

		if replacements == nil {
			copyRecord(rr, nil, "")
		} else {
			for _, rr := range replacements {
				copyRecord(rr, &newTtl, newHeader.Name)
			}
		}
	}

	dns.Dedup(xs, nil)

	return xs
}

func checkTLDNSSet(msg *dns.Msg) (string, time.Duration, bool) {
	var tld string
	var ttl time.Duration

	for i, rr := range append(msg.Answer, msg.Ns...) {
		hdr := rr.Header()
		if hdr.Rrtype != dns.TypeNS {
			return "", 0, false
		}
		if !isPublicSuffix(hdr.Name) {
			return "", 0, false
		}

		if tld == "" {
			tld = hdr.Name
		} else if hdr.Name != tld {
			return "", 0, false
		}

		rrTTL := time.Duration(hdr.Ttl) * time.Second
		if i == 0 || rrTTL < ttl {
			ttl = rrTTL
		}
	}

	return tld, ttl, true
}

func isPublicSuffix(fqdn string) bool {
	name := strings.TrimSuffix(fqdn, ".")
	s, _ := publicsuffix.PublicSuffix(name)
	return s == name
}

func arpaName(ip net.IP) string {
	if ip := ip.To4(); ip != nil {
		return arpaName4(ip)
	}

	return arpaName6(ip)
}

func arpaName4(ip net.IP) string {
	if len(ip) != 4 {
		panic("arpaName4: not four bytes")
	}

	labels := make([]string, 5)
	for i := 0; i < 4; i++ {
		labels[i] = strconv.FormatUint(uint64(ip[3-i]), 10)
	}
	labels[4] = "in-addr.arpa."

	return strings.Join(labels, ".")
}

func arpaName6(ip net.IP) string {
	if len(ip) != 16 {
		panic("arpaName6: not sixteen bytes: " + strconv.Itoa(len(ip)))
	}

	labels := make([]string, 33)

	for i := 0; i < 16; i++ {
		labels[i*2+0] = strconv.FormatUint(uint64(ip[15-i])&0xF, 16)
		labels[i*2+1] = strconv.FormatUint(uint64(ip[15-i])>>4, 16)
	}

	labels[32] = "ip6.arpa."

	return strings.Join(labels, ".")
}
