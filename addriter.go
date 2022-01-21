package dnsresolver

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/miekg/dns"
)

type addressIterator struct {
	resolver *Resolver
	records  []dns.RR
	trace    *Trace
	inner    *queryIterator
}

func newAddrIter(r *Resolver, nsSet nsSet, trace *Trace) *addressIterator {
	return &addressIterator{
		resolver: r,
		records:  nsSet.Addrs(),
		trace:    trace,
	}
}

func (it *addressIterator) Next(ctx context.Context) (dns.RR, string, error) {
	if it.inner != nil {
		rr, addr, err := it.inner.Next(ctx)
		if err == io.EOF {
			it.inner = nil
		} else {
			return rr, addr, err
		}
	}

	if len(it.records) == 0 {
		return nil, "", io.EOF
	}

	rr := it.records[0]
	it.records = it.records[1:]

	addr, err := it.addrFromRR(ctx, rr, it.trace)
	if it.inner != nil {
		return it.inner.Next(ctx)
	} else {
		return rr, addr, err
	}
}

func (it *addressIterator) addrFromRR(ctx context.Context, rr dns.RR, trace *Trace) (string, error) {
	var target string

	switch rr := rr.(type) {
	case *dns.A:
		return net.JoinHostPort(rr.A.String(), it.resolver.defaultPort), nil
	case *dns.AAAA:
		return net.JoinHostPort(rr.AAAA.String(), it.resolver.defaultPort), nil
	case *dns.SRV:
		// From explicitly configured OS servers. We use them to discover
		// the root name servers, so while DNS allows rr.Target to be a
		// domain name, we have to require IP addresses here.
		if net.ParseIP(rr.Target) == nil {
			// This should have been validated by SetSystemServers, so we can
			// panic.
			panic("not an ip address: " + rr.Target)
		}
		return net.JoinHostPort(rr.Target, strconv.Itoa(int(rr.Port))), nil
	case *dns.CNAME:
		// From a prior A or AAAA response, following NS resolution.
		target = rr.Target
	case *dns.NS:
		// From a prior delegation response without suitable ADDITIONAL section
		// in the response. Example:
		//
		//     ; <<>> DiG 9.16.24-RH <<>> cmcdn.de @a.nic.de. +norecurse
		//     ;; global options: +cmd
		//     ;; Got answer:
		//     ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1000
		//     ;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 2, ADDITIONAL: 1
		//
		//     ;; OPT PSEUDOSECTION:
		//     ; EDNS: version: 0, flags:; udp: 1452
		//     ; COOKIE: 2a60da5d645aaa7b1e727b7261eb1cb11999d328033c5fee (good)
		//     ;; QUESTION SECTION:
		//     ;cmcdn.de.                      IN      A
		//
		//     ;; AUTHORITY SECTION:
		//     cmcdn.de.               86400   IN      NS      jay.ns.cloudflare.com.
		//     cmcdn.de.               86400   IN      NS      kara.ns.cloudflare.com.
		//
		//     ;; Query time: 137 msec
		//     ;; SERVER: 194.0.0.53#53(194.0.0.53)
		//     ;; WHEN: Fri Jan 21 21:50:57 CET 2022
		//     ;; MSG SIZE  rcvd: 119
		//
		target = rr.Ns
	default:
		panic(fmt.Sprintf("unexpected record type: %T", rr))
	}

	var qs []dns.Question
	if !it.resolver.ip6disabled {
		qs = append(qs, dns.Question{
			Name:   target,
			Qtype:  dns.TypeAAAA,
			Qclass: dns.ClassINET,
		})
	}
	if !it.resolver.ip4disabled {
		qs = append(qs, dns.Question{
			Name:   target,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		})
	}

	it.inner = &queryIterator{
		resolver:  it.resolver,
		trace:     it.trace,
		traceRoot: rr,
		queries:   qs,
	}

	return "", nil
}

type queryIterator struct {
	resolver  *Resolver
	trace     *Trace
	traceRoot dns.RR
	queries   []dns.Question

	inner *addressIterator
}

func (it *queryIterator) Next(ctx context.Context) (dns.RR, string, error) {
	if it.inner != nil {
		rr, addr, err := it.inner.Next(ctx)
		if err == io.EOF {
			it.inner = nil
		} else {
			return rr, addr, err
		}
	}

	if len(it.queries) == 0 {
		return nil, "", io.EOF
	}

	q := it.queries[0]
	it.queries = it.queries[1:]

	it.trace.pushRoot(it.traceRoot)
	result := it.resolver.queryIteratively(ctx, q, it.trace)
	it.trace.popRoot()

	it.inner = newAddrIter(it.resolver, nsResponseSet(result), it.trace)

	return it.Next(ctx)
}
