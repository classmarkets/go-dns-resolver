package dnsresolver

import (
	"time"

	"github.com/miekg/dns"
)

// RecordSet represents the response to a DNS query.
type RecordSet struct {
	// Raw is the miekg/dns message that has been received from the server and
	// was used to construct this RecordSet. If no response has been received --
	// due to a network error, for instance -- Raw contains only the
	// QUESTION section.
	Raw dns.Msg

	// Name is the fully qualified domain name of this record set. The trailing
	// dot is omitted.
	//
	// Name is set even in case of network errors, in which case it is the
	// domainName argument to Resolver.Query.
	Name string

	// Type is the type of the DNS response returned by the name
	// server, such as "A", "AAAA", "SRV", etc.
	//
	// Type is set even in case of network errors, in which case it is the
	// recordType argument to Resolver.Query.
	//
	// If the response indicates an error, Type is set to a string
	// representation of that error, such as "NXDOMAIN", "SERVFAIL", etc.
	Type string

	// TTL is the smallest time-to-live of the records in this set, as returned
	// by the name server.
	TTL time.Duration

	// Values contains the values of each record in the DNS response, in the
	// order sent by the server. The values may be quoted, for instance in SPF
	// record sets.
	Values []string

	// ServerAddr contains the IP address and port of the name server that has
	// returned this record set.
	//
	// ServerAddr is set even in case of network errors.
	ServerAddr string

	// Age is the amount of time that has passed since the response was cached
	// by a Resolver.
	//
	// Age is
	// - negative if the RecordSet has not been added to the cache,
	// - zero if the query for this RecordSet caused it to be added to the
	//   cache,
	// - positive if it was present in the cache before the query for this
	//   RecordSet has started.
	Age time.Duration

	// RTT is the measured round-trip time for this record set, i.e. the
	// duration between sending the DNS query to the server and receiving the
	// response. This duration includes encoding the request packet(s) and
	// parsing the response packet(s). It does not include the time spent on
	// any other recursive queries, such as NS lookups.
	//
	// RTT is set even in case of network errors (but then excludes parsing the
	// response, obviously).
	RTT time.Duration

	// Trace reports all DNS queries that where necessary to retrieve this
	// RecordSet.
	Trace *Trace
}

func (rs *RecordSet) fromResponse(resp *dns.Msg, addr string, rtt, age time.Duration, ignoreName bool) {
	if resp != nil {
		rs.Raw = *resp
	}

	rs.ServerAddr = addr
	rs.RTT = rtt
	rs.Age = age

	first := true
	for _, rr := range normalize(resp) {
		hdr := rr.Header()
		if !ignoreName && hdr.Name != rs.Raw.Question[0].Name {
			continue
		}

		ttl := time.Duration(hdr.Ttl) * time.Second
		if first || ttl < rs.TTL {
			rs.TTL = ttl
		}
		first = false

		rs.Values = append(rs.Values, rrValue(rr))
	}
}
