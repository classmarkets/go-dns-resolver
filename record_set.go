package dnsresolver

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// RecordSet represents the response to a DNS query.
type RecordSet struct {
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

	additional [][3]string // name, type, value; wire-format

	// NameServerAddress contains the IP address and port of the name server
	// that has returned this record set.
	//
	// NameServerAddress is set even in case of network errors.
	NameServerAddress string

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
	Trace     *Trace
	traceNode *TraceNode

	// TODO: Authoritative bool?
	// TODO: FromCache bool?
}

func (rs *RecordSet) findAdditionalIPRecords(name string) []string {
	var ips []string

	for _, r := range rs.additional {
		if dns.CanonicalName(r[1]) != "A" && r[1] != "AAAA" {
			continue
		}
		if dns.CanonicalName(r[0]) != dns.CanonicalName(name) {
			continue
		}
		if net.ParseIP(r[2]) == nil {
			continue
		}

		ips = append(ips, r[1])
	}

	return ips
}

func newRecordSet(typ, name string, trace *Trace) *RecordSet {
	if name != "." {
		name = strings.TrimSuffix(name, ".")
	}
	return &RecordSet{
		Name:  name,
		Type:  typ,
		Age:   -1 * time.Second,
		Trace: trace,
	}
}
