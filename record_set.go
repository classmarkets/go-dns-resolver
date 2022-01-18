package dnsresolver

import "time"

// RecordSet represents the response to a DNS query.
type RecordSet struct {
	// QueryType is the type of query that has been sent, such as "A", "AAAA",
	// "SRV", etc.
	//
	// QueryType is set even in case of network errors.
	QueryType string

	// Name is the fully qualified domain name of this record set. The trailing
	// dot is omitted.
	//
	// Name is set even in case of network errors.
	Name string

	// ResponseType is the type of the DNS response returned by the name
	// server, such as "A", "AAAA", "SRV", etc.
	//
	// If the response indicates an error, ResponseType is set to a string
	// representation of that error, such as "NXDOMAIN", "SERVFAIL", etc.
	ResponseType string

	// TTL is the time-to-live of this DNS response, as returned by the name
	// server. If the name server is a caching name server, this is not
	// necessarily the same as the maximum TTL that the authoritative name
	// server would advice.
	TTL time.Duration

	// Values contains the values of each record in the DNS response, in the
	// order sent by the server. The values may be quoted, for instance in SPF
	// record sets.
	Values []string

	// NameServerAddress contains the IP address and port of the name server
	// that has returned this record set.
	//
	// NameServerAddress is set even in case of network errors.
	NameServerAddress string

	// Age is the amount of time that has passed since the response was cached
	// by a Resolver. Age is zero if the RecordSet has not been added to the
	// cache.
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

	// Trace reports which name servers have answered queries.
	// TODO: make docs specific
	Trace []RecordSet

	// TODO: Authoritative bool?
	// TODO: FromCache bool?
}
