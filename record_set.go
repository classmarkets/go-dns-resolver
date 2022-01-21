package dnsresolver

import (
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
	Trace *Trace
}

func (rs *RecordSet) fromResult(result queryResult) error {
	rs.RTT = result.RTT
	rs.NameServerAddress = result.ServerAddr

	err := result.Error
	if err != nil {
		return LookupError{
			RecordType: rs.Type,
			DomainName: rs.Name,
			Cause:      err,
		}
	}

	resp := result.Response
	if resp.Rcode != dns.RcodeSuccess {
		return ErrorReponse{
			RecordType: rs.Type,
			DomainName: rs.Name,
			Code:       resp.Rcode,
		}
	}

	type valueSet struct {
		values []string
		ttl    time.Duration
	}

	idx := indexResponse(resp)

	q := result.Question

	set, err := idx.search(q.Name, q.Qtype, nil, nil)
	if err != nil {
		return err
	}

	rs.Values = set.values
	rs.TTL = set.ttl

	return nil
}

type valueSet struct {
	values []string
	ttl    time.Duration
}

type recordIndex map[string]map[uint16]*valueSet

func indexResponse(resp *dns.Msg) recordIndex {
	idx := map[string]map[uint16]*valueSet{}

	for _, rr := range append(resp.Answer, resp.Extra...) {
		hdr := rr.Header()
		if idx[hdr.Name] == nil {
			idx[hdr.Name] = map[uint16]*valueSet{}
		}
		ttl := time.Duration(hdr.Ttl) * time.Second
		s := idx[hdr.Name][hdr.Rrtype]
		if s == nil {
			s = &valueSet{
				ttl: ttl,
			}
			idx[hdr.Name][hdr.Rrtype] = s
		} else if ttl < s.ttl {
			s.ttl = ttl
		}

		s.values = append(s.values, rrValue(rr))
	}

	return idx
}

func rrValue(rr dns.RR) string {
	return strings.TrimPrefix(rr.String(), rr.Header().String())
}

func (idx recordIndex) search(name string, typ uint16, ttl *time.Duration, seen map[string]bool) (*valueSet, error) {
	if seen == nil {
		seen = map[string]bool{}
	} else if seen[name] {
		return nil, ErrCircular
	} else {
		seen[name] = true
	}

	if set := idx[name][typ]; set != nil {
		ttl = idx.minTTL(ttl, set)

		return &valueSet{
			values: set.values,
			ttl:    *ttl,
		}, nil
	}

	if typ == dns.TypeCNAME {
		return nil, ErrNXDomain
	}

	cname := idx[name][dns.TypeCNAME]
	if cname == nil {
		return nil, ErrNXDomain
	}

	ttl = idx.minTTL(ttl, cname)

	return idx.search(cname.values[0], typ, ttl, seen)
}

func (idx recordIndex) minTTL(ttl *time.Duration, set *valueSet) *time.Duration {
	if ttl == nil {
		ttl = new(time.Duration)
		*ttl = set.ttl
	} else if set.ttl < *ttl {
		*ttl = set.ttl
	}

	return ttl
}
