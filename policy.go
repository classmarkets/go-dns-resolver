package dnsresolver

import (
	"net"
	"time"

	"golang.org/x/net/publicsuffix"
)

// TimeoutPolicy determines the round-trip timout for a single DNS query.
//
// recordType is the type of the record set to be queried, such as "A", "AAAA",
// "SRV", etc. nameServerAddress is the IP address and port of the server to
// query.
//
// Any non-positive duration is understood as an infinite timeout.
type TimeoutPolicy func(recordType string, nameServerAddress string) (timeout time.Duration)

// DefaultTimeoutPolicy returns the default TimeoutPolicy. It is used by
// Resolver.Query if Resolver.TimeoutPolicy is nil.
//
// DefaultTimeoutPolicy assumes low latency to addresses in PrivateNets
// (10.0.0.0/8, 192.168.0.0/16, fd00::/8, etc.) and causes requests to such
// addresses to timeout after 100 milliseconds and all other requests after 1
// second.
func DefaultTimeoutPolicy() TimeoutPolicy {
	return defaultTimeoutPolicy
}
func defaultTimeoutPolicy(recordType string, nameServerAddress string) time.Duration {
	ipStr, _, err := net.SplitHostPort(nameServerAddress)
	if err != nil {
		panic(err)
	}
	ip := net.ParseIP(ipStr)

	for _, n := range PrivateNets {
		if n.Contains(ip) {
			return 100 * time.Millisecond
		}
	}
	return 1 * time.Second
}

// PrivateNets is used by DefaultTimeoutPolicy to return a low timeout for
// destination addresses in one of these subnets.
var PrivateNets = []*net.IPNet{
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("127.0.0.0/8"),
	mustParseCIDR("169.254.0.0/16"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.0.0.0/24"),
	mustParseCIDR("192.0.2.0/24"),
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("198.18.0.0/15"),
	mustParseCIDR("198.51.100.0/24"),
	mustParseCIDR("203.0.113.0/24"),
	mustParseCIDR("233.252.0.0/24"),
	mustParseCIDR("::1/128"),
	mustParseCIDR("2001:db8::/32"),
	mustParseCIDR("fd00::/8"),
	mustParseCIDR("fe80::/10"),
}

func mustParseCIDR(cidr string) *net.IPNet {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}

	return n
}

// CachePolicy determines how long a Resolver's cached DNS responses remain
// fresh.
type CachePolicy func(RecordSet) (ttl time.Duration)

// DefaultCachePolicy returns the default CachePolicy. It is used by
// Resolver.Query if Resolver.CachePolicy is nil.
//
// DefaultCachePolicy obeys the server-returned TTL for NS responses for public
// suffixes that are managed by ICANN (such as ".com", ".org", ".co.uk"; see
// https://publicsuffix.org/) and caches nothing else.
func DefaultCachePolicy() CachePolicy {
	return defaultCachePolicy
}
func defaultCachePolicy(rs RecordSet) time.Duration {
	if rs.ResponseType != "NS" {
		return 0
	}

	publicSuffix, icann := publicsuffix.PublicSuffix(rs.Name)
	if icann && publicSuffix == rs.Name {
		return rs.TTL
	}

	return 0
}

// ObeyResponderAdvice returns a CachePolicy that obeys the TTL advice that is
// returned by name servers, except for NXDOMAIN responses, which are cached
// for the duration of negativeTTL.
//
// A resolver with an ObeyResponderAdvice policy behaves pretty much like an
// off-the-shelf resolver, such as dnsmasq.
func ObeyResponderAdvice(negativeTTL time.Duration) CachePolicy {
	return func(rs RecordSet) time.Duration {
		if rs.ResponseType == "NXDOMAIN" {
			return negativeTTL
		}
		return rs.TTL
	}
}
