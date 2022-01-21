package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Resolver resolves DNS queries recursively.
//
// Concurrent calls to all methods are safe, but exported fields of the
// Resolver must not be changed until all method calls have returned, of
// course.
type Resolver struct {
	// TimeoutPolicy determines the round-trip timout for a single DNS query.
	// If nil, DefaultTimeoutPolicy() is used.
	TimeoutPolicy TimeoutPolicy

	// CachePolicy determines how long DNS responses remain in this resolver's
	// cache. If nil, DefaultCachePolicy() is used.
	//
	// The CachePolicy is consulted even for NXDOMAIN responses.
	//
	// If CachePolicy is changed after the cache has already been populated,
	// cached responses are still returned as appropriate. Use ClearCache to
	// clear the cache if desired.
	//
	// The cache size is limited to 10k entries, and the least recently used
	// records are evicted if necessary.
	CachePolicy CachePolicy

	logFunc func(queryResult)

	// defaultPort is added to things like NS results. This should be "53" for
	// the real world and "5354" in tests.
	defaultPort string

	ip4disabled bool
	ip6disabled bool

	// mu protects zoneServers and cache.
	//
	// zoneServers and cache contain lists of ip:port pairs and cacheItems
	// respectively, keyed by fully qualified domain names, including trailing
	// dots.
	mu          sync.RWMutex
	zoneServers map[string][]string
	cache       map[string]cacheItem

	once              sync.Once
	systemServerAddrs []string
	rootServerAddrs   []string
}

const maxCacheSize = 10_000

type cacheItem struct {
	set        RecordSet
	addedAt    time.Time
	lastUsedAt time.Time // for a poor man's LRU cache
	ttl        time.Duration
}

// New returns a new Resolver that resolves all queries recursively starting at
// the root name servers, and uses the DefaultTimeoutPolicy and
// DefaultCachePolicy.
func New() *Resolver {
	return &Resolver{
		defaultPort: "53",
		zoneServers: map[string][]string{},
		cache:       map[string]cacheItem{},
	}
}

// WithZoneServer causes the resolver to use the specified name servers for the
// given DNS zone (a DNS zone is a suffix of a fully qualified domain name).
//
// For instance,
//
//     r := dnsresolver.New()
//     r.WithZoneServer("example.com", []string{"10.0.0.100"})
//     r.Query(ctx, "A", "foo.example.com")
//
// results in the following DNS queries:
//
//          TYPE  NAME              SERVER
//     1)     NS  foo.example.com.  @10.0.0.100
//     2.a)    A  foo.example.com.  @10.0.0.100               ; if the NS query results in an NXDOMAIN response
//     2.b)    A  foo.example.com.  @{1st NS record from 1)}  ; otherwise
//
// Note the absent NS queries for .com and .example.com.
//
// zone is always understood as a fully qualified domain name, making the
// trailing dot optional.
//
// Name servers MUST be specified as IPv4 or IPv6 addresses. The port is
// optional and defaults to 53. If serverAddresses is nil or empty, the zone's
// name servers are determined with DNS queries as usual.
//
// WithZoneServer may be called multiple times to add servers for distinct
// zones, but repeated calls with the same zone will overwrite any prior calls.
func (r *Resolver) WithZoneServer(zone string, serverAddresses []string) error {
	if len(serverAddresses) == 0 {
		r.mu.Lock()
		delete(r.zoneServers, zone)
		r.mu.Unlock()

		return nil
	}

	// TODO: validate and normalize zone

	serverAddresses, err := r.normalizeAddrs(serverAddresses)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.zoneServers[zone] = serverAddresses
	r.mu.Unlock()

	return nil
}

// SetSystemServers specifies the IP addresses and, optionally, ports for the
// resolver(s) of the operating system. These servers are only used to discover
// the root name servers.
//
// This method is intended mostly for testing this package, but is also useful
// if the operating system's resolver can't be trusted to query the root zone
// correctly, or if automatic detection fails.
//
// If SetSystemServers has not been called when Query is first called, Resolver
// will attempt to discover the operating system's resolver(s). This is
// platform specific. For instance, on *nix systems, /etc/resolv.conf is
// parsed.
//
// Calling SetSystemServers after the first call to Query has no effect,
// because these servers are only used once to discover the root servers and
// the list of root servers is cached forever.
func (r *Resolver) SetSystemServers(serverAddresses ...string) error {
	serverAddresses, err := r.normalizeAddrs(serverAddresses)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.systemServerAddrs = serverAddresses
	r.mu.Unlock()

	return nil
}

func (r *Resolver) normalizeAddrs(addrs []string) ([]string, error) {
	seen := map[string]bool{}
	validDistinctAddrs := make([]string, 0, len(addrs))

	for _, addr := range addrs {
		ip, port, err := net.SplitHostPort(addr)
		if err != nil {
			ip = addr
		}

		if net.ParseIP(ip) == nil {
			return nil, errors.New("not an ip address: " + addr)
		}

		if port == "" {
			port = "53"
		}
		addr = net.JoinHostPort(ip, port)

		if seen[addr] {
			continue
		}
		seen[addr] = true
		validDistinctAddrs = append(validDistinctAddrs, addr)
	}

	return validDistinctAddrs, nil
}

// ClearCache removes any cached DNS responses.
func (r *Resolver) ClearCache() {
	r.mu.Lock()
	r.cache = map[string]cacheItem{}
	r.mu.Unlock()
}

// Query starts a recursive query for the given record type and DNS name.
//
// Cancel the context to abort any inflight request. If canceled, the context's
// error is returned but it may be wrapped.
//
// recordType is the type of the record set to query, such as "A", "AAAA",
// "SRV", etc.
//
// domainName is always understood as a fully qualified domain, making the
// trailing dot optional.
//
// Name servers are discovered starting at the global root name servers, unless
// the servers for a relevant zone have been specified with WithZoneServer.
//
// Timeouts are applied according to the TimeoutPolicy. If a timeout occurs,
// context.DeadlineExceeded is returned but it may be wrapped and must be
// tested for with errors.Is.
//
// Query populates the resolver's cache according to the configured
// CachePolicy, however matching existing items in the cache are returned
// independently of the CachePolicy.
//
// If a terminal error occurs, the record set for the last received response is
// returned (which may be empty if the last response was an error response),
// along with an error. If no query succeeds, a RecordSet with Type NXDOMAIN is
// returned, along with an error.
//
// Concurrent calls to Query are safe, but public fields of the Resolver must
// not be changed until all Query calls have returned.
//
// Most name servers are setup redundantly, i.e. NS responses include multiple
// records. Such name servers are tried in the order they appear in in the
// response, until one returns a response (even if the responses indicates an
// error, such as NXDOMAIN) After any response has been received, no other
// servers in the NS set are queried. For instance:
//
//         QUERY            NAME SERVER               RESULT
//     1)  NS com.          @a.root-servers.org.  ->  a.gtld-servers.net.
//                                                    c.gtld-servers.net.
//                                                    b.gtld-servers.net.
//
//     2)  NS example.com.  @a.gtld-servers.net.  ->  network timeout
//
//     3)  NS example.com.  @c.gtld-servers.net.  ->  NXDOMAIN
//
// b.gtld-servers.net is not queried because c.gtld-servers.net. responded
// (albeit with an NXDOMAIN error).
//
// If the name server returns an inconsistent record set,
// - records with a name other than the domainName argument are ignored,
// - records with a type other than the recordType argument are ignored,
// - and RecordSet.TTL will be the smallest value amongst all other records,
//
// For instance, if the DNS response is as follows for whatever reason:
//
//     ;; QUESTION SECTION:
//     ;example.com.                   IN      A
//
//     ;; ANSWER SECTION:
//     example.com.            666     IN      A       192.0.2.0
//     example.com.            555     IN      A       192.0.2.1
//     foo.example.com.        444     IN      A       192.0.2.1
//     example.com.            333     IN      AAAA    2001:db8::
//
// then Name will be "example.com", Type will be "A", TTL will be 555 seconds,
// and values will be []string{"192.0.2.0", "192.0.2.1"}
func (r *Resolver) Query(ctx context.Context, recordType string, domainName string) (RecordSet, error) {
	rs := RecordSet{
		Name:  domainName,
		Type:  recordType,
		Age:   -1 * time.Second,
		Trace: new(Trace),
	}

	if _, ok := dns.StringToType[recordType]; !ok {
		return rs, fmt.Errorf("unsupported record type: %s", recordType)
	}

	nsSet := r.discoverSystemServers()
	q := dns.Question{
		Name:   ".",
		Qtype:  dns.TypeNS,
		Qclass: dns.ClassINET,
	}

	result := r.doQuery(ctx, q, nsSet, rs.Trace)
	if result.Error != nil {
		return rs, fmt.Errorf("discover root name servers: %w", result.Error)
	}
	nsSet = nsResponseSet(result)

	q = dns.Question{
		Name:   dns.CanonicalName(domainName),
		Qtype:  dns.StringToType[recordType],
		Qclass: dns.ClassINET,
	}

	for {
		result := r.doQuery(ctx, q, nsSet, rs.Trace)

		if result.isDelegation() {
			nsSet = nsResponseSet(result)
			continue
		}

		err := rs.fromResult(result)

		return rs, err
	}

	return rs, errors.New("TODO")
}

type queryResult struct {
	Question   *dns.Question
	ServerAddr string
	RTT        time.Duration
	Response   *dns.Msg
	Error      error
}

func (r *Resolver) doQuery(ctx context.Context, q dns.Question, nsSet nsSet, trace *Trace) queryResult {
	result := queryResult{
		Question: &q,
	}

	if err := nsSet.Err(); err != nil {
		result.Error = fmt.Errorf("%s %s: name server unavailable: %w",
			dns.TypeToString[q.Qtype], q.Name, err)
		return result
	}

	addrs := nsSet.Addrs()
	for _, rr := range addrs {
		addr, err := r.serverAddrFromRR(ctx, rr, trace)
		result.ServerAddr = addr
		if err != nil {
			result.Error = err
			trace.add(result, rr)
			continue
		}

		// addr should now be an ip:port pair (otherwise serverAddrFromRR
		// messed up). We need an IP address here to prevent net.Dial from
		// using the OS resolver implicitly.
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			result.Error = fmt.Errorf("not a host:port pair: %s: %w", addr, err)
			trace.add(result, rr)
			continue
		}

		ip := net.ParseIP(host)
		if ip == nil {
			result.Error = fmt.Errorf("not an ip address: %s", host)
			trace.add(result, rr)
			continue
		}

		if ip.To4() != nil {
			if r.ip4disabled {
				result.Error = errors.New("IPv4 disabled")
				trace.add(result, rr)
				continue
			}
		} else if r.ip6disabled {
			result.Error = errors.New("IPv6 disabled")
			trace.add(result, rr)
			continue
		}

		result.ServerAddr = addr

		c := new(dns.Client)

		m := new(dns.Msg)
		m.Question = []dns.Question{q}
		m.RecursionDesired = q.Qtype == dns.TypeNS && q.Name == "."

		result.Response, result.RTT, result.Error = c.ExchangeContext(ctx, m, addr)
		trace.add(result, rr)
		if r.logFunc != nil {
			r.logFunc(result)
		}

		if result.Error != nil {
			continue
		}

		return result
	}

	result.Error = errors.New("no supported name servers available")

	return result
}

func (r *Resolver) serverAddrFromRR(ctx context.Context, rr dns.RR, trace *Trace) (string, error) {
	switch rr := rr.(type) {
	case *dns.A:
		return net.JoinHostPort(rr.A.String(), r.defaultPort), nil
	case *dns.AAAA:
		return net.JoinHostPort(rr.AAAA.String(), r.defaultPort), nil
	case *dns.SRV:
		// From explicitly configured OS servers. We use them to discover
		// the root name servers, so while DNS allows rr.Target to be a
		// domain name, we have to require IP addresses here.
		//
		// This should have been validated by SetSystemServers, so we can panic.
		if net.ParseIP(rr.Target) == nil {
			panic("not an ip address: " + rr.Target)
		}
		return net.JoinHostPort(rr.Target, strconv.Itoa(int(rr.Port))), nil
	case *dns.NS:
		panic("unreachable")
		// From a prior NS query without AUTHORITY or suitable ADDITIONAL
		// section in the response. Example:
		//
		//     ; <<>> DiG 9.16.24-RH <<>> NS cmcdn.de. @a.nic.de. +norecurse
		//     ;; global options: +cmd
		//     ;; Got answer:
		//     ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51502
		//     ;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 2, ADDITIONAL: 1
		//
		//     ;; OPT PSEUDOSECTION:
		//     ; EDNS: version: 0, flags:; udp: 1452
		//     ; COOKIE: 12e4cbd55f475a5d7e2cdf3e61e9684a60a0f37bf9d563d4 (good)
		//     ;; QUESTION SECTION:
		//     ;cmcdn.de.                      IN      NS
		//
		//     ;; AUTHORITY SECTION:
		//     cmcdn.de.               86400   IN      NS      kara.ns.cloudflare.com.
		//     cmcdn.de.               86400   IN      NS      jay.ns.cloudflare.com.
		//
		//     ;; Query time: 53 msec
		//     ;; SERVER: 194.0.0.53#53(194.0.0.53)
		//     ;; WHEN: Thu Jan 20 14:48:58 CET 2022
		//     ;; MSG SIZE  rcvd: 119
		//
		// TODO: start a new query tree to resolve rr.Ns

		/*XXX
		q := dns.Question{
			Name:   rr.Ns,
			Qtype:  dns.TypeNS,
			Qclass: dns.ClassINET,
		}

		// TODO: trace.pushRoot(rr)
		nsSet := r.locateResolverFor(ctx, rr.Ns, trace)
		result := r.doQuery(ctx, q, nsSet, trace)
		// TODO: trace.popRoot()

		rs := RecordSet{}
		err := rs.fromResult(result)
		if err != nil {
			return "", err
		}

		return net.JoinHostPort(rs.Values[0], r.defaultPort), nil
		*/
	default:
		panic(fmt.Sprintf("unexpected record type: %T", rr))
	}
}

func (r *queryResult) isDelegation() bool {
	// We consider the response a delegation if
	//
	// - the response is not authoritative,
	// - the union of the ANSWER and AUTHORITY sections is entirely NS records,
	// - and the ADDITIONAL contains A or AAAA records for at least one of the
	//   NS records

	resp := r.Response

	if resp.Authoritative {
		return false
	}

	if (len(resp.Answer)+len(resp.Ns)) == 0 || len(resp.Extra) == 0 {
		return false
	}

	names := map[string]bool{}
	for _, rr := range append(resp.Answer, resp.Ns...) {
		ns, ok := rr.(*dns.NS)
		if !ok {
			return false
		}
		names[ns.Ns] = true
	}

	for _, rr := range resp.Extra {
		switch rr.(type) {
		case *dns.A:
		case *dns.AAAA:
		default:
			continue
		}

		if names[rr.Header().Name] {
			return true
		}
	}

	return false
}
