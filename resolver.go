package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/classmarkets/go-dsn-resolver/cache"
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

	logFunc func(RecordSet, error)

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
	cache       *cache.Cache

	once              sync.Once
	systemServerAddrs []string
	rootServerAddrs   []string

	seen map[string]map[dns.Question]struct{} // used to detect cycles
}

// New returns a new Resolver that resolves all queries recursively starting at
// the root name servers, and uses the DefaultTimeoutPolicy and
// DefaultCachePolicy.
func New() *Resolver {
	return &Resolver{
		defaultPort: "53",
		zoneServers: map[string][]string{},
		cache:       cache.New(10_000),
		seen:        map[string]map[dns.Question]struct{}{},
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
	r.cache.Clear()
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
		Raw: dns.Msg{
			Question: []dns.Question{
				{
					Name:   dns.CanonicalName(domainName),
					Qtype:  dns.StringToType[recordType],
					Qclass: dns.ClassINET,
				},
			},
		},
		Name:  domainName,
		Type:  recordType,
		Age:   -1 * time.Second,
		Trace: &Trace{},
	}

	if _, ok := dns.StringToType[recordType]; !ok {
		return rs, fmt.Errorf("unsupported record type: %s", recordType)
	}

	var stack stack

	r.mu.Lock()
	if r.TimeoutPolicy == nil {
		r.TimeoutPolicy = DefaultTimeoutPolicy()
	}
	if r.CachePolicy == nil {
		r.CachePolicy = DefaultCachePolicy()
	}
	r.mu.Unlock()

	rootAddrs, err := r.discoverRootServers(ctx, rs.Trace)
	if err != nil {
		return rs, err
	}
	if len(rootAddrs) == 0 {
		return rs, errors.New("no IP addresses in root name server query")
	}

	stack.push(&stackFrame{
		q:     rs.Raw.Question[0],
		addrs: rootAddrs,
	})

	var resp *dns.Msg

	for stack.size() > 0 {
		frame := stack.top()

		if len(frame.addrs) == 0 {
			return rs, errors.New("servers exhausted")
		}
		addr := frame.addrs[0]
		frame.addrs = frame.addrs[1:]

	retry:
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
			addr = net.JoinHostPort(addr, r.defaultPort)
		}

		ip := net.ParseIP(host)
		if ip == nil {
			err = fmt.Errorf("not an ip address: %s", host)
			continue
		}

		var rtt, age time.Duration
		resp, rtt, age, err = r.doQuery(ctx, frame.q, addr, rs.Trace)
		if isTerminal(resp, err) {
			return rs, fmt.Errorf("%s %s: %w", rs.Type, rs.Name, err)
		} else if err != nil {
			continue
		}

		if stack.size() > 1 && empty(resp) {
			// We're trying to figure out the addresses for a name server but
			// we didn't get any records back. If we tried to find IPv6
			// addresses and IPv4 is also supported, don't give up yet. Try
			// again, this time with A records.
			if frame.q.Qtype == dns.TypeAAAA && !r.ip4disabled {
				frame.q.Qtype = dns.TypeA
				goto retry
			}
		}

		if resp.Rcode != dns.RcodeSuccess {
			continue
		}

		if isAuthoritative(resp) {
			stack.pop()
			rs.Trace.pop()

			if stack.size() == 0 {
				rs.fromResponse(resp, addr, rtt, age, false)

				return rs, nil
			}
			frame = stack.top()
		}

		addrs, names := r.referrals(resp)

		if len(addrs) > 0 {
			frame.addrs = addrs
		} else if len(names) > 0 {
			rs.Trace.push()
			qtype := dns.TypeAAAA
			if r.ip6disabled {
				qtype = dns.TypeA
			}
			stack.push(&stackFrame{
				q: dns.Question{
					// TODO: should we search for the other names too?
					Name:   names[0],
					Qtype:  qtype,
					Qclass: dns.ClassINET,
				},
				addrs: rootAddrs,
			})
		} else {
			return rs, errors.New("empty response")
		}
	}

	return rs, errors.New("name servers exhausted")
}

type stackFrame struct {
	q     dns.Question
	addrs []string
}

type stack []*stackFrame

func (s *stack) size() int          { return len(*s) }
func (s *stack) top() *stackFrame   { return (*s)[len(*s)-1] }
func (s *stack) pop()               { *s = (*s)[:len(*s)-1] }
func (s *stack) push(f *stackFrame) { *s = append(*s, f) }

func (r *Resolver) discoverRootServers(ctx context.Context, trace *Trace) ([]string, error) {
	addrs, err := r.discoverSystemServers()
	if err != nil {
		return nil, err
	}

	q := dns.Question{
		Name:   ".",
		Qtype:  dns.TypeNS,
		Qclass: dns.ClassINET,
	}

	var resp *dns.Msg
	for _, addr := range addrs {
		resp, _, _, err = r.doQuery(ctx, q, addr, trace)
		if err != nil {
			continue
		}

		addrs, _ := r.referrals(resp)
		if len(addrs) == 0 {
			err = errors.New("no IP addresses in root name server query")
			continue
		}

		return addrs, nil
	}

	return nil, fmt.Errorf("discover root servers: %w", err)
}

func isTerminal(resp *dns.Msg, err error) bool {
	return errors.Is(err, ErrCircular)
}

func (r *Resolver) referrals(m *dns.Msg) (ips, names []string) {
	for _, rr := range normalize(m) {
		switch rr := rr.(type) {
		case *dns.A:
			if !r.ip4disabled {
				ips = append(ips, rr.A.String())
			}
		case *dns.AAAA:
			if !r.ip6disabled {
				ips = append(ips, rr.AAAA.String())
			}
		case *dns.NS:
			names = append(names, rr.Ns)
		case *dns.CNAME:
			names = append(names, rr.Target)
		}
	}

	return ips, names
}

// doQuery sends a single DNS query. doQuery uses the cache and timeout
// policies as required, i. e. the response may be served from the cache
// instead of sending a query to the server at addr.
//
// addr must be an ip:port pair.
func (r *Resolver) doQuery(ctx context.Context, q dns.Question, addr string, trace *Trace) (resp *dns.Msg, rtt, age time.Duration, err error) {
	m := new(dns.Msg)
	m.Question = []dns.Question{q}
	m.RecursionDesired = q.Qtype == dns.TypeNS && q.Name == "."

	tn := &TraceNode{
		Server:  addr,
		Message: m,
	}

	if trace.contains(q, addr) {
		tn.Error = fmt.Errorf("%w: repeated query: %s %s @%s",
			ErrCircular, dns.TypeToString[q.Qtype], q.Name, addr)
		trace.add(tn)
		return nil, 0, -1 * time.Second, tn.Error
	}

	// addr must be an ip:port pair. We need an IP address here to
	// prevent net.Dial from using the OS resolver implicitly.
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		tn.Error = fmt.Errorf("not an ip:port pair: %s", host)
		trace.add(tn)
		return nil, 0, -1 * time.Second, tn.Error
	}

	ip := net.ParseIP(host)
	if ip == nil {
		tn.Error = fmt.Errorf("not an ip:port pair: %s", host)
		trace.add(tn)
		return nil, 0, -1 * time.Second, tn.Error
	}

	if ip.To4() != nil {
		if r.ip4disabled {
			tn.Error = fmt.Errorf("IPv4 disabled")
			trace.add(tn)
			return nil, 0, -1 * time.Second, tn.Error
		}
	} else if r.ip6disabled {
		tn.Error = fmt.Errorf("IPv6 disabled")
		trace.add(tn)
		return nil, 0, -1 * time.Second, tn.Error
	}

	resp, rtt, age = r.cache.Lookup(q, addr)
	tn.Age = age

	if resp == nil {
		age = -1 * time.Second
		tn.Age = -1 * time.Second

		r.mu.RLock()
		top := r.TimeoutPolicy
		r.mu.RUnlock()

		to := top(dns.TypeToString[q.Qtype], trimTrailingDot(q.Name), addr)
		cancel := func() {}
		if to > 0 {
			ctx, cancel = context.WithTimeout(ctx, to)
		}

		resp, rtt, err = new(dns.Client).ExchangeContext(ctx, m, addr)
		cancel()
	}
	if resp != nil {
		tn.Message = resp
	}
	tn.RTT = rtt
	tn.Error = err

	if resp != nil && age < 0 {
		// Apply cache policy and update cache as required.

		rs := RecordSet{
			Name: trimTrailingDot(q.Name),
			Type: dns.TypeToString[q.Qtype],
		}
		rs.fromResponse(resp.Copy(), addr, rtt, age, true)

		r.mu.RLock()
		cp := r.CachePolicy
		r.mu.RUnlock()

		ttl := cp(rs)
		if ttl > 0 {
			age = 0
			tn.Age = 0
			r.cache.Update(q, addr, resp, ttl)
		}
	}

	trace.add(tn)

	if r.logFunc != nil {
		msg := resp
		if resp == nil {
			msg = m
		}
		r.logFunc(RecordSet{
			Raw:        *msg,
			ServerAddr: addr,
			RTT:        rtt,
			Age:        age,
		}, err)
	}

	return resp, rtt, age, err
}
