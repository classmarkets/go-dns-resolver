package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/classmarkets/go-dns-resolver/cache"
	"github.com/miekg/dns"
)

// Resolver resolves DNS queries recursively.
//
// Concurrent calls to all methods are safe, but exported fields of the
// Resolver must not be changed until all method calls have returned, of
// course.
type Resolver struct {
	// mu protects against races in Query, which initializes fields with their
	// default values if necessary.
	mu sync.RWMutex

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

	systemServerAddrs []string

	cache *cache.Cache
}

// resolver is the same as Resolver, but doesn't need a mutex because it is
// created for each call to Resolver.Query and therefore not used
// concurrently.
type resolver struct {
	TimeoutPolicy TimeoutPolicy
	CachePolicy   CachePolicy
	logFunc       func(RecordSet, error)

	defaultPort string

	ip4disabled bool
	ip6disabled bool

	cache *cache.Cache

	systemServerAddrs []string
	seen              map[string]map[dns.Question]struct{} // used to detect cycles
}

// New returns a new Resolver that resolves all queries recursively starting
// at the root name servers, and uses the DefaultTimeoutPolicy and
// DefaultCachePolicy.
func New() *Resolver {
	return &Resolver{
		TimeoutPolicy: DefaultTimeoutPolicy(),
		CachePolicy:   DefaultCachePolicy(),
		defaultPort:   "53",
		cache:         cache.New(10_000),
	}
}

// SetBootstrapServers specifies the IP addresses and, optionally, ports for
// the name servers that are used to discover the root name servers. By
// default the name servers configured in the operating system are used.
//
// This method is intended mostly for testing this package, but is also useful
// if the operating system's resolver can't be trusted to query the root zone
// correctly, or if automatic detection fails.
//
// If SetBootstrapServers has not been called when Query is first called, Resolver
// will attempt to discover the operating system's resolver(s). This is
// platform specific. For instance, on *nix systems, /etc/resolv.conf is
// parsed.
func (r *Resolver) SetBootstrapServers(serverAddresses ...string) error {
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
			port = r.defaultPort
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
func (R *Resolver) Query(ctx context.Context, recordType string, domainName string) (RecordSet, error) {
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

	R.mu.Lock()

	var err error
	if len(R.systemServerAddrs) == 0 {
		R.systemServerAddrs, err = R.discoverSystemServers()
	}
	if err != nil {
		R.mu.Unlock()
		return rs, fmt.Errorf("cannot determine system resolvers: %w", err)
	}

	if R.TimeoutPolicy == nil {
		R.TimeoutPolicy = DefaultTimeoutPolicy()
	}
	if R.CachePolicy == nil {
		R.CachePolicy = DefaultCachePolicy()
	}

	r := &resolver{
		TimeoutPolicy:     R.TimeoutPolicy,
		CachePolicy:       R.CachePolicy,
		logFunc:           R.logFunc,
		defaultPort:       R.defaultPort,
		ip4disabled:       R.ip4disabled,
		ip6disabled:       R.ip6disabled,
		cache:             R.cache,
		systemServerAddrs: R.systemServerAddrs,
		seen:              map[string]map[dns.Question]struct{}{},
	}

	R.mu.Unlock()

	return r.Query(ctx, recordType, domainName, rs)
}

func (r *resolver) Query(ctx context.Context, recordType string, domainName string, rs RecordSet) (RecordSet, error) {
	var stack stack

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
		}

		if errors.Is(err, syscall.ENETUNREACH) {
			if ip.To4() != nil {
				r.ip4disabled = true
			} else {
				r.ip6disabled = true
			}
		}

		if stack.size() > 1 && empty(resp) {
			// We're trying to figure out the address(es) for a name server
			// but we didn't get any records back. If we tried to find IPv6
			// addresses and IPv4 is also supported, don't give up yet. Try
			// again, this time with A records.
			if frame.q.Qtype == dns.TypeAAAA && !r.ip4disabled {
				frame.q.Qtype = dns.TypeA
				goto retry
			}

			if len(frame.altNames) > 0 {
				frame.q.Name = frame.altNames[0]
				if !r.ip6disabled {
					frame.q.Qtype = dns.TypeAAAA
				}
				frame.altNames = frame.altNames[1:]
				addr = rootAddrs[0]
				frame.addrs = rootAddrs[1:]

				goto retry
			}
		}

		if err != nil {
			continue
		}

		if stack.size() == 0 {
			switch resp.Rcode {
			case dns.RcodeSuccess:
			case dns.RcodeNameError:
				return rs, fmt.Errorf("%s %s: %w", rs.Type, rs.Name, ErrNXDomain)
			case dns.RcodeServerFailure:
				continue
			default:
				return rs, fmt.Errorf("%s %s: %s", rs.Type, rs.Name, dns.RcodeToString[resp.Rcode])
			}
		} else if resp.Rcode != dns.RcodeSuccess {
			continue
		}

		// TODO: cache addresses of TLD servers

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
					Name:   names[0],
					Qtype:  qtype,
					Qclass: dns.ClassINET,
				},
				altNames: names[1:],
				addrs:    rootAddrs,
			})
		} else {
			return rs, errors.New("empty response")
		}
	}

	return rs, errors.New("name servers exhausted")
}

type stackFrame struct {
	q        dns.Question
	altNames []string
	addrs    []string
}

type stack []*stackFrame

func (s *stack) size() int          { return len(*s) }
func (s *stack) top() *stackFrame   { return (*s)[len(*s)-1] }
func (s *stack) pop()               { *s = (*s)[:len(*s)-1] }
func (s *stack) push(f *stackFrame) { *s = append(*s, f) }

func (r *resolver) discoverRootServers(ctx context.Context, trace *Trace) ([]string, error) {
	if len(r.systemServerAddrs) == 0 {
		return nil, errors.New("system resolvers not discovered")
	}

	q := dns.Question{
		Name:   ".",
		Qtype:  dns.TypeNS,
		Qclass: dns.ClassINET,
	}

	var (
		resp *dns.Msg
		err  error
	)
	for _, addr := range r.systemServerAddrs {
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
	switch {
	case errors.Is(err, ErrCircular),
		errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return true
	default:
		return false
	}
}

func (r *resolver) referrals(m *dns.Msg) (ips, names []string) {
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
func (r *resolver) doQuery(ctx context.Context, q dns.Question, addr string, trace *Trace) (resp *dns.Msg, rtt, age time.Duration, err error) {
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

		to := r.TimeoutPolicy(dns.TypeToString[q.Qtype], trimTrailingDot(q.Name), addr)
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

		ttl := r.CachePolicy(rs)
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
