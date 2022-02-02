# Go DNS resolver

This library provides a system-independent[^1], non-caching DNS resolver.

It is useful in cases where up-to-date DNS records are required, and primarily
intended for use in infrastructure automation tasks.

go-dns-resolver is built on top of the excellent [miekg/dns][miekgdns] package,
but provides a much higher-level API. The priority here is usage ergonomics for
the common cases, not completeness or performance.

Package documentation: https://pkg.go.dev/github.com/classmarkets/go-dns-resolver

[^1]: The system resolver is used to discover the root name servers unless
  configured otherwise; gotta start somewhere.


[miekgdns]: https://github.com/miekg/dns

## Examples

### Query up-to-date A records:

Query the current A records for one.example.com.

```go
ctx := context.Background() // cancel the context to abort in-flight queries

r := dnsresolver.New()

// go-dns-resolver always expects fully qualified domains, so the trailing
// dots is optional.
domain := "one.example.com"

recordSet, err := r.Query(ctx, "A", domain)
if errors.Is(err, dnsresolver.ErrNXDomain) {
    log.Println("Record not found")
} else if err != nil {
    log.Fatal(err)
}

// Display all DNS queries that have been sent. 
fmt.Println(recordSet.Trace.Dump())

fmt.Printf("%#v\n", recordSet.Values)     // []string{"203.0.113.12", "203.0.113.20", "203.0.113.80"}; the values of the A records
fmt.Printf("%#v\n", recordSet.ServerAddr) // "198.51.100.53:53"; the name server that answered the final query.
fmt.Printf("%#v\n", recordSet.TTL)        // 1 * time.Hour
```

### Enable response caching

Response caching is very minimal by default, but can be enabled on a
case-by-case basis.

Using the `ObeyResponderAdvice` cache policy caches all responses as advised
by the name servers.

```go
ctx := context.Background() // cancel the context to abort in-flight queries

r := dnsresolver.New()

// Cache NXDOMAIN responses for 1 minute, and everything else according to the
// TTLs of the DNS records.
r.CachePolicy = dnsresolver.ObeyResponderAdvice(1 * time.Minute)

r.Query(ctx, "A", "two.example.com") // pretty slow
r.Query(ctx, "A", "two.example.com") // almost instant

r.ClearCache()

r.Query(ctx, "A", "two.example.com") // pretty slow again
```

### Configuring timeouts

By default, queries sent to private IP addresses (10.0.0.0/8, 192.168.0.0/16,
fd00::/8, etc.) have a timeout of 100 milliseconds and all other queries have
a timeout of 1 second. If a private subnet is not in fact on the local
network, or some DNS servers are really slow, the timeout policy can be
adjusted as necessary:


```go
ctx := context.Background()

// total timeout for all required DNS queries
ctx, cancel := context.WithTimeout(ctx, 10 * time.Second)
defer cancel()

r := dnsresolver.New()

defaultPolicy := dnsresolver.DefaultTimeoutPolicy()

// 10.200.0.0/16 is a VPN, i.e. not local, and can be expected to be
// somewhat slow.
_, vpn, _ := net.ParseCIDR("10.200.0.0/16")

r.TimeoutPolicy = func(recordType, domainName, nameServerAddress string) time.Duration {
    ipStr, _, _ := net.SplitHostPort(nameServerAddress)
    ip := net.ParseIP(ipStr)

    if vpn.Contains(ip) {
        return 1 * time.Second
    } else {
        return defaultPolicy(recordType, domainName, nameServerAddress)
    }
}

r.Query(ctx, "A", "three.example.com")
```

### Configuring bootstrap servers

go-dns-resolver does not include a hard-coded list of root name servers.
Consequently, the root name servers have to be discovered by querying some
other name server. By default, those "other name servers" are the name servers
configured in the OS.

If determining the system name servers fails, or the system name servers
cannot be trusted to deliver the correct root name servers, the set of initial
name servers can be specified explicitly.

```go
ctx := context.Background()

r := dnsresolver.New()

// Use Google's name servers to discover the root name servers, and if that
// fails try CloudFlare's server too. The ports are optional and default to 53.
r.SetBootstrapServers("8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53")

// Will send a query for "NS ." to 8.8.8.8, then start resolving
// four.example.com at the root name servers. Note that 8.8.8.8 will never see
// a query for four.example.com.
r.Query(ctx, "A", "four.example.com")
```
