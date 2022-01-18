# Go DNS resolver

This library provides a recursive DNS resolver that offers selective caching.
It is useful in cases where up-to-date DNS records are required, and primarily
intended for use in infrastructure automation tasks. This resolver applies
minimal caching by default: only NS records for public suffixes (".com", ".org"
and such) are cached, all other TTL fields in DNS responses are ignored. The
caching policy is fully customizable, though.

go-dns-resolver is built on top of the excellent [miekg/dns][miekgdns] package,
but provides a much higher-level API. The priority here is usage ergonomics for
the common cases, not completeness or performance.

[miekgdns]: https://github.com/miekg/dns

## Examples

### Query up to date A records:

Query the current A records for one.example.com, starting with the root name
servers:

```go
ctx := context.Background() // cancel the context to abort in-flight queries

r := dnsresolver.New()

// go-dns-resolver always expects fully qualified domains, so all trailing
// dots are optional.
recordSet, err := r.Query(ctx, "A", "one.example.com")
if errors.Is(err, dnsresolver.ErrNXDomain) {
    log.Println("Record not found")
    fmt.Printf("%#v\n", recordSet.Trace) // TODO
} else if err != nil {
    log.Fatal(err)
}

fmt.Printf("%#v\n", recordSet.Values)     // []string{"203.0.113.12", "203.0.113.20", "203.0.113.80"}; the values of the final A records
fmt.Printf("%#v\n", recordSet.NameServer) // "198.51.100.53:53"; the name server that answered the final query. Same as recordSet.Trace[0].Server
fmt.Printf("%#v\n", recordSet.TTL)        // 1 * time.Hour
```

### Query up to date A records using specific name servers

Query the current A records for two.example.com, using the name servers at
10.0.0.100:53 and 10.0.0.200:5353 for the example.com. zone. This will skip the
NS queries from com. and example.com.

```go
ctx := context.Background() // cancel the context to abort in-flight queries

r := dnsresolver.New()

// go-dns-resolver always expects fully qualified domains, so all trailing
// dots are optional.
//
// Name servers must be specified by IP address and the port defaults to 53.
//
// Multiple calls to WithZoneServer will add or overwrite name servers for the
// given zone.
//
// Call r.WithZoneServer("example.com", nil) to remove the zone server again.
err := r.WithZoneServer("example.com", []string{"10.0.0.100", "10.0.0.200:5353"})
if err != nil {
    log.Fatal(err)
}

recordSet, err := r.Query(ctx, "A", "two.example.com")
if errors.Is(err, dnsresolver.ErrNXDomain) {
    log.Println("Record not found")
    fmt.Printf("%#v\n", recordSet.Trace) // TODO
} else if err != nil {
    log.Fatal(err)
}

fmt.Printf("%#v\n", recordSet.Values)     // []string{"203.0.113.12", "203.0.113.20", "203.0.113.80"}; the values of the final A records
fmt.Printf("%#v\n", recordSet.NameServer) // "10.0.0.100:53"; the name server that answered the final query
fmt.Printf("%#v\n", recordSet.TTL)        // 1 * time.Hour
```

### Enable response caching

Response caching is very minimal by default, but can be enabled for more
records on a case-by-case basis.

Query the current A records for three.example.com and four.example.com, but
remember all responses to NS queries.

```go
ctx := context.Background() // cancel the context to abort in-flight queries

r := dnsresolver.New()

// All trailing dots are optional (go-dns-resolver always expects fully
// qualified domains). Name servers must be specified by IP address and the port
// defaults to 53.
//
// Set CachePolicy to nil to disable caching again.
r.CachePolicy = func(r dnsresolver.RecordSet) (ttl time.Duration) {
    if r.ResponseType == "NS" {
        return 1*time.Minute // or r.TTL to honor the suggestion of the responding name server
    }

    return 0 // Any non-positive duration prevents caching.
}

recordSet, err := r.Query(ctx, "A", "three.example.com")
if errors.Is(err, dnsresolver.ErrNXDomain) {
    log.Println("Record not found")
    fmt.Printf("%#v\n", recordSet.Trace) // TODO
} else if err != nil {
    log.Fatal(err)
}

fmt.Printf("%#v\n", recordSet.Values)     // []string{"203.0.113.112", "203.0.113.120", "203.0.113.180"}
fmt.Printf("%#v\n", recordSet.NameServer) // "198.51.100.53"

// Further error handling omitted for brevity.

recordSet, _ := r.Query(ctx, "A", "four.example.com")
fmt.Printf("%#v\n", recordSet.Values)     // []string{"203.0.113.212", "203.0.113.220", "203.0.113.280"}
fmt.Printf("%#v\n", recordSet.NameServer) // "198.51.100.53"; same as above, because it has been cached

r.ClearCache()

recordSet, _ := r.Query(ctx, "A", "four.example.com")
fmt.Printf("%#v\n", recordSet.Values)     // []string{"203.0.113.29", "203.0.113.37", "203.0.113.97"}
fmt.Printf("%#v\n", recordSet.NameServer) // "198.51.100.78"; different name server now
```

### Compare name server responses

Compare the responses from two name servers. Useful for consistency checks of
small record sets.

RecordSet.Equal compares the Type, TTL, and Values of two record sets, ignoring
the order of Values.

This only works well if the name servers return all values with every query
instead of, say, three random values out of ten. Since DNS packets are limited
in size, servers are forced to truncate records with too many values _somehow_.
If that goes together with randomization, Equal isn't particularly useful.

Also, because the TTL is compared as well, only responses from authoritative
name servers should be compared, otherwise the TTL may represent the remaining
life time of a cached response, which can obviously differ between servers.

```go
ctx := context.Background() // cancel the context to abort in-flight queries

r := dnsresolver.New()

// Error handling omitted for brevity.

_ = r.WithZoneServer("example.com", []string{"10.0.0.100"})
setA, _ := r.Query(ctx, "A", "five.example.com")

_ = r.WithZoneServer("example.com", []string{"10.0.0.200"})
setB, _ := r.Query(ctx, "A", "five.example.com")

// Compare the TTL and Values fields, ignoring the order of Values.
if !setA.Equal(setB) {
    fireAlert("name servers out of sync")
}
```
