package dnsresolver

import "errors"

// ErrNXDomain is returned by Resolver.Query if the final response of a query
// chain is a NXDOMAIN response. ErrNXDomain may be wrapped and must be tested
// for with errors.Is.
var ErrNXDomain = errors.New("NXDOMAIN response")

// ErrCircular is returned by Resolver.Query if records refer to one another.
// Such circular references typically happen with CNAME or NS records.
// ErrCircular may be wrapped and must be tested for with errors.Is.
var ErrCircular = errors.New("circular reference")
