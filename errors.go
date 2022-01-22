package dnsresolver

import (
	"errors"
)

// ErrNXDomain is returned by Resolver.Query if the final response of a query
// chain is a NXDOMAIN response. ErrNXDomain may be wrapped and must be tested
// for with errors.Is.
var ErrNXDomain = errors.New("NXDOMAIN response")

// ErrCircular is returned by Resolver.Query if CNAME records or name servers
// refer to one another. ErrCircular may be wrapped and must be tested for with
// errors.Is.
var ErrCircular = errors.New("circular reference")
