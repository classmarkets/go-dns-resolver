package dnsresolver

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// ErrNXDomain is returned by Resolver.Query if the final response of a query
// chain is a NXDOMAIN response. ErrNXDomain may be wrapped and must be tested
// for with errors.Is.
var ErrNXDomain = errors.New("NXDOMAIN response")

// ErrCircular is returned by Resolver.Query if CNAME records or name servers
// refer to one another. ErrCircular may be wrapped and must be tested for with
// errors.Is.
var ErrCircular = errors.New("circular reference")

// LookupError is returned by Resolver.Query if the desired query could not be
// made, typically due to a network error or timeout.
type LookupError struct {
	RecordType string
	DomainName string
	Cause      error
}

func (err LookupError) Unwrap() error { return err.Cause }
func (err LookupError) Error() string {
	return fmt.Sprintf("%s %s: %v", err.RecordType, err.DomainName, err.Cause)
}

// ErrorReponse is returned by Resolver.Query if the DNS server responds with a
// code other than "NoError".
type ErrorReponse struct {
	RecordType string
	DomainName string
	Code       int
}

func (err ErrorReponse) Error() string {
	return fmt.Sprintf("%s %s: query unsuccessfull: %v", err.RecordType, err.DomainName, dns.RcodeToString[err.Code])
}

func (err ErrorReponse) Unwrap() error {
	switch err.Code {
	case dns.RcodeNameError:
		return ErrNXDomain
	default:
		return errors.New(dns.RcodeToString[err.Code])
	}
}
