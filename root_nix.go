//go:build !windows
// +build !windows

package dnsresolver

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

func (r *Resolver) discoverRootServers(ctx context.Context) error {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("cannot determine root name servers: %w", err)
	}

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeNS)
	m.RecursionDesired = true

	for _, srv := range config.Servers {
		resp, _, err := c.Exchange(m, srv+":"+config.Port)
		if err != nil {
			return fmt.Errorf("cannot determine root name servers: %w", err)
		}

		if resp.Rcode != dns.RcodeSuccess {
			err = fmt.Errorf("cannot determine root name servers: %s", dns.RcodeToString[resp.Rcode])

			// Normally we stop querying as soon as we get any kind of
			// response, but since we can't do anything at all without knowing
			// the root servers we try a bit harder here and keep going.
			continue
		}

		r.rootServerAddrs = r.rootServerAddrs[0:]
		for _, e := range resp.Extra {
			switch e := e.(type) {
			case *dns.A:
				r.rootServerAddrs = append(r.rootServerAddrs, e.A.String())
			case *dns.AAAA:
				r.rootServerAddrs = append(r.rootServerAddrs, e.AAAA.String())
			}
		}

		if len(r.rootServerAddrs) > 0 {
			return nil
		}

		err = errors.New("cannot determine root name servers: empty additional section")
	}

	if err != nil {
		return err
	}

	return errors.New("unimplemented") // TODO
}
