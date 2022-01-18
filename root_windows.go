package dnsresolver

import (
	"context"
	"errors"
)

func (r *Resolver) discoverRootServers(ctx context.Context) error {
	// TODO: This seems to be, erm, interesting, on Windows:
	// - https://gist.github.com/moloch--/9fb1c8497b09b45c840fe93dd23b1e98
	// - https://github.com/miekg/dns/issues/334
	return errors.New("unimplemented")
}
