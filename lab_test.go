package dnsresolver

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"text/tabwriter"

	"github.com/miekg/dns"
)

type Lab struct {
	RootServer  *TestServer
	TLDServer   *TestServer
	ZoneServers map[string]*TestServer
}

// NewLab starts a root name server, a tld name server, the name servers
// defined by zoneServers, and configured r to use the root server.
//
// zones is a map of zone origins to RFC 1035 style zone definitions. The root
// server listens on 127.0.0.250:5354, the tld server on 127.0.0.100:5354, and
// the zone servers on consecutive addresses starting at 127.0.0.101:5354.
//
// All servers are automatically shut down when the test finishes.
func NewLab(t *testing.T, r *Resolver, zones map[string]string) *Lab {
	r.defaultPort = "5354"
	r.systemServerAddrs = []string{"127.0.0.250"}
	r.logFunc = DebugLog(t)

	lab := &Lab{
		ZoneServers: map[string]*TestServer{},
	}

	var zoneNames []string

	for zoneName := range zones {
		zoneNames = append(zoneNames, zoneName)
	}
	sort.Strings(zoneNames)

	buf := &bytes.Buffer{}
	tw := tabwriter.NewWriter(buf, 0, 0, 2, ' ', 0)

	for i, zoneName := range zoneNames {
		addr := net.IP{127, 0, 0, byte(101 + i)}.String()
		fmt.Fprintf(tw, "%-s\t321\tIN\tNS\t%d.iana-server.net.test.\n", dns.CanonicalName(zoneName), i)
		fmt.Fprintf(tw, "%d.iana-server.net.test.\t321\tIN\tA\t%s\n", i, addr)

		lab.ZoneServers[zoneName] = NewTestServer(t, addr,
			fmt.Sprintf("$ORIGIN %s\n%s", dns.CanonicalName(zoneName), strings.TrimSpace(zones[zoneName])),
		)
	}

	tw.Flush()

	lab.TLDServer = NewTestServer(t, "127.0.0.100", buf.String())
	lab.RootServer = NewRootServer(t, "127.0.0.250", "127.0.0.100")

	t.Log("TLD zonefile:\n" + buf.String())

	return lab
}

func DebugLog(t *testing.T) func(queryResult) {
	return func(result queryResult) {
		q := result.Question
		resp := result.Response
		err := result.Error

		t.Logf("%s\t@%s %dms\n", strings.TrimPrefix(q.String(), ";"), result.ServerAddr, result.RTT.Milliseconds())
		if err != nil {
			t.Logf("\t%v\n", err)
		} else if resp.Rcode != dns.RcodeSuccess {
			t.Logf("\t%s\n", dns.RcodeToString[resp.Rcode])
		} else {
			if len(resp.Answer) > 0 {
				t.Logf("\tANSWER\n")
				for _, rr := range resp.Answer {
					t.Logf("\t\t%s\n", rr.String())
				}
			}
			if len(resp.Ns) > 0 {
				t.Logf("\tAUTHORITY\n")
				for _, rr := range resp.Ns {
					t.Logf("\t\t%s\n", rr.String())
				}
			}
			if len(resp.Extra) > 0 {
				t.Logf("\tADDITIONAL\n")
				for _, rr := range resp.Extra {
					t.Logf("\t\t%s\n", rr.String())
				}
			}
		}
	}
}
