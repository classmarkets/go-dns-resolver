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

type TestServer struct {
	t  *testing.T
	DB map[uint16]map[string][]dns.RR
	dns.Server
}

func (ts *TestServer) AddRecordSet(rr dns.RR) {
	hdr := rr.Header()

	if ts.DB == nil {
		ts.DB = map[uint16]map[string][]dns.RR{}
	}
	if ts.DB[hdr.Rrtype] == nil {
		ts.DB[hdr.Rrtype] = map[string][]dns.RR{}
	}
	ts.DB[hdr.Rrtype][hdr.Name] = append(ts.DB[hdr.Rrtype][hdr.Name], rr)
}

// NewTestServer returns a DNS server that listens on addr:5354/udp and serves
// the zone specified by zone, the contents of an RFC 1035 style zonefile.
// Unless specified with an $ORIGIN directive, the origin is the root zone ".".
//
// The server is automatically shut down when the test finishes.
func NewTestServer(t *testing.T, addr string, zone string) *TestServer {
	srv := &TestServer{}

	zp := dns.NewZoneParser(
		strings.NewReader(strings.TrimSpace(zone)+"\n"),
		".",
		addr+".zone",
	)

	zp.SetIncludeAllowed(false)

	for {
		rr, ok := zp.Next()
		if !ok {
			break
		}
		srv.AddRecordSet(rr)
	}

	if err := zp.Err(); err != nil {
		t.Fatal(err)
	}

	t.Logf("Starting name server on %s:5354/udp", addr)
	ln, err := net.ListenPacket("udp", addr+":5354")
	if err != nil {
		t.Fatal(err)
	}

	srv.Server = dns.Server{
		PacketConn: ln,
		Handler:    testHandler(t, zone, addr+".zone"),
	}

	expectErr := make(chan struct{})

	t.Cleanup(func() {
		close(expectErr)
		srv.Shutdown()
	})

	go func() {
		err := srv.ActivateAndServe()
		select {
		case <-expectErr:
		default:
			if err != nil {
				t.Fatal(err)
			}
		}
	}()

	return srv
}

// NewRootServer returns a DNS server that listens on rootAddr:5354/udp and
// serves part of the root zone. NS records for the com., net., org., and
// co.uk. zones are served, and they all point to tldAddr.
//
// The server is automatically shut down when the test finishes.
func NewRootServer(t *testing.T, rootAddr, tldAddr string) *TestServer {
	return NewTestServer(t, rootAddr, `
com.                   321  IN  NS  gtld-server.net.test.
net.                   321  IN  NS  gtld-server.net.test.
org.                   321  IN  NS  gtld-server.net.test.
co.uk.                 321  IN  NS  gtld-server.net.test.
gtld-server.net.test.  321  IN  A   `+tldAddr+`

; When asked for the root zone return ourselves, so we can use this server in
; Resolver.systemResolvers.
.                      321  IN  NS  self.test.
self.test.             321  IN  A   `+rootAddr+`
	`)
}

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

	lab := &Lab{
		RootServer:  NewRootServer(t, "127.0.0.250", "127.0.0.100"),
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
	t.Log("TLD zonefile:\n" + buf.String())
	lab.TLDServer = NewTestServer(t, "127.0.0.100", buf.String())

	return lab
}

func testHandler(t *testing.T, zone, fname string) dns.Handler {
	zp := dns.NewZoneParser(
		strings.NewReader(strings.TrimSpace(zone)+"\n"),
		".", fname)

	zp.SetIncludeAllowed(false)

	db := map[uint16]map[string][]dns.RR{}

	for {
		rr, ok := zp.Next()
		if !ok {
			break
		}
		hdr := rr.Header()

		if db[hdr.Rrtype] == nil {
			db[hdr.Rrtype] = map[string][]dns.RR{}
		}
		db[hdr.Rrtype][hdr.Name] = append(db[hdr.Rrtype][hdr.Name], rr)
	}

	if err := zp.Err(); err != nil {
		t.Fatal(err)
	}

	/*
		ns := new(dns.NS)
		ns.Hdr.Name = "example.com."
		ns.Hdr.Rrtype = dns.TypeNS
		ns.Hdr.Class = dns.ClassINET
		ns.Ns = "self."
		ns.Hdr.Ttl = 300

		a := new(dns.A)
		a.Hdr.Name = "self."
		a.Hdr.Rrtype = dns.TypeA
		a.Hdr.Class = dns.ClassINET
		a.Hdr.Ttl = 60
		a.A = net.ParseIP("127.0.0.100")

		db := map[uint16]map[string][]dns.RR{}
		db[dns.TypeA] = map[string][]dns.RR{}
		db[dns.TypeNS] = map[string][]dns.RR{}
		db[dns.TypeNS]["example.com."] = append(db[dns.TypeNS]["example.com."], ns)

		db[dns.TypeA]["self."] = append(db[dns.TypeA]["example.com."], a)
	*/

	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {

		switch r.Opcode {
		case dns.OpcodeQuery:
		default:
			t.Logf("opcode %v is not supported", r.Opcode)
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNotImplemented)
			w.WriteMsg(m)
			return
		}

		if len(r.Question) == 0 {
			t.Logf("no question")
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeFormatError)
			w.WriteMsg(m)
			return
		}

		if len(r.Question) > 1 {
			t.Logf("multiple questions are not supported")
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNotImplemented)
			w.WriteMsg(m)
			return
		}

		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeSuccess)
		m.Authoritative = true
		m.Answer = db[m.Question[0].Qtype][m.Question[0].Name]

		if len(m.Answer) == 0 {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			return
		}

		switch m.Question[0].Qtype {
		case dns.TypeNS:
			for _, rr := range m.Answer {
				var additionalIPName string

				switch rr := rr.(type) {
				case *dns.NS:
					additionalIPName = rr.Ns
				}

				if additionalIPName != "" {
					m.Extra = append(m.Extra, db[dns.TypeA][additionalIPName]...)
					m.Extra = append(m.Extra, db[dns.TypeAAAA][additionalIPName]...)
				}
			}
		}

		w.WriteMsg(m)
	})
}
