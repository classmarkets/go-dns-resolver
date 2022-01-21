package dnsresolver

import (
	"net"
	"strings"
	"testing"

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
	srv := &TestServer{
		t: t,
	}

	srv.parseZone(zone, addr+".zone")

	t.Logf("Starting name server on %s:5354/udp", addr)
	ln, err := net.ListenPacket("udp", addr+":5354")
	if err != nil {
		t.Fatal(err)
	}

	srv.Server = dns.Server{
		PacketConn: ln,
		Handler:    srv,
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

func (ts *TestServer) parseZone(zone, fname string) {
	if ts.DB == nil {
		ts.DB = map[uint16]map[string][]dns.RR{}
	}

	lines := strings.Split(zone, "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	zone = strings.Join(lines, "\n")

	zp := dns.NewZoneParser(strings.NewReader(zone+"\n"), ".", fname)

	zp.SetIncludeAllowed(false)

	for {
		rr, ok := zp.Next()
		if !ok {
			break
		}
		ts.AddRecordSet(rr)
	}

	if err := zp.Err(); err != nil {
		ts.t.Fatal(err)
	}
}

func (ts *TestServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	errCode := func(w dns.ResponseWriter, r *dns.Msg, code int) {
		m := new(dns.Msg)
		m.SetRcode(r, code)
		w.WriteMsg(m)
	}

	nxDomain := func(w dns.ResponseWriter, r *dns.Msg) {
		errCode(w, r, dns.RcodeNameError)
	}

	switch r.Opcode {
	case dns.OpcodeQuery:
	default:
		ts.t.Logf("opcode %v is not supported", r.Opcode)
		errCode(w, r, dns.RcodeNotImplemented)
		return
	}

	if len(r.Question) == 0 {
		ts.t.Logf("no question")
		errCode(w, r, dns.RcodeFormatError)
		return
	}

	if len(r.Question) > 1 {
		ts.t.Logf("multiple questions are not supported")
		errCode(w, r, dns.RcodeNotImplemented)
		return
	}

	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeSuccess)
	m.Authoritative = true
	ts.addAnswer(m, m.Question[0].Qtype, m.Question[0].Name, &m.Answer)

	if len(m.Answer)+len(m.Ns)+len(m.Extra) == 0 {
		nxDomain(w, r)
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
				m.Extra = append(m.Extra, ts.DB[dns.TypeA][additionalIPName]...)
				m.Extra = append(m.Extra, ts.DB[dns.TypeAAAA][additionalIPName]...)
			}
		}
	}

	w.WriteMsg(m)
}

func (ts *TestServer) addAnswer(m *dns.Msg, typ uint16, name string, dest *[]dns.RR) {
	rrs := ts.DB[typ][name]
	*dest = append(*dest, rrs...)

	if len(rrs) > 0 {
		return
	}
	if typ == dns.TypeCNAME {
		return
	}

	cnames := ts.DB[dns.TypeCNAME][name]

	*dest = append(*dest, cnames...)
	for _, cname := range cnames {
		ts.addAnswer(m, typ, cname.(*dns.CNAME).Target, dest)
	}
}
