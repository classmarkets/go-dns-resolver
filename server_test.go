package dnsresolver

import (
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
)

type testHandler interface {
	ServeDNS(*testing.T, dns.ResponseWriter, *dns.Msg)
}

type TestServer struct {
	dns.Server

	t        *testing.T
	handlers map[string]testHandler
}

func NewTestServer(t *testing.T, addr string) *TestServer {
	srv := &TestServer{
		t:        t,
		handlers: map[string]testHandler{},
	}

	t.Logf("Starting name server on %s/udp", addr)
	ln, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}

	srv.Server = dns.Server{
		PacketConn: ln,
		Handler:    srv,
	}

	srv.Start()

	return srv
}

func NewRootServer(t *testing.T, addr string, r *Resolver) *TestServer {
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	if r != nil {
		r.systemServerAddrs = []string{ip}
	}

	srv := NewTestServer(t, addr)

	srv.ExpectQuery("NS .").Respond().
		Answer(
			NS(t, ".", 321, "self.test."),
		).
		Additional(
			A(t, "self.test.", 321, ip),
		)

	return srv
}

func (ts *TestServer) Start() {
	expectErr := make(chan struct{})

	ts.t.Cleanup(func() {
		close(expectErr)
		ts.Shutdown()
	})

	go func() {
		err := ts.ActivateAndServe()
		select {
		case <-expectErr:
		default:
			if err != nil {
				ts.t.Fatal(err)
			}
		}
	}()
}

func (ts *TestServer) IP() string {
	addr := ts.PacketConn.LocalAddr().String()
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		ts.t.Fatal(err)
	}
	return ip
}

type expectation struct {
	testHandler
}

func (ts *TestServer) ExpectQuery(pattern string) *expectation {
	h := &expectation{}
	ts.handlers[pattern] = h

	return h
}

func (ts *TestServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if !ts.validate(w, r) {
		return
	}

	q := r.Question[0]

	pattern := fmt.Sprintf("%s %s",
		dns.TypeToString[q.Qtype], q.Name,
	)

	h := ts.handlers[pattern]
	if h == nil {
		ts.t.Errorf("Unexpected query: %s", pattern)

		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNotImplemented)
		w.WriteMsg(m)

		return
	}

	h.ServeDNS(ts.t, w, r)
}

func (ts *TestServer) validate(w dns.ResponseWriter, r *dns.Msg) bool {
	errCode := func(w dns.ResponseWriter, r *dns.Msg, code int) {
		m := new(dns.Msg)
		m.SetRcode(r, code)
		w.WriteMsg(m)
	}

	switch r.Opcode {
	case dns.OpcodeQuery:
	default:
		ts.t.Logf("opcode %v is not supported", r.Opcode)
		errCode(w, r, dns.RcodeNotImplemented)
		return false
	}

	if len(r.Question) == 0 {
		ts.t.Logf("no question")
		errCode(w, r, dns.RcodeFormatError)
		return false
	}

	if len(r.Question) > 1 {
		ts.t.Logf("multiple questions are not supported")
		errCode(w, r, dns.RcodeNotImplemented)
		return false
	}

	return true
}

type serveHandler struct {
	code       int
	answer     []dns.RR
	authority  []dns.RR
	additional []dns.RR
}

func (h *expectation) Respond() *serveHandler {
	x := &serveHandler{}
	h.testHandler = x

	return x
}

func (h *serveHandler) Status(code int) *serveHandler {
	h.code = code

	return h
}

func (h *serveHandler) Answer(rrs ...dns.RR) *serveHandler {
	h.answer = rrs

	return h
}

func (h *serveHandler) Authority(rrs ...dns.RR) *serveHandler {
	h.authority = rrs

	return h
}

func (h *serveHandler) Additional(rrs ...dns.RR) *serveHandler {
	h.additional = rrs

	return h
}

type delegationHandler struct {
	upstreamAddr string
	viaAuthority bool
}

func (h *expectation) DelegateTo(addr string) *delegationHandler {
	x := &delegationHandler{
		upstreamAddr: addr,
	}

	h.testHandler = x

	return x
}

func (h *delegationHandler) ViaAuthoritySection() *delegationHandler {
	h.viaAuthority = true
	return h
}

func (h *delegationHandler) ServeDNS(t *testing.T, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeSuccess)
	m.Authoritative = false

	if net.ParseIP(h.upstreamAddr) != nil {
		m.Answer = []dns.RR{
			NS(t, "com.", 321, "next.test."),
		}
		m.Extra = []dns.RR{
			A(t, "next.test.", 321, h.upstreamAddr),
		}
	} else {
		m.Answer = []dns.RR{
			NS(t, "com.", 321, h.upstreamAddr),
		}
	}

	if h.viaAuthority {
		m.Ns = m.Answer
		m.Answer = nil
	}

	w.WriteMsg(m)
}

func (h *serveHandler) ServeDNS(t *testing.T, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)

	m.SetRcode(r, h.code)
	m.Authoritative = true

	m.Answer = h.answer
	m.Ns = h.authority
	m.Extra = h.additional

	w.WriteMsg(m)
}
