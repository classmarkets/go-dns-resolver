package dnsresolver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestResolver_SetBootstrapServers_AddressNormalization(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		r := New()

		err := r.SetBootstrapServers("127.0.0.1", "127.0.0.2:5353")

		assert.NoError(t, err)
		assert.Equal(t, r.systemServerAddrs, []string{"127.0.0.1:53", "127.0.0.2:5353"})
	})
	t.Run("unique", func(t *testing.T) {
		r := New()

		err := r.SetBootstrapServers("127.0.0.1", "127.0.0.1:53")

		assert.NoError(t, err)
		assert.Equal(t, r.systemServerAddrs, []string{"127.0.0.1:53"})
	})
	t.Run("invalid", func(t *testing.T) {
		r := New()

		err := r.SetBootstrapServers("127.0.0.1", "localhost:5353")

		assert.EqualError(t, err, "not an ip address: localhost:5353")
		assert.Len(t, r.systemServerAddrs, 0)
	})
}

func TestResolver_Query_SimpleARecord(t *testing.T) {
	r := New()
	r.defaultPort = "5354"
	r.logFunc = DebugLog(t)

	rootSrv := NewRootServer(t, "127.0.0.250:"+r.defaultPort)
	comSrv := NewTestServer(t, "127.0.0.100:"+r.defaultPort)
	expSrv := NewTestServer(t, "127.0.0.101:"+r.defaultPort)

	r.SetBootstrapServers(rootSrv.IP())

	rootSrv.ExpectQuery("A www.example.com.").DelegateTo("com.", comSrv.IP())
	comSrv.ExpectQuery("A www.example.com.").DelegateTo("example.com.", expSrv.IP()).ViaAuthoritySection()
	expSrv.ExpectQuery("A www.example.com.").Respond().
		Answer(
			A(t, "www.example.com.", 321, "192.0.2.0"),
			A(t, "www.example.com.", 321, "192.0.2.1"),
		)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	rs, err := r.Query(ctx, "A", "www.example.com")
	t.Logf("Trace:\n" + rs.Trace.Dump())
	assert.NoError(t, err)

	assert.Equal(t, "www.example.com", rs.Name)
	assert.Equal(t, "A", rs.Type)
	assert.Equal(t, 321*time.Second, rs.TTL)
	assert.Equal(t, []string{"192.0.2.0", "192.0.2.1"}, rs.Values)
	assert.Equal(t, "127.0.0.101:5354", rs.ServerAddr)
	assert.Equal(t, rs.Age, -1*time.Second)
	assert.Greater(t, rs.RTT, time.Duration(0))

	wantTrace := strings.TrimSpace(`
? . IN NS @127.0.0.250:5354 (rtt<1ms, age=0s)
  ! . 321 IN NS self.test.
  ! self.test. 321 IN A 127.0.0.250
? www.example.com. IN A @127.0.0.250:5354 (rtt<1ms, age=0s)
  ! com. 321 IN NS ns1.test.
  ! ns1.test. 321 IN A 127.0.0.100
? www.example.com. IN A @127.0.0.100:5354 (rtt<1ms, age=-1s)
  ! example.com. 321 IN NS ns1.test.
  ! ns1.test. 321 IN A 127.0.0.101
? www.example.com. IN A @127.0.0.101:5354 (rtt<1ms, age=-1s)
  ! www.example.com. 321 IN A 192.0.2.0
  ! www.example.com. 321 IN A 192.0.2.1
	`) + "\n"

	assert.Equal(t, wantTrace, rs.Trace.Dump())
}

func TestResolver_Query_Fallback(t *testing.T) {
	r := New()
	r.defaultPort = "5354"
	r.logFunc = DebugLog(t)

	rootSrv := NewRootServer(t, "127.0.0.250:"+r.defaultPort)
	comSrv := NewTestServer(t, "127.0.0.100:"+r.defaultPort)
	errSrv := NewTestServer(t, "127.0.0.101:"+r.defaultPort)
	expSrv := NewTestServer(t, "127.0.0.102:"+r.defaultPort)

	r.SetBootstrapServers(rootSrv.IP())

	rootSrv.ExpectQuery("A www.example.com.").DelegateTo("com.", comSrv.IP())
	comSrv.ExpectQuery("A www.example.com.").DelegateTo("example.com.", errSrv.IP(), expSrv.IP())
	errSrv.ExpectQuery("A www.example.com.").Respond().Status(dns.RcodeServerFailure)
	expSrv.ExpectQuery("A www.example.com.").Respond().
		Answer(
			A(t, "www.example.com.", 321, "192.0.2.0"),
			A(t, "www.example.com.", 321, "192.0.2.1"),
		)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	rs, err := r.Query(ctx, "A", "www.example.com")
	t.Logf("Trace:\n" + rs.Trace.Dump())
	assert.NoError(t, err)

	assert.Equal(t, "www.example.com", rs.Name)
	assert.Equal(t, []string{"192.0.2.0", "192.0.2.1"}, rs.Values)
	assert.Equal(t, "127.0.0.102:5354", rs.ServerAddr)

	wantTrace := strings.TrimSpace(`
? . IN NS @127.0.0.250:5354 (rtt<1ms, age=0s)
  ! . 321 IN NS self.test.
  ! self.test. 321 IN A 127.0.0.250
? www.example.com. IN A @127.0.0.250:5354 (rtt<1ms, age=0s)
  ! com. 321 IN NS ns1.test.
  ! ns1.test. 321 IN A 127.0.0.100
? www.example.com. IN A @127.0.0.100:5354 (rtt<1ms, age=-1s)
  ! example.com. 321 IN NS ns1.test.
  ! example.com. 321 IN NS ns2.test.
  ! ns1.test. 321 IN A 127.0.0.101
  ! ns2.test. 321 IN A 127.0.0.102
? www.example.com. IN A @127.0.0.101:5354 (rtt<1ms, age=-1s)
  X SERVFAIL
? www.example.com. IN A @127.0.0.102:5354 (rtt<1ms, age=-1s)
  ! www.example.com. 321 IN A 192.0.2.0
  ! www.example.com. 321 IN A 192.0.2.1
	`) + "\n"

	assert.Equal(t, wantTrace, rs.Trace.Dump())
}

func TestResolver_Query_CNAMEResolution(t *testing.T) {
	r := New()
	r.defaultPort = "5354"
	r.logFunc = DebugLog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	rootSrv := NewRootServer(t, "127.0.0.250:"+r.defaultPort)
	comSrv := NewTestServer(t, "127.0.0.100:"+r.defaultPort)
	expSrv := NewTestServer(t, "127.0.0.101:"+r.defaultPort)

	r.SetBootstrapServers(rootSrv.IP())

	rootSrv.ExpectQuery("A example.com.").DelegateTo("com.", comSrv.IP())
	comSrv.ExpectQuery("A example.com.").DelegateTo("example.com.", expSrv.IP())
	expSrv.ExpectQuery("A example.com.").Respond().
		Answer(
			CNAME(t, "example.com.", 321, "www.example.com."),
		).
		Additional(
			A(t, "www.example.com.", 321, "192.0.2.1"),
		)

	rs, err := r.Query(ctx, "A", "example.com")
	t.Logf("Trace:\n" + rs.Trace.Dump())
	assert.NoError(t, err)

	assert.Equal(t, "example.com", rs.Name)
	assert.Equal(t, "A", rs.Type)
	assert.Equal(t, 321*time.Second, rs.TTL)
	assert.Equal(t, []string{"192.0.2.1"}, rs.Values)
	assert.Equal(t, "127.0.0.101:5354", rs.ServerAddr)
	assert.Equal(t, rs.Age, -1*time.Second)
	assert.Greater(t, rs.RTT, time.Duration(0))

	wantTrace := strings.TrimSpace(`
? . IN NS @127.0.0.250:5354 (rtt<1ms, age=0s)
  ! . 321 IN NS self.test.
  ! self.test. 321 IN A 127.0.0.250
? example.com. IN A @127.0.0.250:5354 (rtt<1ms, age=0s)
  ! com. 321 IN NS ns1.test.
  ! ns1.test. 321 IN A 127.0.0.100
? example.com. IN A @127.0.0.100:5354 (rtt<1ms, age=-1s)
  ! example.com. 321 IN NS ns1.test.
  ! ns1.test. 321 IN A 127.0.0.101
? example.com. IN A @127.0.0.101:5354 (rtt<1ms, age=-1s)
  ! example.com. 321 IN CNAME www.example.com.
  ! www.example.com. 321 IN A 192.0.2.1
			`) + "\n"

	assert.Equal(t, wantTrace, rs.Trace.Dump())
}

func TestResolver_Query_ZoneGap(t *testing.T) {
	r := New()
	r.defaultPort = "5354"
	r.logFunc = DebugLog(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	rootSrv := NewRootServer(t, "127.0.0.250:"+r.defaultPort)
	comSrv := NewTestServer(t, "127.0.0.100:"+r.defaultPort)
	netSrv := NewTestServer(t, "127.0.0.101:"+r.defaultPort)
	expSrv := NewTestServer(t, "127.0.0.102:"+r.defaultPort)

	r.SetBootstrapServers(rootSrv.IP())

	rootSrv.ExpectQuery("A example.com.").DelegateTo("com.", comSrv.IP())
	comSrv.ExpectQuery("A example.com.").DelegateTo("example.com.", "ns1.test.net.")
	{
		rootSrv.ExpectQuery("AAAA ns1.test.net.").DelegateTo("net.", netSrv.IP())
		netSrv.ExpectQuery("AAAA ns1.test.net.").Respond().
			Answer( /* empty */ )

		netSrv.ExpectQuery("A ns1.test.net.").Respond().
			Answer(
				A(t, "ns1.test.net.", 321, expSrv.IP()),
			)
	}

	expSrv.ExpectQuery("A example.com.").Respond().
		Answer(
			A(t, "example.com.", 321, "192.0.2.0"),
		)

	rs, err := r.Query(ctx, "A", "example.com")
	t.Logf("Trace:\n" + rs.Trace.Dump())
	assert.NoError(t, err)

	assert.Equal(t, "example.com", rs.Name)
	assert.Equal(t, "A", rs.Type)
	assert.Equal(t, 321*time.Second, rs.TTL)
	assert.Equal(t, []string{"192.0.2.0"}, rs.Values)
	assert.Equal(t, "127.0.0.102:5354", rs.ServerAddr)
	assert.Equal(t, rs.Age, -1*time.Second)
	assert.Greater(t, rs.RTT, time.Duration(0))

	wantTrace := strings.TrimSpace(`
? . IN NS @127.0.0.250:5354 (rtt<1ms, age=0s)
  ! . 321 IN NS self.test.
  ! self.test. 321 IN A 127.0.0.250
? example.com. IN A @127.0.0.250:5354 (rtt<1ms, age=0s)
  ! com. 321 IN NS ns1.test.
  ! ns1.test. 321 IN A 127.0.0.100
? example.com. IN A @127.0.0.100:5354 (rtt<1ms, age=-1s)
  ! example.com. 321 IN NS ns1.test.net.
    ? ns1.test.net. IN AAAA @127.0.0.250:5354 (rtt<1ms, age=0s)
      ! net. 321 IN NS ns1.test.
      ! ns1.test. 321 IN A 127.0.0.101
    ? ns1.test.net. IN AAAA @127.0.0.101:5354 (rtt<1ms, age=-1s)
      ~ EMPTY
    ? ns1.test.net. IN A @127.0.0.101:5354 (rtt<1ms, age=-1s)
      ! ns1.test.net. 321 IN A 127.0.0.102
? example.com. IN A @127.0.0.102:5354 (rtt<1ms, age=-1s)
  ! example.com. 321 IN A 192.0.2.0
	`) + "\n"

	assert.Equal(t, wantTrace, rs.Trace.Dump())
}

func TestResolver_Query_NameFallback(t *testing.T) {
	r := New()
	r.defaultPort = "5354"
	r.logFunc = DebugLog(t)

	rootSrv := NewRootServer(t, "127.0.0.250:"+r.defaultPort)
	comSrv := NewTestServer(t, "127.0.0.100:"+r.defaultPort)
	netSrv := NewTestServer(t, "127.0.0.101:"+r.defaultPort)
	orgSrv := NewTestServer(t, "127.0.0.102:"+r.defaultPort)
	dd24Srv := NewTestServer(t, "127.0.0.103:"+r.defaultPort)
	awsSrv := NewTestServer(t, "127.0.0.104:"+r.defaultPort)

	r.SetBootstrapServers(rootSrv.IP())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rootSrv.ExpectQuery("NS dr.classmarkets.com.").DelegateTo("com.", comSrv.IP())
	comSrv.ExpectQuery("NS dr.classmarkets.com.").DelegateTo("classmarkets.com.",
		"ns1.domaindiscount24.net.",
		"ns2.domaindiscount24.net.",
		"ns3.domaindiscount24.net.",
	)
	{
		rootSrv.ExpectQuery("AAAA ns1.domaindiscount24.net.").DelegateTo("net.", netSrv.IP())
		netSrv.ExpectQuery("AAAA ns1.domaindiscount24.net.").DelegateTo("domaindiscount24.net.", dd24Srv.IP())
		dd24Srv.ExpectQuery("AAAA ns1.domaindiscount24.net.").Respond().Status(dns.RcodeServerFailure)
		dd24Srv.ExpectQuery("A ns1.domaindiscount24.net.").Respond().
			Answer(
				A(t, "ns1.domaindiscount24.net.", 300, dd24Srv.IP()),
			)
	}
	dd24Srv.ExpectQuery("NS dr.classmarkets.com.").DelegateTo("dr.classmarkets.com.",
		"ns-1094.awsdns-08.org.",
		"ns-180.awsdns-22.com.",
		"ns-1990.awsdns-56.co.uk.",
		"ns-761.awsdns-31.net.",
	)
	{
		rootSrv.ExpectQuery("AAAA ns-1094.awsdns-08.org.").DelegateTo("org.", orgSrv.IP())
		orgSrv.ExpectQuery("AAAA ns-1094.awsdns-08.org.").DelegateTo("awsdns-08.org.", awsSrv.IP())
		awsSrv.ExpectQuery("AAAA ns-1094.awsdns-08.org.").Respond().Status(dns.RcodeServerFailure)
		awsSrv.ExpectQuery("A ns-1094.awsdns-08.org.").Respond().Status(dns.RcodeServerFailure)

		rootSrv.ExpectQuery("AAAA ns-180.awsdns-22.com.").DelegateTo("com.", comSrv.IP())
		comSrv.ExpectQuery("AAAA ns-180.awsdns-22.com.").DelegateTo("awsdns-22.com.", awsSrv.IP())
		awsSrv.ExpectQuery("AAAA ns-180.awsdns-22.com.").Respond().Status(dns.RcodeRefused)
		awsSrv.ExpectQuery("A ns-180.awsdns-22.com.").Respond().
			Answer(
				A(t, "ns-180.awsdns-22.com.", 300, awsSrv.IP()),
			)
	}
	awsSrv.ExpectQuery("NS dr.classmarkets.com.").Respond().
		Answer(
			NS(t, "dr.classmarkets.com.", 300, "ns-1990.awsdns-56.co.uk."),
			NS(t, "dr.classmarkets.com.", 300, "ns-761.awsdns-31.net."),
			NS(t, "dr.classmarkets.com.", 300, "ns-1094.awsdns-08.org."),
			NS(t, "dr.classmarkets.com.", 300, "ns-180.awsdns-22.com."),
		)

	rs, err := r.Query(ctx, "NS", "dr.classmarkets.com")
	t.Logf("Trace:\n" + rs.Trace.Dump())
	assert.NoError(t, err)
	assert.Equal(t, []string{
		"ns-1990.awsdns-56.co.uk.",
		"ns-761.awsdns-31.net.",
		"ns-1094.awsdns-08.org.",
		"ns-180.awsdns-22.com.",
	}, rs.Values)
}

func TestResolver_Query_DetectCycle(t *testing.T) {
	r := New()
	r.defaultPort = "5354"
	r.logFunc = DebugLog(t)
	r.ip6disabled = true

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	rootSrv := NewRootServer(t, "127.0.0.250:"+r.defaultPort)
	comSrv := NewTestServer(t, "127.0.0.100:"+r.defaultPort)
	netSrv := NewTestServer(t, "127.0.0.101:"+r.defaultPort)

	r.SetBootstrapServers(rootSrv.IP())

	rootSrv.ExpectQuery("A example.com.").DelegateTo("com.", comSrv.IP())
	comSrv.ExpectQuery("A example.com.").DelegateTo("example.com.", "ns1.test.net.")

	rootSrv.ExpectQuery("A ns1.test.net.").DelegateTo("net.", netSrv.IP())
	netSrv.ExpectQuery("A ns1.test.net.").Respond().
		Answer(
			CNAME(t, "ns1.test.net.", 321, "ns2.test.net."),
		)

	rootSrv.ExpectQuery("A ns2.test.net.").DelegateTo("net.", netSrv.IP())
	netSrv.ExpectQuery("A ns2.test.net.").Respond().
		Answer(
			CNAME(t, "ns2.test.net.", 321, "ns1.test.net."),
		)

	rs, err := r.Query(ctx, "A", "example.com")
	t.Logf("Trace:\n" + rs.Trace.Dump())
	assert.EqualError(t, err, "A example.com: circular reference: repeated query: A ns1.test.net. @127.0.0.250:5354")
	assert.True(t, errors.Is(err, ErrCircular))
}

func TestResolver_Query_NS(t *testing.T) {
	r := New()
	r.defaultPort = "5354"
	r.logFunc = DebugLog(t)

	rootSrv := NewRootServer(t, "127.0.0.250:"+r.defaultPort)
	comSrv := NewTestServer(t, "127.0.0.100:"+r.defaultPort)
	expSrv := NewTestServer(t, "127.0.0.101:"+r.defaultPort)

	r.SetBootstrapServers(rootSrv.IP())

	rootSrv.ExpectQuery("NS www.example.com.").DelegateTo("com.", comSrv.IP())
	comSrv.ExpectQuery("NS www.example.com.").DelegateTo("example.com", expSrv.IP())
	expSrv.ExpectQuery("NS www.example.com.").Respond().
		Answer(
			NS(t, "www.example.com.", 321, "ns1.example.com."),
			NS(t, "www.example.com.", 321, "ns2.example.com."),
		)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	rs, err := r.Query(ctx, "NS", "www.example.com")
	t.Logf("Trace:\n" + rs.Trace.Dump())
	assert.NoError(t, err)

	assert.Equal(t, "www.example.com", rs.Name)
	assert.Equal(t, "NS", rs.Type)
	assert.Equal(t, 321*time.Second, rs.TTL)
	assert.Equal(t, []string{"ns1.example.com.", "ns2.example.com."}, rs.Values)
	assert.Equal(t, "127.0.0.101:5354", rs.ServerAddr)
	assert.Equal(t, rs.Age, -1*time.Second)
	assert.Greater(t, rs.RTT, time.Duration(0))
}

func TestResolver_Query_Caching_DefaultPolicy(t *testing.T) {
	r := New()
	r.defaultPort = "5354"
	r.logFunc = DebugLog(t)

	rootSrv := NewRootServer(t, "127.0.0.250:"+r.defaultPort)
	comSrv := NewTestServer(t, "127.0.0.100:"+r.defaultPort)
	expSrv := NewTestServer(t, "127.0.0.101:"+r.defaultPort)

	r.SetBootstrapServers(rootSrv.IP())

	rootSrv.ExpectQuery("NS www.example.com.").DelegateTo("com.", comSrv.IP())
	comSrv.ExpectQuery("NS www.example.com.").DelegateTo("example.com.", expSrv.IP())
	expSrv.ExpectQuery("NS www.example.com.").Respond().
		Answer(
			NS(t, "www.example.com.", 321, "ns1.example.com."),
			NS(t, "www.example.com.", 321, "ns2.example.com."),
		)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	rs, err := r.Query(ctx, "NS", "www.example.com")
	t.Logf("Trace:\n" + rs.Trace.Dump())
	assert.NoError(t, err)

	comSrv.ExpectQuery("NS www.example.com.").DelegateTo("example.com.", expSrv.IP())
	expSrv.ExpectQuery("NS www.example.com.").Respond().
		Answer(
			NS(t, "www.example.com.", 321, "ns1.example.com."),
			NS(t, "www.example.com.", 321, "ns2.example.com."),
		)

	rs, err = r.Query(ctx, "NS", "www.example.com")
	t.Logf("Trace:\n" + rs.Trace.Dump())
	assert.NoError(t, err)
}

func TestResolver_Query_Caching_ObeyResponderAdvice(t *testing.T) {
	r := New()
	r.defaultPort = "5354"
	r.logFunc = DebugLog(t)
	r.CachePolicy = ObeyResponderAdvice(1 * time.Minute)

	rootSrv := NewRootServer(t, "127.0.0.250:"+r.defaultPort)
	comSrv := NewTestServer(t, "127.0.0.100:"+r.defaultPort)
	expSrv := NewTestServer(t, "127.0.0.101:"+r.defaultPort)

	r.SetBootstrapServers(rootSrv.IP())

	rootSrv.ExpectQuery("A www.example.com.").DelegateTo("com.", comSrv.IP())
	comSrv.ExpectQuery("A www.example.com.").DelegateTo("example.com.", expSrv.IP())
	expSrv.ExpectQuery("A www.example.com.").Respond().
		Answer(
			A(t, "www.example.com.", 321, "192.0.2.1"),
		)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	rs, err := r.Query(ctx, "A", "www.example.com")
	t.Logf("Trace:\n" + rs.Trace.Dump())
	assert.NoError(t, err)

	assert.Equal(t, "www.example.com", rs.Name)
	assert.Equal(t, "A", rs.Type)
	assert.Equal(t, 321*time.Second, rs.TTL)
	assert.Equal(t, []string{"192.0.2.1"}, rs.Values)
	assert.Equal(t, "127.0.0.101:5354", rs.ServerAddr)
	assert.Equal(t, rs.Age, time.Duration(0))
	assert.Greater(t, rs.RTT, time.Duration(0))

	// Same query again. Since everything is cached, the servers shouldn't
	// receive any more queries.
	rootSrv.AssertNoOutstandingExpectations(t)
	comSrv.AssertNoOutstandingExpectations(t)
	expSrv.AssertNoOutstandingExpectations(t)

	rs, err = r.Query(ctx, "A", "www.example.com")
	t.Logf("Trace:\n" + rs.Trace.Dump())
	assert.NoError(t, err)

	assert.Equal(t, "www.example.com", rs.Name)
	assert.Equal(t, "A", rs.Type)
	assert.Equal(t, 321*time.Second, rs.TTL)
	assert.Equal(t, []string{"192.0.2.1"}, rs.Values)
	assert.Equal(t, "127.0.0.101:5354", rs.ServerAddr)
	assert.Greater(t, rs.Age, time.Duration(0))
	assert.Greater(t, rs.RTT, time.Duration(0))
}

func TestResolver_Referrals(t *testing.T) {
	cases := []struct {
		answer     []dns.RR
		authority  []dns.RR
		additional []dns.RR

		ip4disabled bool
		ip6disabled bool

		wantIPs   []string
		wantNames []string
	}{
		{
			answer: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				A(t, "ns1.example.com.", 300, "192.0.2.2"),
			},
			wantIPs: []string{"192.0.2.1", "192.0.2.2"},
		},
		{
			answer: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				AAAA(t, "ns1.example.com.", 300, "::1"),
			},
			wantIPs: []string{"192.0.2.1", "::1"},
		},
		{
			answer: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				AAAA(t, "ns1.example.com.", 300, "::1"),
			},
			ip4disabled: true,
			wantIPs:     []string{"::1"},
		},
		{
			answer: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				AAAA(t, "ns1.example.com.", 300, "::1"),
			},
			ip6disabled: true,
			wantIPs:     []string{"192.0.2.1"},
		},
		{
			answer: []dns.RR{
				CNAME(t, "ns1.", 300, "ns1.example.com."),
			},
			additional: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				A(t, "ns1.example.com.", 300, "192.0.2.2"),
				A(t, "ns2.example.com.", 300, "192.0.2.3"),
			},
			wantIPs: []string{"192.0.2.1", "192.0.2.2"},
		},
		{
			answer: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
			},
			additional: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				A(t, "ns1.example.com.", 300, "192.0.2.2"),
			},
			wantIPs: []string{"192.0.2.1", "192.0.2.2"},
		},
		{
			authority: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
			},
			additional: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				A(t, "ns1.example.com.", 300, "192.0.2.2"),
			},
			wantIPs: []string{"192.0.2.1", "192.0.2.2"},
		},
		{
			authority: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
			},
			additional: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				A(t, "ns1.example.com.", 300, "192.0.2.2"),
				AAAA(t, "ns1.example.com.", 300, "::1"),
			},
			wantIPs: []string{"192.0.2.1", "192.0.2.2", "::1"},
		},
		{
			authority: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
			},
			additional: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				A(t, "ns1.example.com.", 300, "192.0.2.2"),
				AAAA(t, "ns1.example.com.", 300, "::1"),
			},
			ip4disabled: true,
			wantIPs:     []string{"::1"},
		},
		{
			authority: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
			},
			additional: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				A(t, "ns1.example.com.", 300, "192.0.2.2"),
				AAAA(t, "ns1.example.com.", 300, "::1"),
			},
			ip6disabled: true,
			wantIPs:     []string{"192.0.2.1", "192.0.2.2"},
		},
		{
			authority: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
			},
			additional: []dns.RR{
				A(t, "ns1.example.com.", 300, "192.0.2.1"),
				A(t, "ns1.example.com.", 300, "192.0.2.2"),
				AAAA(t, "ns1.example.com.", 300, "::1"),
			},
			ip4disabled: true,
			ip6disabled: true,
			wantIPs:     nil,
		},
		{
			authority: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
			},
			additional: []dns.RR{
				CNAME(t, "ns1.example.com.", 300, "ns2.example.com."),
				CNAME(t, "ns2.example.com.", 300, "ns3.example.com."),
				A(t, "ns3.example.com.", 300, "192.0.2.2"),
				AAAA(t, "ns3.example.com.", 300, "::1"),
			},
			wantIPs: []string{"192.0.2.2", "::1"},
		},
		{
			authority: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
			},
			additional: []dns.RR{
				CNAME(t, "ns1.example.com.", 300, "ns2.example.com."),
			},
			wantIPs:   nil,
			wantNames: []string{"ns2.example.com."},
		},
		{
			authority: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
				NS(t, "ns1.", 300, "ns2.example.com."),
			},
			wantIPs:   nil,
			wantNames: []string{"ns1.example.com.", "ns2.example.com."},
		},
		{
			answer: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
				NS(t, "ns1.", 300, "ns2.example.com."),
			},
			wantIPs:   nil,
			wantNames: []string{"ns1.example.com.", "ns2.example.com."},
		},
		{
			authority: []dns.RR{
				NS(t, "ns1.", 300, "ns1.example.com."),
			},
			additional: []dns.RR{
				CNAME(t, "ns1.example.com.", 300, "ns2.example.com."),
				CNAME(t, "ns2.example.com.", 300, "ns1.example.com."),
			},
			wantIPs:   nil,
			wantNames: nil,
		},
		{
			// systemd-resolved does this when asked for A foo.example.com.
			answer: []dns.RR{
				CNAME(t, "foo.example.com.", 300, "bar.example.com."),
				CNAME(t, "bar.example.com.", 300, "baz.example.com."),
				A(t, "baz.example.com.", 300, "192.0.2.1"),
			},
			wantIPs:   []string{"192.0.2.1"},
			wantNames: nil,
		},
	}

	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			m := &dns.Msg{
				Answer: tc.answer,
				Ns:     tc.authority,
				Extra:  tc.additional,
			}

			r := new(resolver)
			r.ip4disabled = tc.ip4disabled
			r.ip6disabled = tc.ip6disabled

			ips, names := r.referrals(m)
			assert.Equal(t, tc.wantIPs, ips, "unexpected ip set")
			assert.Equal(t, tc.wantNames, names, "unexpected name set")
		})
	}
}
