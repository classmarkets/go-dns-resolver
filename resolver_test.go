package dnsresolver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestResolver_WithZoneServer_AddressNormalization(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		r := New()

		err := r.WithZoneServer("example.com", []string{"127.0.0.1", "127.0.0.2:5353"})

		assert.NoError(t, err)
		assert.Equal(t, r.zoneServers["example.com"], []string{"127.0.0.1:53", "127.0.0.2:5353"})
	})
	t.Run("unique", func(t *testing.T) {
		r := New()

		err := r.WithZoneServer("example.com", []string{"127.0.0.1", "127.0.0.1:53"})

		assert.NoError(t, err)
		assert.Equal(t, r.zoneServers["example.com"], []string{"127.0.0.1:53"})
	})
	t.Run("invalid", func(t *testing.T) {
		r := New()

		err := r.WithZoneServer("example.com", []string{"127.0.0.1", "localhost:5353"})

		assert.EqualError(t, err, "not an ip address: localhost:5353")
		assert.Len(t, r.zoneServers, 0)
	})
}

func TestResolver_SetSystemServers_AddressNormalization(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		r := New()

		err := r.SetSystemServers("127.0.0.1", "127.0.0.2:5353")

		assert.NoError(t, err)
		assert.Equal(t, r.systemServerAddrs, []string{"127.0.0.1:53", "127.0.0.2:5353"})
	})
	t.Run("unique", func(t *testing.T) {
		r := New()

		err := r.SetSystemServers("127.0.0.1", "127.0.0.1:53")

		assert.NoError(t, err)
		assert.Equal(t, r.systemServerAddrs, []string{"127.0.0.1:53"})
	})
	t.Run("invalid", func(t *testing.T) {
		r := New()

		err := r.SetSystemServers("127.0.0.1", "localhost:5353")

		assert.EqualError(t, err, "not an ip address: localhost:5353")
		assert.Len(t, r.systemServerAddrs, 0)
	})
}

func TestResolver_DiscoverRootServers(t *testing.T) {
	return
	r := New()
	r.ip6disabled = true
	r.logFunc = DebugLog(t)
	//rs, err := r.Query(context.Background(), "A", "google.com")
	rs, err := r.Query(context.Background(), "A", "cmcdn.de")
	t.Logf("Trace:\n" + rs.Trace.Dump())
	assert.NoError(t, err)
}

func TestResolver_Query_SimpleARecord(t *testing.T) {
	r := New()
	r.defaultPort = "5354"
	r.logFunc = DebugLog(t)

	rootSrv := NewRootServer(t, "127.0.0.250:"+r.defaultPort, r)
	comSrv := NewTestServer(t, "127.0.0.100:"+r.defaultPort)
	expSrv := NewTestServer(t, "127.0.0.101:"+r.defaultPort)

	rootSrv.ExpectQuery("A www.example.com.").DelegateTo(comSrv.IP())
	comSrv.ExpectQuery("A www.example.com.").DelegateTo(expSrv.IP()).ViaAuthoritySection()
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
	assert.Equal(t, "127.0.0.101:5354", rs.NameServerAddress)
	assert.Equal(t, rs.Age, -1*time.Second)
	assert.Greater(t, rs.RTT, time.Duration(0))

	wantTrace := strings.TrimSpace(`
? . IN NS @127.0.0.250:5354 0ms
  ! . 321 IN NS self.test.
  ! self.test. 321 IN A 127.0.0.250
    ? www.example.com. IN A @127.0.0.250:5354 0ms
      ! com. 321 IN NS ns1.test.
      ! ns1.test. 321 IN A 127.0.0.100
        ? www.example.com. IN A @127.0.0.100:5354 0ms
          ! com. 321 IN NS ns1.test.
          ! ns1.test. 321 IN A 127.0.0.101
            ? www.example.com. IN A @127.0.0.101:5354 0ms
              ! www.example.com. 321 IN A 192.0.2.0
              ! www.example.com. 321 IN A 192.0.2.1
	`) + "\n"

	assert.Equal(t, wantTrace, rs.Trace.Dump())
}

func TestResolver_Query_Fallback(t *testing.T) {
	r := New()
	r.defaultPort = "5354"
	r.logFunc = DebugLog(t)

	rootSrv := NewRootServer(t, "127.0.0.250:"+r.defaultPort, r)
	comSrv := NewTestServer(t, "127.0.0.100:"+r.defaultPort)
	errSrv := NewTestServer(t, "127.0.0.101:"+r.defaultPort)
	expSrv := NewTestServer(t, "127.0.0.102:"+r.defaultPort)

	rootSrv.ExpectQuery("A www.example.com.").DelegateTo(comSrv.IP())
	comSrv.ExpectQuery("A www.example.com.").DelegateTo(errSrv.IP(), expSrv.IP())
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
	assert.Equal(t, "127.0.0.102:5354", rs.NameServerAddress)

	wantTrace := strings.TrimSpace(`
? . IN NS @127.0.0.250:5354 0ms
  ! . 321 IN NS self.test.
  ! self.test. 321 IN A 127.0.0.250
    ? www.example.com. IN A @127.0.0.250:5354 0ms
      ! com. 321 IN NS ns1.test.
      ! ns1.test. 321 IN A 127.0.0.100
        ? www.example.com. IN A @127.0.0.100:5354 0ms
          ! com. 321 IN NS ns1.test.
          ! com. 321 IN NS ns2.test.
          ! ns1.test. 321 IN A 127.0.0.101
            ? www.example.com. IN A @127.0.0.101:5354 0ms
              X SERVFAIL
          ! ns2.test. 321 IN A 127.0.0.102
            ? www.example.com. IN A @127.0.0.102:5354 0ms
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

	rootSrv := NewRootServer(t, "127.0.0.250:"+r.defaultPort, r)
	comSrv := NewTestServer(t, "127.0.0.100:"+r.defaultPort)
	expSrv := NewTestServer(t, "127.0.0.101:"+r.defaultPort)

	rootSrv.ExpectQuery("A example.com.").DelegateTo(comSrv.IP())
	comSrv.ExpectQuery("A example.com.").DelegateTo(expSrv.IP())
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
	assert.Equal(t, "127.0.0.101:5354", rs.NameServerAddress)
	assert.Equal(t, rs.Age, -1*time.Second)
	assert.Greater(t, rs.RTT, time.Duration(0))

	wantTrace := strings.TrimSpace(`
? . IN NS @127.0.0.250:5354 0ms
  ! . 321 IN NS self.test.
  ! self.test. 321 IN A 127.0.0.250
    ? example.com. IN A @127.0.0.250:5354 0ms
      ! com. 321 IN NS ns1.test.
      ! ns1.test. 321 IN A 127.0.0.100
        ? example.com. IN A @127.0.0.100:5354 0ms
          ! com. 321 IN NS ns1.test.
          ! ns1.test. 321 IN A 127.0.0.101
            ? example.com. IN A @127.0.0.101:5354 0ms
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

	rootSrv := NewRootServer(t, "127.0.0.250:"+r.defaultPort, r)
	comSrv := NewTestServer(t, "127.0.0.100:"+r.defaultPort)
	netSrv := NewTestServer(t, "127.0.0.101:"+r.defaultPort)
	expSrv := NewTestServer(t, "127.0.0.102:"+r.defaultPort)

	rootSrv.ExpectQuery("A example.com.").DelegateTo(comSrv.IP())
	comSrv.ExpectQuery("A example.com.").DelegateTo("ns1.test.net.")
	rootSrv.ExpectQuery("AAAA ns1.test.net.").DelegateTo(netSrv.IP())
	rootSrv.ExpectQuery("A ns1.test.net.").DelegateTo(netSrv.IP())
	netSrv.ExpectQuery("AAAA ns1.test.net.").Respond()
	netSrv.ExpectQuery("A ns1.test.net.").Respond().
		Answer(
			A(t, "ns1.test.net.", 321, expSrv.IP()),
		)
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
	assert.Equal(t, "127.0.0.102:5354", rs.NameServerAddress)
	assert.Equal(t, rs.Age, -1*time.Second)
	assert.Greater(t, rs.RTT, time.Duration(0))

	wantTrace := strings.TrimSpace(`
? . IN NS @127.0.0.250:5354 0ms
  ! . 321 IN NS self.test.
  ! self.test. 321 IN A 127.0.0.250
    ? example.com. IN A @127.0.0.250:5354 0ms
      ! com. 321 IN NS ns1.test.
      ! ns1.test. 321 IN A 127.0.0.100
        ? example.com. IN A @127.0.0.100:5354 0ms
          ! com. 321 IN NS ns1.test.net.
            ? . IN NS @127.0.0.250:5354 0ms
              ! . 321 IN NS self.test.
              ! self.test. 321 IN A 127.0.0.250
                ? ns1.test.net. IN AAAA @127.0.0.250:5354 0ms
                  ! com. 321 IN NS ns1.test.
                  ! ns1.test. 321 IN A 127.0.0.101
                    ? ns1.test.net. IN AAAA @127.0.0.101:5354 0ms
                      ~ EMPTY
            ? . IN NS @127.0.0.250:5354 0ms
              ! . 321 IN NS self.test.
              ! self.test. 321 IN A 127.0.0.250
                ? ns1.test.net. IN A @127.0.0.250:5354 0ms
                  ! com. 321 IN NS ns1.test.
                  ! ns1.test. 321 IN A 127.0.0.101
                    ? ns1.test.net. IN A @127.0.0.101:5354 0ms
                      ! ns1.test.net. 321 IN A 127.0.0.102
                        ? example.com. IN A @127.0.0.102:5354 0ms
                          ! example.com. 321 IN A 192.0.2.0
	`) + "\n"

	assert.Equal(t, wantTrace, rs.Trace.Dump())
}
