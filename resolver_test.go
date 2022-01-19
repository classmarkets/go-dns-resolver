package dnsresolver

import (
	"context"
	"testing"
	"time"

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
	_, err := New().Query(context.Background(), "A", "google.com")
	assert.NoError(t, err)
}

func TestResolver_Query_SimpleARecord(t *testing.T) {
	r := New()

	NewLab(t, r, map[string]string{
		"example.com": `
			@ 321 IN A 192.0.2.0
			;@ 321 IN A 192.0.2.1
		`,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	rs, err := r.Query(ctx, "A", "example.com")
	assert.NoError(t, err)

	assert.Equal(t, "example.com", rs.Name)
	assert.Equal(t, "A", rs.Type)
	assert.Equal(t, 321*time.Second, rs.TTL)
	assert.Equal(t, []string{"192.0.2.0"}, rs.Values) // TODO: , "192.0.2.1"})
	assert.Equal(t, "127.0.0.101:5354", rs.NameServerAddress)
	assert.Equal(t, rs.Age, -1*time.Second)
	// TODO: RTT > 0 assert.Equal(t, rs.RTT, -1*time.Second)
	// TODO: Trace
}
