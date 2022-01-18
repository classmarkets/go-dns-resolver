package dnsresolver

import (
	"context"
	"testing"

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

func TestResolver_SetRootServers_AddressNormalization(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		r := New()

		err := r.SetRootServers("127.0.0.1", "127.0.0.2:5353")

		assert.NoError(t, err)
		assert.Equal(t, r.rootServerAddrs, []string{"127.0.0.1:53", "127.0.0.2:5353"})
	})
	t.Run("unique", func(t *testing.T) {
		r := New()

		err := r.SetRootServers("127.0.0.1", "127.0.0.1:53")

		assert.NoError(t, err)
		assert.Equal(t, r.rootServerAddrs, []string{"127.0.0.1:53"})
	})
	t.Run("invalid", func(t *testing.T) {
		r := New()

		err := r.SetRootServers("127.0.0.1", "localhost:5353")

		assert.EqualError(t, err, "not an ip address: localhost:5353")
		assert.Len(t, r.rootServerAddrs, 0)
	})
}

func TestResolver_DiscoverRootServers(t *testing.T) {
	_, err := New().Query(context.Background(), "A", "google.com")
	assert.NoError(t, err)
}
