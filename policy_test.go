package dnsresolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestIsPublicSuffix(t *testing.T) {
	cases := []struct {
		fqdn string
		want bool
	}{
		{".", true},
		{"com.", true},
		{"foo.com.", false},
		{"uk.", true},
		{"co.uk.", true},
		{"foo.co.uk.", false},
		{"aero.", true},
		{"airline.aero.", true},
		{"foo.airline.aero.", false},
	}

	for _, tc := range cases {
		t.Run(tc.fqdn, func(t *testing.T) {
			assert.Equal(t, tc.want, isPublicSuffix(tc.fqdn), tc.fqdn)
		})
	}
}

func TestDefaultCachePolicy(t *testing.T) {
	cases := []struct {
		q         dns.Question
		answer    []dns.RR
		authority []dns.RR
		want      time.Duration
	}{
		{
			q: dns.Question{Qtype: dns.TypeA, Name: "bbc.co.uk."},
			authority: []dns.RR{
				NS(t, "uk.", 172800, "nsa.nic.uk."),
			},
			want: 172800 * time.Second,
		},
		{
			q: dns.Question{Qtype: dns.TypeA, Name: "bbc.co.uk."},
			authority: []dns.RR{
				NS(t, "bbc.co.uk.", 172800, "dns1.bbc.co.uk."),
			},
			want: 0,
		},
		{
			q: dns.Question{Qtype: dns.TypeA, Name: "bbc.co.uk."},
			authority: []dns.RR{
				NS(t, "uk.", 172800, "nsa.nic.uk."),
				NS(t, "uk.", 172800, "nsb.nic.uk."),
			},
			want: 172800 * time.Second,
		},
		{
			q: dns.Question{Qtype: dns.TypeA, Name: "bbc.co.uk."},
			authority: []dns.RR{
				NS(t, "uk.", 172800, "nsa.nic.uk."),
				NS(t, "co.uk.", 172800, "nsa.nic.uk."),
			},
			want: 0,
		},
		{
			q: dns.Question{Qtype: dns.TypeA, Name: "bbc.co.uk."},
			authority: []dns.RR{
				NS(t, "uk.", 172800, "nsa.nic.uk."),
				NS(t, "bbc.co.uk.", 172800, "dns1.bbc.co.uk."),
			},
			want: 0,
		},
	}

	t.Parallel()

	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			msg := dns.Msg{}
			msg.Question = append(msg.Question, tc.q)
			msg.Answer = append(msg.Answer, tc.answer...)
			msg.Ns = append(msg.Ns, tc.authority...)

			got := defaultCachePolicy(RecordSet{Raw: msg})
			assert.Equal(t, tc.want, got)
		})
	}
}
