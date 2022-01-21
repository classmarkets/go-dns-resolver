package dnsresolver

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolver_RecordSet_fromResult(t *testing.T) {
	cases := []struct {
		skip   bool
		name   string
		result queryResult
		want   RecordSet
		err    error
	}{
		{
			name: "empty",
			result: queryResult{
				Question: &dns.Question{Name: "example.com.", Qtype: dns.TypeA},
				Response: &dns.Msg{},
			},
			want: RecordSet{},
			err:  ErrNXDomain,
		},
		{
			name: "missing",
			result: queryResult{
				Question: &dns.Question{Name: "example.com.", Qtype: dns.TypeAAAA},
				Response: &dns.Msg{
					Answer: []dns.RR{
						A(t, "example.com.", 300, "192.0.2.1"), // but we requested AAAA
					},
				},
			},
			want: RecordSet{},
			err:  ErrNXDomain,
		},
		{
			name: "trivial",
			result: queryResult{
				Question: &dns.Question{Name: "example.com.", Qtype: dns.TypeA},
				Response: &dns.Msg{
					Answer: []dns.RR{
						A(t, "example.com.", 300, "192.0.2.1"),
					},
				},
			},
			want: RecordSet{
				TTL:    300 * time.Second,
				Values: []string{"192.0.2.1"},
			},
		},
		{
			name: "cname_in_answer",
			result: queryResult{
				Question: &dns.Question{Name: "example.com.", Qtype: dns.TypeA},
				Response: &dns.Msg{
					Answer: []dns.RR{
						CNAME(t, "example.com.", 300, "www.example.com."),
						A(t, "www.example.com.", 200, "192.0.2.1"),
					},
				},
			},
			want: RecordSet{
				TTL:    200 * time.Second,
				Values: []string{"192.0.2.1"},
			},
		},
		{
			name: "cname_in_additional",
			result: queryResult{
				Question: &dns.Question{Name: "example.com.", Qtype: dns.TypeA},
				Response: &dns.Msg{
					Answer: []dns.RR{
						CNAME(t, "example.com.", 300, "www.example.com."),
					},
					Extra: []dns.RR{
						A(t, "www.example.com.", 200, "192.0.2.1"),
					},
				},
			},
			want: RecordSet{
				TTL:    200 * time.Second,
				Values: []string{"192.0.2.1"},
			},
		},
		{
			name: "double_cname",
			result: queryResult{
				Question: &dns.Question{Name: "example.com.", Qtype: dns.TypeA},
				Response: &dns.Msg{
					Answer: []dns.RR{
						CNAME(t, "example.com.", 300, "www.example.com."),
						A(t, "www.example.com.", 200, "192.0.2.1"),
						A(t, "www.example.com.", 199, "192.0.2.2"),
					},
				},
			},
			want: RecordSet{
				TTL: 199 * time.Second,
				Values: []string{
					"192.0.2.1",
					"192.0.2.2",
				},
			},
		},
		{
			name: "recursive_cname",
			result: queryResult{
				Question: &dns.Question{Name: "example.com.", Qtype: dns.TypeA},
				Response: &dns.Msg{
					Answer: []dns.RR{
						CNAME(t, "example.com.", 300, "www.example.com."),
						CNAME(t, "www.example.com.", 199, "foo.www.example.com."),
						CNAME(t, "foo.www.example.com.", 200, "bar.www.example.com."),
						A(t, "bar.www.example.com.", 200, "192.0.2.1"),
						A(t, "bar.www.example.com.", 200, "192.0.2.2"),
						A(t, "bar.www.example.com.", 200, "192.0.2.3"),
					},
				},
			},
			want: RecordSet{
				TTL: 199 * time.Second,
				Values: []string{
					"192.0.2.1",
					"192.0.2.2",
					"192.0.2.3",
				},
			},
		},
		{
			name: "circular_cname",
			result: queryResult{
				Question: &dns.Question{Name: "example.com.", Qtype: dns.TypeA},
				Response: &dns.Msg{
					Answer: []dns.RR{
						CNAME(t, "example.com.", 300, "www.example.com."),
						CNAME(t, "www.example.com.", 199, "example.com."),
					},
				},
			},
			want: RecordSet{},
			err:  ErrCircular,
		},
	}

	t.Parallel()
	for _, tc := range cases {
		if tc.skip {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			var set RecordSet
			err := set.fromResult(tc.result)

			if tc.err != nil {
				require.True(t, errors.Is(err, tc.err))
				return
			}

			require.NoError(t, err)

			assert.Equal(t, tc.want.Values, set.Values)
			assert.Equal(t, tc.want.TTL, set.TTL)
		})
	}
}
