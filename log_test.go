package dnsresolver

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

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
