package dnsresolver

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func DebugLog(t *testing.T) func(queryResult) {

	f := t.Logf
	//f = log.Printf

	return func(result queryResult) {
		q := result.Question
		resp := result.Response
		err := result.Error

		f("%s\t@%s %dms\n", strings.TrimPrefix(q.String(), ";"), result.ServerAddr, result.RTT.Milliseconds())
		if err != nil {
			f("\t%v\n", err)
		} else if resp.Rcode != dns.RcodeSuccess {
			f("\t%s\n", dns.RcodeToString[resp.Rcode])
		} else {
			if len(resp.Answer) > 0 {
				f("\tANSWER\n")
				for _, rr := range resp.Answer {
					f("\t\t%s\n", rr.String())
				}
			}
			if len(resp.Ns) > 0 {
				f("\tAUTHORITY\n")
				for _, rr := range resp.Ns {
					f("\t\t%s\n", rr.String())
				}
			}
			if len(resp.Extra) > 0 {
				f("\tADDITIONAL\n")
				for _, rr := range resp.Extra {
					f("\t\t%s\n", rr.String())
				}
			}
		}
	}
}
