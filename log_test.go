package dnsresolver

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func DebugLog(t *testing.T) func(RecordSet, error) {

	f := t.Logf
	//f = log.Printf

	return func(rs RecordSet, err error) {
		q := rs.Raw.Question[0]
		resp := rs.Raw

		f("%s\t@%s %dms (age=%v)\n", strings.TrimPrefix(q.String(), ";"), rs.ServerAddr, rs.RTT.Milliseconds(), rs.Age)

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
