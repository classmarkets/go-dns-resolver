package dnsresolver

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Trace reports all DNS queries that where necessary to retrieve a RecordSet.
// A trace typically starts with a NS query to one of the root name servers,
// but the first time a resolver is used the trace starts with a query to the
// name servers in the operating system to determine the list of root name
// servers.
type Trace struct {
	Queries []*TraceNode
}

// Dump returns a string representation of the trace.
//
// The output is meant for human consumption and may change between releases of
// this package without notice.
//
// Lines starting with a question mark indicate DNS requests. Lines starting
// with an exclamation mark indicate DNS responses. Lines starting with an X
// indicate network errors.
func (t *Trace) Dump() string {
	buf := &bytes.Buffer{}

	for _, n := range t.Queries {
		n.dump(buf, 0)
	}

	return buf.String()
}

type TraceAnswer struct {
	// Record is a single DNS record that appeared in a DNS response, either in
	// the ANSWER or ADDITIONAL section.
	Record dns.RR

	// Next is the DNS query that has been made following this answer. For
	// instance, if this answer is in response to some NS query, the next query
	// may be for an A record set, directed at the server mentioned in Record.
	Next *TraceNode
}

func (a *TraceAnswer) SetNext(node *TraceNode) {
	if a != nil {
		a.Next = node
	}
}

type TraceNode struct {
	Question *dns.Question
	Server   string

	Err     error
	Answers []*TraceAnswer

	RTT time.Duration
}

func (n *TraceNode) addAnswer(record dns.RR) {
	n.Answers = append(n.Answers, &TraceAnswer{
		Record: record,
	})
}

func (n *TraceNode) findAnswer(value string, types ...string) *TraceAnswer {
	return nil // TODO
}

func (n *TraceNode) dump(w io.Writer, depth int) {
	if n == nil {
		return
	}
	io.WriteString(w, strings.Repeat(" ", depth*4))
	fmt.Fprintf(w, "? %s @%s %vms\n", n.fmt(n.Question), n.Server, n.RTT.Milliseconds())
	io.WriteString(w, strings.Repeat(" ", depth*4))
	if n.Err != nil {
		fmt.Fprintf(w, "  X %v", n.Err)
	} else {
		for _, a := range n.Answers {
			fmt.Fprintf(w, "  ! %v\n", n.fmt(a.Record))
			a.Next.dump(w, depth+1)
		}
	}
}

var spaces = regexp.MustCompile(`[\t ]+`)

func (n *TraceNode) fmt(x fmt.Stringer) string {
	s := x.String()
	s = strings.TrimPrefix(s, ";")
	s = spaces.ReplaceAllString(s, " ")

	return s
}
