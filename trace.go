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
	idx     map[dns.RR]*TraceAnswer

	roots []*TraceAnswer
}

func (t *Trace) pushRoot(root dns.RR) {
	a := t.idx[root]
	if a == nil {
		panic("pushRoot: no answer for trace root")
	}

	t.roots = append(t.roots, a)
}
func (t *Trace) popRoot() {
	if len(t.roots) == 0 {
		panic("popRoot: empty stack")
	}

	t.roots = t.roots[:len(t.roots)-1]
}

func (t *Trace) add(result queryResult, prev dns.RR) {
	n := &TraceNode{
		Question: result.Question,
		Server:   result.ServerAddr,
		Err:      result.Error,
		RTT:      result.RTT,
	}

	if parent := t.idx[prev]; parent != nil {
		parent.Next = append(parent.Next, n)
	} else if len(t.roots) > 0 {
		parent := t.roots[len(t.roots)-1]
		parent.Next = append(parent.Next, n)
	} else {
		t.Queries = append(t.Queries, n)
	}

	if result.Response == nil {
		return
	}

	n.Code = result.Response.Rcode

	all := result.Response.Answer
	all = append(all, result.Response.Ns...)
	all = append(all, result.Response.Extra...)

	for _, rr := range all {
		answer := &TraceAnswer{
			Record: rr,
		}
		if t.idx == nil {
			t.idx = map[dns.RR]*TraceAnswer{}
		}
		n.Answers = append(n.Answers, answer)
		t.idx[rr] = answer
	}
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
	Next []*TraceNode
}

type TraceNode struct {
	Question *dns.Question
	Server   string

	Err     error
	Code    int
	Answers []*TraceAnswer

	RTT time.Duration
}

func (n *TraceNode) dump(w io.Writer, depth int) {
	if n == nil {
		return
	}

	io.WriteString(w, strings.Repeat(" ", depth*4))
	fmt.Fprintf(w, "? %s @%s %vms\n", n.fmt(n.Question), n.Server, n.RTT.Milliseconds())

	if n.Err != nil {
		io.WriteString(w, strings.Repeat(" ", depth*4))
		fmt.Fprintf(w, "  X %v\n", n.Err)
	}

	if n.Code != dns.RcodeSuccess {
		io.WriteString(w, strings.Repeat(" ", depth*4))
		fmt.Fprintf(w, "  X %s\n", dns.RcodeToString[n.Code])
	} else if len(n.Answers) == 0 {
		io.WriteString(w, strings.Repeat(" ", depth*4))
		fmt.Fprintf(w, "  ~ EMPTY\n")
	}

	for _, a := range n.Answers {
		io.WriteString(w, strings.Repeat(" ", depth*4))
		fmt.Fprintf(w, "  ! %v\n", n.fmt(a.Record))

		for _, n := range a.Next {
			n.dump(w, depth+1)
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
