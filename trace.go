package dnsresolver

import (
	"bytes"
	"errors"
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
	stack   []*TraceNode
}

func (t *Trace) push() {
	if len(t.stack) == 0 {
		t.stack = append(t.stack, t.Queries[len(t.Queries)-1])
	} else {
		root := t.stack[len(t.stack)-1]
		t.stack = append(t.stack, root.Children[len(root.Children)-1])
	}
}

func (t *Trace) pop() {
	if len(t.stack) > 0 {
		t.stack = t.stack[:len(t.stack)-1]
	}
}

func (t *Trace) add(n *TraceNode) {
	if len(t.stack) == 0 {
		t.Queries = append(t.Queries, n)
	} else {
		root := t.stack[len(t.stack)-1]
		root.Children = append(root.Children, n)
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

type TraceNode struct {
	Server string

	Message *dns.Msg
	RTT     time.Duration
	Error   error

	Children []*TraceNode
}

func (n *TraceNode) dump(w io.Writer, depth int) {
	if depth > 20 {
		return
	}
	if n == nil {
		return
	}

	msg := n.Message

	io.WriteString(w, strings.Repeat(" ", depth*4))
	fmt.Fprintf(w, "? %s @%s %vms\n", n.fmt(&msg.Question[0]), n.Server, n.RTT.Milliseconds())

	if n.Error != nil {
		io.WriteString(w, strings.Repeat(" ", depth*4))
		if errors.Is(n.Error, ErrCircular) {
			fmt.Fprintf(w, "  X CYCLE\n")
		} else {
			fmt.Fprintf(w, "  X %v\n", n.Error)
		}
	}
	if msg.Rcode != dns.RcodeSuccess {
		io.WriteString(w, strings.Repeat(" ", depth*4))
		fmt.Fprintf(w, "  X %s\n", dns.RcodeToString[msg.Rcode])
	} else if empty(msg) {
		io.WriteString(w, strings.Repeat(" ", depth*4))
		fmt.Fprintf(w, "  ~ EMPTY\n")
	}

	for _, rr := range append(append(msg.Answer, msg.Ns...), msg.Extra...) {
		io.WriteString(w, strings.Repeat(" ", depth*4))
		fmt.Fprintf(w, "  ! %v\n", n.fmt(rr))

		for _, n := range n.Children {
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
