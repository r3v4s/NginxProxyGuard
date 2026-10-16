package dnsentry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// fakeLookuper answers from fixed tables and records every call as
// "<cname|ip4|ip6> <host>", with its context's deadline. cnames answers
// LookupCNAME by queried host with successive answers (the last one repeats);
// a host without an entry answers with itself, as a name without a CNAME
// does. An error in errs (by "cname", "cname <host>", "ip4" or "ip6") wins.
// Each LookupCNAME takes cnameWait. With meet set, each family lookup waits
// up to two seconds for the other family's lookup to start, and overlaps
// counts the lookups that saw it.
type fakeLookuper struct {
	mu        sync.Mutex
	calls     []string
	left      []time.Duration // time left on each call's context
	deadlines []time.Time     // each call's context deadline (zero when none)
	addrs     map[string][]netip.Addr
	errs      map[string]error
	cnames    map[string][]string
	cnameWait time.Duration
	meet      *sync.WaitGroup
	overlaps  int
}

func (f *fakeLookuper) note(call string, ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	left := time.Duration(-1)
	dl, ok := ctx.Deadline()
	if ok {
		left = time.Until(dl)
	}
	f.left = append(f.left, left)
	f.deadlines = append(f.deadlines, dl)
}

func (f *fakeLookuper) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.note(network+" "+host, ctx)
	if f.meet != nil {
		f.meet.Done()
		met := make(chan struct{})
		go func() { f.meet.Wait(); close(met) }()
		select {
		case <-met:
			f.mu.Lock()
			f.overlaps++
			f.mu.Unlock()
		case <-time.After(2 * time.Second):
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := f.errs[network]; err != nil {
		return nil, err
	}
	return f.addrs[network], nil
}

func (f *fakeLookuper) LookupCNAME(ctx context.Context, host string) (string, error) {
	f.note("cname "+host, ctx)
	time.Sleep(f.cnameWait)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := f.errs["cname"]; err != nil {
		return "", err
	}
	if err := f.errs["cname "+host]; err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	answers := f.cnames[host]
	if len(answers) == 0 {
		return host, nil
	}
	if len(answers) > 1 {
		f.cnames[host] = answers[1:]
	}
	return answers[0], nil
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func TestClassifyLookupError(t *testing.T) {
	const server = "192.0.2.53:53" // the resolver's address is in every DNSError
	cases := []struct {
		name          string
		err           error
		outcome, code string
	}{
		{"a: hosts-file name without this family", &net.AddrError{Err: "no suitable address found", Addr: "partner.e2e.example."}, "notfound", "not_found"},
		{"b: NXDOMAIN or NODATA", &net.DNSError{Err: "no such host", Name: "partner.example.com.", Server: server, IsNotFound: true}, "notfound", "not_found"},
		{"b before f", &net.DNSError{Err: "no such host", Server: server, IsNotFound: true, IsTemporary: true}, "notfound", "not_found"},
		{"c: no reply", &net.DNSError{Err: "i/o timeout", Server: server, IsTimeout: true, IsTemporary: true, UnwrapErr: context.DeadlineExceeded}, "transient", "timeout"},
		{"c: the lookup's deadline", fmt.Errorf("lookup: %w", context.DeadlineExceeded), "transient", "timeout"},
		{"c: the check was stopped", &net.DNSError{Err: "operation was canceled", Name: "partner.example.com.", UnwrapErr: context.Canceled}, "transient", "timeout"},
		{"d: SERVFAIL", &net.DNSError{Err: "server misbehaving", Server: server, IsTemporary: true}, "transient", "servfail"},
		{"e: REFUSED and other rcodes", &net.DNSError{Err: "server misbehaving", Server: server}, "transient", "refused"},
		{"f: no route", &net.DNSError{Err: "dial udp " + server + ": connect: network is unreachable", Server: server, IsTemporary: true}, "transient", "network"},
		{"g: lame referral", &net.DNSError{Err: "lame referral", Server: server}, "transient", "servfail"},
		{"g: unreadable reply", &net.DNSError{Err: "cannot unmarshal DNS message", Server: server}, "transient", "servfail"},
		{"g: another address error", &net.AddrError{Err: "missing port in address", Addr: server}, "transient", "servfail"},
		{"g: anything else", errors.New("lookup partner.example.com. on " + server + ": boom"), "transient", "servfail"},
	}
	for _, tc := range cases {
		outcome, code := ClassifyLookupError(tc.err)
		if outcome != tc.outcome || code != tc.code {
			t.Errorf("%s: ClassifyLookupError = %q, %q; want %q, %q", tc.name, outcome, code, tc.outcome, tc.code)
		}
		// Only fixed codes are stored: never the resolver's
		// address, never a port, never the error text.
		if strings.ContainsAny(code, ":/. ") || strings.Contains(code, "192.0.2") {
			t.Errorf("%s: code %q carries error detail", tc.name, code)
		}
	}
	if outcome, code := ClassifyLookupError(nil); outcome != "ok" || code != "" {
		t.Errorf("ClassifyLookupError(nil) = %q, %q", outcome, code)
	}
}

func TestResolveAsksCNAMEThenBothFamiliesThenCNAME(t *testing.T) {
	f := &fakeLookuper{
		addrs:  map[string][]netip.Addr{"ip4": addrs("203.0.113.10"), "ip6": addrs("2001:db8::10")},
		cnames: map[string][]string{"alias.example.com.": {"mid.example.com."}, "mid.example.com.": {"final.example.com."}},
		meet:   &sync.WaitGroup{},
	}
	f.meet.Add(2)
	const perLookup = 3 * time.Second
	Resolve(context.Background(), f, "alias.example.com", perLookup)

	walk := []string{"cname alias.example.com.", "cname mid.example.com.", "cname final.example.com."}
	if len(f.calls) != 8 || !slices.Equal(f.calls[:3], walk) || !slices.Equal(f.calls[5:], walk) {
		t.Fatalf("calls = %q, want the CNAME chain walked to its end first and last, by absolute names", f.calls)
	}
	middle := map[string]bool{f.calls[3]: true, f.calls[4]: true}
	if !middle["ip4 alias.example.com."] || !middle["ip6 alias.example.com."] {
		t.Fatalf("calls = %q, want one ip4 and one ip6 lookup of the name itself between the walks", f.calls)
	}
	if f.overlaps != 2 {
		t.Errorf("the two family lookups did not run at the same time (overlaps %d)", f.overlaps)
	}
	for i, left := range f.left {
		if left <= 0 || left > perLookup {
			t.Errorf("call %q had %v left on its context, want a timeout of at most %v", f.calls[i], left, perLookup)
		}
	}
}

// A slow family must not eat the other's time, so each address lookup has
// its own timeout. A long or slow chain must not take one timeout per hop, so
// the steps of a walk share one.
func TestResolveGivesEachWalkOneTimeoutAndEachFamilyItsOwn(t *testing.T) {
	f := &fakeLookuper{
		addrs:     map[string][]netip.Addr{"ip4": addrs("203.0.113.10")},
		cnames:    map[string][]string{"alias.example.com.": {"mid.example.com."}, "mid.example.com.": {"final.example.com."}},
		cnameWait: 5 * time.Millisecond, // a deadline set at a later step is a later deadline
	}
	Resolve(context.Background(), f, "alias.example.com", 3*time.Second)
	if len(f.deadlines) != 8 {
		t.Fatalf("calls = %q, want a walk of three steps, the two family lookups, then the walk again", f.calls)
	}
	before, families, after := f.deadlines[:3], f.deadlines[3:5], f.deadlines[5:]
	for _, walk := range [][]time.Time{before, after} {
		if !walk[1].Equal(walk[0]) || !walk[2].Equal(walk[0]) {
			t.Errorf("walk deadlines %v, want one deadline for all the steps of a walk", walk)
		}
	}
	for i, d := range families {
		if !d.After(before[0]) {
			t.Errorf("%q has the first walk's deadline, want its own", f.calls[3+i])
		}
	}
	if !after[0].After(before[0]) {
		t.Errorf("the second walk has the first walk's deadline, want its own")
	}
}

// Go's resolver answers one LookupCNAME of a name two or more hops from the
// end of its chain from whichever of its parallel replies comes first: the
// chain's end from the address reply, its first hop from the CNAME reply. A
// walk on from either answer ends at the same name.
func TestResolveFollowsTheCNAMEChainToItsEnd(t *testing.T) {
	for _, answers := range [][]string{
		{"mid.example.com.", "mid.example.com."},
		{"final.example.com.", "final.example.com."},
		{"mid.example.com.", "final.example.com."},
		{"final.example.com.", "mid.example.com."},
	} {
		f := &fakeLookuper{
			addrs: map[string][]netip.Addr{"ip4": addrs("203.0.113.10")},
			cnames: map[string][]string{
				"alias.example.com.": answers, // the first walk's answer, then the second walk's
				"mid.example.com.":   {"final.example.com."},
			},
		}
		a := Resolve(context.Background(), f, "alias.example.com", time.Second)
		o, _ := Observe(a, docsAsPublic(), 4)
		if a.CNAMEBefore != "final.example.com" || a.CNAMEAfter != "final.example.com" || !o.CNAMEOK || o.Canonical != "final.example.com" {
			t.Errorf("alias answering %q: CNAME %q then %q, CNAMEOK %v %q; want final.example.com both times", answers, a.CNAMEBefore, a.CNAMEAfter, o.CNAMEOK, o.Canonical)
		}
	}
}

// A chain whose end changes between the two walks is a change, also when the
// name's own CNAME record stays the same.
func TestResolveSeesAChangeAtTheEndOfTheChain(t *testing.T) {
	f := &fakeLookuper{
		addrs: map[string][]netip.Addr{"ip4": addrs("203.0.113.10")},
		cnames: map[string][]string{
			"alias.example.com.": {"mid.example.com."},
			"mid.example.com.":   {"final.example.com.", "other.example.com."},
		},
	}
	a := Resolve(context.Background(), f, "alias.example.com", time.Second)
	if a.CNAMEBefore != "final.example.com" || a.CNAMEAfter != "other.example.com" {
		t.Errorf("CNAME = %q, %q; want final.example.com, then other.example.com", a.CNAMEBefore, a.CNAMEAfter)
	}
	if o, _ := Observe(a, docsAsPublic(), 4); o.CNAMEOK || o.Canonical != "" {
		t.Errorf("CNAME = %v %q, want no agreed canonical name", o.CNAMEOK, o.Canonical)
	}
}

// A walk that comes back to a name it has seen, follows more than eight
// hops, or fails a lookup on the way gives no canonical name, like a failed
// lookup.
func TestResolveGivesUpOnALoopALongChainOrAFailedStep(t *testing.T) {
	chain := func(hops int) map[string][]string {
		m := map[string][]string{}
		for i := 0; i < hops; i++ {
			m[fmt.Sprintf("hop%d.example.com.", i)] = []string{fmt.Sprintf("hop%d.example.com.", i+1)}
		}
		return m
	}
	a := Resolve(context.Background(), &fakeLookuper{cnames: chain(8)}, "hop0.example.com", time.Second)
	if a.CNAMEBefore != "hop8.example.com" || a.CNAMEAfter != "hop8.example.com" {
		t.Errorf("eight hops: CNAME %q, %q; want hop8.example.com, the end", a.CNAMEBefore, a.CNAMEAfter)
	}
	a = Resolve(context.Background(), &fakeLookuper{cnames: chain(9)}, "hop0.example.com", time.Second)
	if a.CNAMEBefore != "" || a.CNAMEAfter != "" {
		t.Errorf("nine hops: CNAME %q, %q; want none", a.CNAMEBefore, a.CNAMEAfter)
	}

	loop := &fakeLookuper{cnames: map[string][]string{"a.example.com.": {"b.example.com."}, "b.example.com.": {"a.example.com."}}}
	a = Resolve(context.Background(), loop, "a.example.com", time.Second)
	if a.CNAMEBefore != "" || a.CNAMEAfter != "" {
		t.Errorf("a loop: CNAME %q, %q; want none", a.CNAMEBefore, a.CNAMEAfter)
	}
	// It stops when it comes back to a name, not at the hop limit.
	if n := strings.Count(strings.Join(loop.calls, "\n"), "cname "); n != 4 {
		t.Errorf("a loop took %d CNAME lookups, want two for each walk: %q", n, loop.calls)
	}

	failing := &fakeLookuper{
		cnames: map[string][]string{"alias.example.com.": {"mid.example.com."}},
		errs:   map[string]error{"cname mid.example.com.": &net.DNSError{Err: "server misbehaving", Server: "192.0.2.53:53", IsTemporary: true}},
	}
	a = Resolve(context.Background(), failing, "alias.example.com", time.Second)
	if a.CNAMEBefore != "" || a.CNAMEAfter != "" {
		t.Errorf("a failed second step: CNAME %q, %q; want none", a.CNAMEBefore, a.CNAMEAfter)
	}
}

// What Go's resolver returns for a hosts-file name (::ffff: IPv4, an
// AddrError for the missing family, the queried name as its canonical name)
// and what it returns through DNS end up in one shape.
func TestResolveNormalizesTheAnswer(t *testing.T) {
	f := &fakeLookuper{
		addrs: map[string][]netip.Addr{
			"ip4": addrs("198.51.100.7", "::ffff:100.64.32.10", "100.64.32.10"),
			"ip6": addrs("2001:db8::10", "2001:db8::10"),
		},
		cnames: map[string][]string{"partner.example.com.": {"Partner.Example.COM."}},
	}
	a := Resolve(context.Background(), f, "partner.example.com", time.Second)
	if len(f.calls) != 4 {
		t.Errorf("calls = %q, want one CNAME lookup for each walk: the name answers with itself", f.calls)
	}
	if a.V4.Outcome != "ok" || fmt.Sprint(a.V4.Addrs) != "[100.64.32.10 198.51.100.7]" || !a.V4.Addrs[0].Is4() {
		t.Errorf("V4 = %+v, want the two addresses unmapped, sorted and once each", a.V4)
	}
	if a.V6.Outcome != "ok" || fmt.Sprint(a.V6.Addrs) != "[2001:db8::10]" {
		t.Errorf("V6 = %+v", a.V6)
	}
	if a.CNAMEBefore != "partner.example.com" || a.CNAMEAfter != "partner.example.com" {
		t.Errorf("CNAME = %q, %q; want lower case without the trailing dot", a.CNAMEBefore, a.CNAMEAfter)
	}
}

func TestResolveReportsEachFamilyOnItsOwn(t *testing.T) {
	f := &fakeLookuper{
		addrs: map[string][]netip.Addr{"ip4": addrs("::ffff:100.64.32.10")},
		errs: map[string]error{
			"ip6":   &net.AddrError{Err: "no suitable address found", Addr: "partner.e2e.example."},
			"cname": &net.DNSError{Err: "server misbehaving", Server: "192.0.2.53:53", IsTemporary: true},
		},
	}
	a := Resolve(context.Background(), f, "partner.e2e.example", time.Second)
	if a.V4.Outcome != "ok" || a.V4.Addrs[0] != netip.MustParseAddr("100.64.32.10") {
		t.Errorf("V4 = %+v", a.V4)
	}
	if a.V6.Outcome != "notfound" || a.V6.Code != "not_found" {
		t.Errorf("V6 = %+v, want notfound: a hosts-file name without IPv6 has none (not a failing lookup)", a.V6)
	}
	if a.CNAMEBefore != "" || a.CNAMEAfter != "" {
		t.Errorf("a failed CNAME lookup gave %q, %q; want empty", a.CNAMEBefore, a.CNAMEAfter)
	}

	f.errs = map[string]error{"ip6": &net.DNSError{Err: "i/o timeout", IsTimeout: true, IsTemporary: true}}
	a = Resolve(context.Background(), f, "partner.e2e.example", time.Second)
	if a.V4.Outcome != "ok" || a.V6.Outcome != "transient" || a.V6.Code != "timeout" {
		t.Errorf("v6 timeout: V4 %+v V6 %+v", a.V4, a.V6)
	}
}

// A check that is stopped still gets an answer for every name: a timeout,
// which keeps what is published.
func TestResolveAnswersWhenTheContextHasEnded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fakeLookuper{addrs: map[string][]netip.Addr{"ip4": addrs("203.0.113.10")}}
	a := Resolve(ctx, f, "partner.example.com", time.Second)
	if a.V4.Outcome != "transient" || a.V4.Code != "timeout" || a.V6.Outcome != "transient" || a.CNAMEBefore != "" || a.CNAMEAfter != "" {
		t.Fatalf("answer = %+v, want two transient timeouts and no canonical name", a)
	}
}

func TestNormalizeCanonical(t *testing.T) {
	for in, want := range map[string]string{
		"Partner.Example.COM.": "partner.example.com",
		"edge.example.net":     "edge.example.net",
		"a.example.com..":      "a.example.com.",
		".":                    "",
		"":                     "",
	} {
		if got := NormalizeCanonical(in); got != want {
			t.Errorf("NormalizeCanonical(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSystemLookuperOnAHostsFileName runs only in a throwaway container
// without network that has partner.e2e.example in /etc/hosts as
// 100.64.32.10 (what the E2E stack's extra_hosts writes). It pins what the
// fakes above assume of Go's real resolver.
func TestSystemLookuperOnAHostsFileName(t *testing.T) {
	if os.Getenv("NPG_TEST_HOSTS_FILE") != "1" {
		t.Skip("real check only: NPG_TEST_HOSTS_FILE=1 in a --network none container with partner.e2e.example in /etc/hosts")
	}
	ctx := context.Background()
	o, notes := Observe(Resolve(ctx, SystemLookuper(), "partner.e2e.example", 5*time.Second), model.DefaultAddressPolicy(), 4)
	if o.V4.Outcome != "ok" || fmt.Sprint(o.V4.Addrs) != "[100.64.32.10]" || !notes.CGNAT {
		t.Errorf("v4 = %+v (cgnat %v), want ok [100.64.32.10]: the hosts file's ::ffff: form unmapped", o.V4, notes.CGNAT)
	}
	if o.V6.Outcome != "notfound" || o.V6.Code != "not_found" {
		t.Errorf("v6 = %+v, want notfound (row a), not a failing lookup", o.V6)
	}
	if !o.CNAMEOK || o.Canonical != "partner.e2e.example" {
		t.Errorf("CNAME = %v %q, want the name itself", o.CNAMEOK, o.Canonical)
	}
	m := Resolve(ctx, SystemLookuper(), "missing.e2e.example", 5*time.Second)
	if m.V4.Outcome != "transient" || m.V6.Outcome != "transient" || m.CNAMEBefore != "" {
		t.Errorf("missing name = %+v, want transient (never notfound without a network)", m)
	}
	t.Logf("missing name codes: v4 %s, v6 %s", m.V4.Code, m.V6.Code)
}
