package dnsentry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// fakeLookuper answers from fixed tables and records every call as
// "<cname|ip4|ip6> <host>". cnames answers successive LookupCNAME calls (the
// last one repeats); an error in errs (by "cname", "ip4" or "ip6") wins.
// With meet set, each family lookup waits up to two seconds for the other
// family's lookup to start, and overlaps counts the lookups that saw it.
type fakeLookuper struct {
	mu       sync.Mutex
	calls    []string
	left     []time.Duration // time left on each call's context
	addrs    map[string][]netip.Addr
	errs     map[string]error
	cnames   []string
	meet     *sync.WaitGroup
	overlaps int
}

func (f *fakeLookuper) note(call string, ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	left := time.Duration(-1)
	if dl, ok := ctx.Deadline(); ok {
		left = time.Until(dl)
	}
	f.left = append(f.left, left)
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
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := f.errs["cname"]; err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cnames) == 0 {
		return host, nil
	}
	c := f.cnames[0]
	if len(f.cnames) > 1 {
		f.cnames = f.cnames[1:]
	}
	return c, nil
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
		addrs: map[string][]netip.Addr{"ip4": addrs("203.0.113.10"), "ip6": addrs("2001:db8::10")},
		meet:  &sync.WaitGroup{},
	}
	f.meet.Add(2)
	const perLookup = 3 * time.Second
	Resolve(context.Background(), f, "partner.example.com", perLookup)

	if len(f.calls) != 4 || f.calls[0] != "cname partner.example.com." || f.calls[3] != "cname partner.example.com." {
		t.Fatalf("calls = %q, want the CNAME lookup first and last, for the absolute name", f.calls)
	}
	middle := map[string]bool{f.calls[1]: true, f.calls[2]: true}
	if !middle["ip4 partner.example.com."] || !middle["ip6 partner.example.com."] {
		t.Fatalf("calls = %q, want one ip4 and one ip6 lookup between the CNAME lookups", f.calls)
	}
	if f.overlaps != 2 {
		t.Errorf("the two family lookups did not run at the same time (overlaps %d)", f.overlaps)
	}
	for i, left := range f.left {
		if left <= 0 || left > perLookup {
			t.Errorf("call %q had %v left on its context, want its own timeout of at most %v", f.calls[i], left, perLookup)
		}
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
		cnames: []string{"Partner.Example.COM."},
	}
	a := Resolve(context.Background(), f, "partner.example.com", time.Second)
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
