package nginx

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	dnsScopeA  = "acl:11111111-1111-4111-8111-111111111111"
	dnsScopeB  = "acl:22222222-2222-4222-8222-222222222222"
	dnsPartner = "partner.example.com"
	dnsOffice  = "office.example.com"
)

// dnsTestManager is a manager over a temp conf.d whose nginx is cli and,
// unless probe is nil, whose reloads are confirmed against probe.
func dnsTestManager(t *testing.T, cli nginxCLI, probe reloadProbe) *Manager {
	t.Helper()
	return &Manager{
		configPath:         filepath.Join(t.TempDir(), "conf.d"),
		cli:                cli,
		reloadProbe:        probe,
		reloadConfirmWait:  60 * time.Millisecond,
		reloadConfirmEvery: 2 * time.Millisecond,
	}
}

// writeDNSFile writes a file of the npg_dns directory as is.
func writeDNSFile(t *testing.T, m *Manager, file, content string) {
	t.Helper()
	if err := os.MkdirAll(m.dnsIncludeDiskDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.dnsIncludeDiskDir(), file), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readDNSFile(t *testing.T, m *Manager, file string) (string, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(m.dnsIncludeDiskDir(), file))
	if errors.Is(err, os.ErrNotExist) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data), true
}

// writeHostConf writes conf.d/<name>: a geo block including the .geo files
// of refs, and a server whose location includes the .allow files, in order.
func writeHostConf(t *testing.T, m *Manager, name string, refs ...string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("geo $npg_test {\n    default 0;\n")
	for _, r := range refs {
		if strings.HasSuffix(r, ".geo") {
			fmt.Fprintf(&b, "    include %s/%s;\n", DNSIncludeRenderDir, r)
		}
	}
	b.WriteString("}\nserver {\n    listen 8080;\n    location / {\n")
	for _, r := range refs {
		if strings.HasSuffix(r, ".allow") {
			fmt.Fprintf(&b, "        include %s/%s;\n", DNSIncludeRenderDir, r)
		}
	}
	b.WriteString("        deny all;\n        proxy_pass http://127.0.0.1:8081;\n    }\n}\n")
	if err := os.MkdirAll(m.configPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.configPath, name), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// nginxTestFailure is how dockerNginxCLI.Test reports nginx -t failing on
// msg: the error log line, the console line, the summary.
func nginxTestFailure(msg string) error {
	return fmt.Errorf("nginx -t failed: exit status 1: 2026/10/15 02:36:40 [emerg] 8#8: %s\nnginx: [emerg] %s\nnginx: configuration file /etc/nginx/nginx.conf test failed", msg, msg)
}

var emulatedInclude = regexp.MustCompile(`^\s*include (` + regexp.QuoteMeta(DNSIncludeRenderDir) + `/[0-9a-f]{16}\.(?:allow|geo));`)

// emulatedNginx is an nginxCLI whose nginx -t reads the files under
// configPath as nginx 1.30.4 does for what the applier repairs, and words
// its failures the same way. It walks the include
// lines of conf.d/*.conf in file and line order and stops at the first
// problem: a missing npg_dns file is reported in the including file, a line
// of an npg_dns file nginx would refuse in that file.
type emulatedNginx struct {
	configPath  string
	testCalls   int
	reloadCalls int
}

func (e *emulatedNginx) Test(ctx context.Context) error {
	e.testCalls++
	hosts, _ := filepath.Glob(filepath.Join(e.configPath, "*.conf"))
	sort.Strings(hosts)
	for _, host := range hosts {
		data, err := os.ReadFile(host)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			inc := emulatedInclude.FindStringSubmatch(line)
			if inc == nil {
				continue
			}
			disk := filepath.Join(e.configPath, "includes", "npg_dns", filepath.Base(inc[1]))
			content, err := os.ReadFile(disk)
			if err != nil {
				return nginxTestFailure(fmt.Sprintf(`open() "%s" failed (2: No such file or directory) in /etc/nginx/conf.d/%s:%d`, inc[1], filepath.Base(host), i+1))
			}
			for j, l := range strings.Split(string(content), "\n") {
				if word := emulatedRefusedWord(strings.TrimSpace(l), filepath.Ext(disk)); word != "" {
					return nginxTestFailure(fmt.Sprintf(`invalid parameter "%s" in %s:%d`, word, inc[1], j+1))
				}
			}
		}
	}
	return nil
}

func (e *emulatedNginx) Reload(ctx context.Context) error {
	e.reloadCalls++
	return nil
}

// emulatedRefusedWord returns the word nginx refuses in one line of an
// npg_dns file, or "" for a line it reads.
func emulatedRefusedWord(line, ext string) string {
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	f := strings.Fields(strings.TrimSuffix(line, ";"))
	switch {
	case ext == ".allow" && len(f) == 2 && f[0] == "allow":
		if _, err := netip.ParseAddr(f[1]); err != nil {
			return f[1]
		}
		return ""
	case ext == ".geo" && len(f) == 2 && f[1] == "1":
		if _, err := netip.ParseAddr(f[0]); err != nil {
			return f[0]
		}
		return ""
	}
	return f[0]
}

func TestDNSIncludeKeyIsStable(t *testing.T) {
	// A changed key would leave every rendered include pointing at files
	// nothing writes any more.
	cases := map[[2]string]string{
		{dnsScopeA, dnsPartner}: "8bb3373391259111",
		{dnsScopeB, dnsPartner}: "a98f5a74559f0f8d",
		{"trusted", dnsPartner}: "8cc579924a629e95",
	}
	for in, want := range cases {
		if got := DNSIncludeKey(in[0], in[1]); got != want {
			t.Errorf("DNSIncludeKey(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestDNSIncludeExtsAndRenderPath(t *testing.T) {
	exts := []struct {
		scope string
		want  []string
	}{
		{dnsScopeA, []string{".allow"}},
		{"uri:" + dnsScopeA[4:], []string{".geo"}},
		{"prio:global", []string{".geo"}},
		{"rl:global", []string{".geo"}},
		{"trusted", []string{".allow", ".geo"}},
		{"acl:global", nil},
		{"ACL:" + dnsScopeA[4:], nil},
		{"acl:aaaaaaaa-1111-4111-8111-111111111111", []string{".allow"}},
		{"acl:AAAAAAAA-1111-4111-8111-111111111111", nil}, // one spelling per owner, one key
		{"", nil},
		{"trusted:x", nil},
	}
	for _, c := range exts {
		if got := DNSIncludeExts(c.scope); !slices.Equal(got, c.want) {
			t.Errorf("DNSIncludeExts(%q) = %q, want %q", c.scope, got, c.want)
		}
	}
	if got, want := DNSIncludeRenderPath(dnsScopeA, dnsPartner, ".allow"), "/etc/nginx/conf.d/includes/npg_dns/8bb3373391259111.allow"; got != want {
		t.Errorf("render path = %q, want %q", got, want)
	}
	for _, c := range [][3]string{
		{dnsScopeA, dnsPartner, ".geo"},              // not an extension of an access list
		{dnsScopeA, "Partner.Example.com", ".allow"}, // not normalized
		{dnsScopeA, "partner.example.com\nallow all", ".allow"},
		{dnsScopeA, "", ".allow"},
		{"acl:global", dnsPartner, ".allow"},
	} {
		if got := DNSIncludeRenderPath(c[0], c[1], c[2]); got != "" {
			t.Errorf("DNSIncludeRenderPath(%q, %q, %q) = %q, want \"\"", c[0], c[1], c[2], got)
		}
	}
}

func TestFormatDNSIncludeFile(t *testing.T) {
	addrs := []string{"2001:db8::10", "203.0.113.7", "::ffff:203.0.113.10", "203.0.113.7", "198.51.100.0/24", "all", "fe80::1%eth0", " 192.0.2.1", "198.51.100.999", ""}
	want := map[string]string{
		".allow": "# npg dns: partner.example.com scope " + dnsScopeA + " gen 3\nallow 203.0.113.7;\nallow 203.0.113.10;\nallow 2001:db8::10;\n",
		".geo":   "# npg dns: partner.example.com scope " + dnsScopeA + " gen 3\n203.0.113.7 1;\n203.0.113.10 1;\n2001:db8::10 1;\n",
	}
	for ext, w := range want {
		if got := string(FormatDNSIncludeFile(dnsPartner, dnsScopeA, 3, ext, addrs)); got != w {
			t.Errorf("%s:\n%s\nwant:\n%s", ext, got, w)
		}
	}
	if got := FormatDNSIncludeFile(dnsPartner, dnsScopeA, 3, ".conf", addrs); got != nil {
		t.Errorf("unknown extension: %q, want nil", got)
	}
	// Unchecked text never reaches the header: it is left out.
	for _, c := range []struct {
		name, scope string
		gen         int64
	}{
		{"partner.example.com\nallow all;", dnsScopeA, 1},
		{dnsPartner, "acl:x\nallow all;", 1},
		{dnsPartner, dnsScopeA, -1},
	} {
		if got := string(FormatDNSIncludeFile(c.name, c.scope, c.gen, ".allow", []string{"203.0.113.7"})); got != "allow 203.0.113.7;\n" {
			t.Errorf("FormatDNSIncludeFile(%q, %q, %d) = %q, want only the address line", c.name, c.scope, c.gen, got)
		}
	}
	if got := FormatDNSIncludeFile(dnsPartner, dnsScopeA, 0, ".allow", nil); string(got) != "# npg dns: partner.example.com scope "+dnsScopeA+" gen 0\n" {
		t.Errorf("no addresses: %q, want the header alone", got)
	}
}

func TestParseDNSIncludeHeader(t *testing.T) {
	line := strings.SplitN(string(FormatDNSIncludeFile(dnsPartner, "trusted", 42, ".geo", nil)), "\n", 2)[0]
	name, scope, gen, ok := ParseDNSIncludeHeader(line)
	if !ok || name != dnsPartner || scope != "trusted" || gen != 42 {
		t.Fatalf("ParseDNSIncludeHeader(%q) = %q, %q, %d, %v", line, name, scope, gen, ok)
	}
	if _, _, _, ok := ParseDNSIncludeHeader(line + "\r"); !ok {
		t.Error("a trailing CR must not hide the header")
	}
	for _, bad := range []string{
		"",
		"# npg dns: partner.example.com scope trusted",
		"# npg dns: partner.example.com scope trusted gen x",
		"# npg dns: partner.example.com scope trusted gen -1",
		"# npg dns: partner.example.com scope trusted gen 1 extra",
		"# npg dns: Partner.example.com scope trusted gen 1",
		"# npg dns: partner.example.com scope acl:global gen 1",
		"# npg dns:  partner.example.com scope trusted gen 1",
		"allow 203.0.113.7;",
	} {
		if _, _, _, ok := ParseDNSIncludeHeader(bad); ok {
			t.Errorf("ParseDNSIncludeHeader(%q) accepted", bad)
		}
	}
}

func TestWriteDNSIncludeFilesWritesEachFileOnce(t *testing.T) {
	m := dnsTestManager(t, &fakeNginxCLI{}, nil)
	changed, err := m.WriteDNSIncludeFiles("trusted", dnsPartner, 1, []string{"203.0.113.7"})
	if err != nil || !changed {
		t.Fatalf("first write: %v, %v; want true, nil", changed, err)
	}
	key := DNSIncludeKey("trusted", dnsPartner)
	for _, ext := range []string{".allow", ".geo"} {
		got, ok := readDNSFile(t, m, key+ext)
		if want := string(FormatDNSIncludeFile(dnsPartner, "trusted", 1, ext, []string{"203.0.113.7"})); !ok || got != want {
			t.Errorf("%s = %q, want %q", ext, got, want)
		}
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	for _, ext := range []string{".allow", ".geo"} {
		if err := os.Chtimes(m.dnsIncludeDiskPath(key, ext), old, old); err != nil {
			t.Fatal(err)
		}
	}
	// The same content in another order: nothing to write.
	if changed, err := m.WriteDNSIncludeFiles("trusted", dnsPartner, 1, []string{"203.0.113.7", "203.0.113.7"}); err != nil || changed {
		t.Fatalf("same content: %v, %v; want false, nil", changed, err)
	}
	for _, ext := range []string{".allow", ".geo"} {
		if info, err := os.Stat(m.dnsIncludeDiskPath(key, ext)); err != nil || !info.ModTime().Equal(old) {
			t.Errorf("%s was rewritten although its content did not change", ext)
		}
	}
	if changed, err := m.WriteDNSIncludeFiles("trusted", dnsPartner, 2, nil); err != nil || !changed {
		t.Fatalf("emptied: %v, %v; want true, nil", changed, err)
	}
	if got, _ := readDNSFile(t, m, key+".allow"); got != "# npg dns: partner.example.com scope trusted gen 2\n" {
		t.Errorf("emptied .allow = %q", got)
	}
}

func TestWriteDNSIncludeFilesRefusesBadInput(t *testing.T) {
	m := dnsTestManager(t, &fakeNginxCLI{}, nil)
	for _, c := range []struct {
		scope, name string
		gen         int64
	}{
		{"acl:global", dnsPartner, 1},
		{dnsScopeA, "Partner.Example.com", 1},
		{dnsScopeA, "partner.example.com\nallow all", 1},
		{dnsScopeA, dnsPartner, -1},
	} {
		if changed, err := m.WriteDNSIncludeFiles(c.scope, c.name, c.gen, []string{"203.0.113.7"}); err == nil || changed {
			t.Errorf("WriteDNSIncludeFiles(%q, %q, %d) = %v, %v; want an error", c.scope, c.name, c.gen, changed, err)
		}
	}
	if files, err := m.ReadDNSIncludeDir(); err != nil || len(files) != 0 {
		t.Fatalf("bad input wrote %d file(s) (%v)", len(files), err)
	}
}

// Whatever set it is asked to write, a file holds exactly that set: never an
// address it was not given, never one it was given twice, never a line
// nginx -t would refuse.
func TestWriteDNSIncludeFilesNeverWritesMoreThanAsked(t *testing.T) {
	pool := []string{"203.0.113.7", "203.0.113.8", "198.51.100.20", "2001:db8::10", "2001:db8::11", "::ffff:203.0.113.10", "203.0.113.10", "not-an-address", "198.51.100.0/24"}
	m := dnsTestManager(t, &fakeNginxCLI{}, nil)
	rng := rand.New(rand.NewPCG(320, 7))
	for i := 0; i < 300; i++ {
		var asked []string
		for _, a := range pool {
			if rng.IntN(2) == 0 {
				asked = append(asked, a)
			}
		}
		scope := []string{dnsScopeA, "trusted", "prio:global"}[rng.IntN(3)]
		if _, err := m.WriteDNSIncludeFiles(scope, dnsPartner, int64(i), asked); err != nil {
			t.Fatal(err)
		}
		want, _ := canonicalDNSIncludeAddrs(asked)
		files, err := m.ReadDNSIncludeDir()
		if err != nil {
			t.Fatal(err)
		}
		key := DNSIncludeKey(scope, dnsPartner)
		seen := 0
		for _, f := range files {
			if f.Key != key {
				continue
			}
			seen++
			if !f.HasHeader || f.Gen != int64(i) || !slices.Equal(f.Addrs, want) || f.Empty != (len(want) == 0) {
				t.Fatalf("round %d, %s%s: header %v gen %d addrs %q empty %v; asked %q, want %q", i, f.Key, f.Ext, f.HasHeader, f.Gen, f.Addrs, f.Empty, asked, want)
			}
			content, _ := readDNSFile(t, m, f.Key+f.Ext)
			for _, l := range strings.Split(content, "\n") {
				if w := emulatedRefusedWord(strings.TrimSpace(l), f.Ext); w != "" {
					t.Fatalf("round %d: %s%s holds a line nginx refuses: %q", i, f.Key, f.Ext, l)
				}
			}
		}
		if seen != len(DNSIncludeExts(scope)) {
			t.Fatalf("round %d: %d file(s) of %s, want %d", i, seen, scope, len(DNSIncludeExts(scope)))
		}
	}
}

func TestReadDNSIncludeDir(t *testing.T) {
	m := dnsTestManager(t, &fakeNginxCLI{}, nil)
	if files, err := m.ReadDNSIncludeDir(); err != nil || files != nil {
		t.Fatalf("no directory: %v, %v; want nil, nil", files, err)
	}
	keyA := DNSIncludeKey(dnsScopeA, dnsPartner)
	keyB := DNSIncludeKey(dnsScopeB, dnsPartner)
	writeDNSFile(t, m, keyA+".allow", string(FormatDNSIncludeFile(dnsPartner, dnsScopeA, 5, ".allow", []string{"203.0.113.7", "2001:db8::10"})))
	writeDNSFile(t, m, keyB+".allow", "")                                                                                          // created by the render
	writeDNSFile(t, m, "0123456789abcdef.allow", "# a comment\n\n")                                                                // no header, empty
	writeDNSFile(t, m, "1123456789abcdef.allow", "# npg dns: partner.example.com scope "+dnsScopeA+" gen 1\nallow 203.0.113.9;\n") // header of another key
	writeDNSFile(t, m, "2123456789abcdef.geo", "garbage line\n")
	writeDNSFile(t, m, ".tmp-123", "allow 203.0.113.1;\n")
	writeDNSFile(t, m, "ABCDEF0123456789.allow", "")
	writeDNSFile(t, m, "0123456789abcdef.conf", "")
	if err := os.Mkdir(filepath.Join(m.dnsIncludeDiskDir(), "3123456789abcdef.allow"), 0o755); err != nil {
		t.Fatal(err)
	}
	files, err := m.ReadDNSIncludeDir()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]DNSIncludeFile{}
	for _, f := range files {
		got[f.Key+f.Ext] = f
	}
	if len(got) != 5 {
		t.Fatalf("read %d files (%v), want the 5 key-named regular files", len(got), files)
	}
	if f := got[keyA+".allow"]; !f.HasHeader || f.Name != dnsPartner || f.Scope != dnsScopeA || f.Gen != 5 || f.Empty || !slices.Equal(f.Addrs, []string{"203.0.113.7", "2001:db8::10"}) {
		t.Errorf("written file: %+v", f)
	}
	if f := got[keyB+".allow"]; f.HasHeader || !f.Empty || f.Addrs != nil {
		t.Errorf("0-byte file: %+v", f)
	}
	if f := got["0123456789abcdef.allow"]; f.HasHeader || !f.Empty {
		t.Errorf("comment-only file: %+v", f)
	}
	if f := got["1123456789abcdef.allow"]; f.HasHeader || f.Empty || !slices.Equal(f.Addrs, []string{"203.0.113.9"}) {
		t.Errorf("a header naming another (scope, name) does not count: %+v", f)
	}
	if f := got["2123456789abcdef.geo"]; f.HasHeader || f.Empty || f.Addrs != nil {
		t.Errorf("a line nginx would refuse makes the file non-empty: %+v", f)
	}
}

func TestScanDNSIncludeReferences(t *testing.T) {
	m := dnsTestManager(t, &fakeNginxCLI{}, nil)
	writeHostConf(t, m, "proxy_host_a_example_com.conf", "8bb3373391259111.allow", "0123456789abcdef.geo")
	writeHostConf(t, m, "proxy_host_b_example_com.conf.disabled", "1111111111111111.allow")
	if err := os.WriteFile(filepath.Join(filepath.Dir(m.configPath), "nginx.conf"), []byte("http {\n    geo $x {\n        include "+DNSIncludeRenderDir+"/8cc579924a629e95.geo;\n    }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(m.configPath, "includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.configPath, "includes", "x.conf"), []byte("include "+DNSIncludeRenderDir+"/2222222222222222.allow;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	refs, err := m.ScanDNSIncludeReferences()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"8bb3373391259111.allow": true, "0123456789abcdef.geo": true, "8cc579924a629e95.geo": true}
	if len(refs) != len(want) {
		t.Fatalf("refs = %v, want %v (conf.d/*.conf and nginx.conf only)", refs, want)
	}
	for k := range want {
		if !refs[k] {
			t.Errorf("missing %s in %v", k, refs)
		}
	}
	if err := os.Mkdir(filepath.Join(m.configPath, "broken.conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ScanDNSIncludeReferences(); err == nil {
		t.Error("an unreadable config must be an error")
	}
}

func TestEnsureDNSIncludeFile(t *testing.T) {
	m := dnsTestManager(t, &fakeNginxCLI{}, nil)
	if err := m.EnsureDNSIncludeFile("8bb3373391259111", ".allow"); err != nil {
		t.Fatal(err)
	}
	if got, ok := readDNSFile(t, m, "8bb3373391259111.allow"); !ok || got != "" {
		t.Fatalf("created %q (exists %v), want an empty file", got, ok)
	}
	content := string(FormatDNSIncludeFile(dnsPartner, dnsScopeA, 1, ".allow", []string{"203.0.113.7"}))
	writeDNSFile(t, m, "8bb3373391259111.allow", content)
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(m.dnsIncludeDiskPath("8bb3373391259111", ".allow"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureDNSIncludeFile("8bb3373391259111", ".allow"); err != nil {
		t.Fatal(err)
	}
	if got, _ := readDNSFile(t, m, "8bb3373391259111.allow"); got != content {
		t.Errorf("an existing file was changed: %q", got)
	}
	if info, err := os.Stat(m.dnsIncludeDiskPath("8bb3373391259111", ".allow")); err != nil || time.Since(info.ModTime()) > time.Hour {
		t.Errorf("an existing file keeps its old modification time, so the GC could take it from a render")
	}
	for _, bad := range [][2]string{{"8BB3373391259111", ".allow"}, {"8bb337339125911", ".allow"}, {"8bb3373391259111", ".conf"}, {"../../x", ".allow"}} {
		if err := m.EnsureDNSIncludeFile(bad[0], bad[1]); err == nil {
			t.Errorf("EnsureDNSIncludeFile(%q, %q) accepted", bad[0], bad[1])
		}
	}
}

// nginx -t names one missing file per run: each is created
// empty, then nginx is reloaded once.
func TestApplyDNSIncludesCreatesMissingFilesOneRunAtATime(t *testing.T) {
	cli := &emulatedNginx{}
	m := dnsTestManager(t, cli, nil)
	cli.configPath = m.configPath
	refs := []string{"8bb3373391259111.allow", "a98f5a74559f0f8d.allow", "8cc579924a629e95.geo"}
	writeHostConf(t, m, "proxy_host_example_com.conf", refs...)
	res := m.ApplyDNSIncludes(context.Background())
	if res.Outcome != "signalled" {
		t.Fatalf("outcome = %+v, want signalled", res)
	}
	if cli.testCalls != 4 || cli.reloadCalls != 1 {
		t.Errorf("nginx -t ran %d time(s) and reload %d, want 4 and 1", cli.testCalls, cli.reloadCalls)
	}
	for _, r := range refs {
		if got, ok := readDNSFile(t, m, r); !ok || got != "" {
			t.Errorf("%s: %q (exists %v), want an empty file", r, got, ok)
		}
	}
}

// A file that stays missing (nginx looks somewhere the API does not write)
// is repaired once; the apply then reports the host file nginx names.
func TestApplyDNSIncludesRepairsEachFileOnce(t *testing.T) {
	missing := nginxTestFailure(`open() "` + DNSIncludeRenderDir + `/8bb3373391259111.allow" failed (2: No such file or directory) in /etc/nginx/conf.d/proxy_host_example_com.conf:8`)
	cli := &fakeNginxCLI{testErrs: []error{missing, missing, missing, missing}}
	m := dnsTestManager(t, cli, nil)
	writeHostConf(t, m, "proxy_host_example_com.conf", "8bb3373391259111.allow")
	res := m.ApplyDNSIncludes(context.Background())
	if res.Outcome != "blocked" || res.BlockingFile != "proxy_host_example_com.conf" {
		t.Fatalf("result = %+v, want blocked by proxy_host_example_com.conf", res)
	}
	if cli.testCalls != 2 || cli.reloadCalls != 0 {
		t.Errorf("nginx -t ran %d time(s) and reload %d, want 2 and 0", cli.testCalls, cli.reloadCalls)
	}
}

// The repairs are bounded by the files the configs include, plus one.
func TestApplyDNSIncludesRepairBudget(t *testing.T) {
	var errs []error
	for i := 0; i < 10; i++ {
		errs = append(errs, nginxTestFailure(fmt.Sprintf(`open() "%s/%016x.allow" failed (2: No such file or directory) in /etc/nginx/conf.d/proxy_host_example_com.conf:8`, DNSIncludeRenderDir, i)))
	}
	cli := &fakeNginxCLI{testErrs: errs}
	m := dnsTestManager(t, cli, nil)
	writeHostConf(t, m, "proxy_host_example_com.conf", "8bb3373391259111.allow", "a98f5a74559f0f8d.allow")
	if res := m.ApplyDNSIncludes(context.Background()); res.Outcome != "blocked" {
		t.Fatalf("result = %+v, want blocked", res)
	}
	if cli.testCalls != 4 {
		t.Errorf("nginx -t ran %d times, want 4 (2 included files + 1 repairs, then give up)", cli.testCalls)
	}
}

// An [emerg] inside an npg_dns file empties that file (never restores an
// older content) and the reload goes on.
func TestApplyDNSIncludesEmptiesAFileNginxRefuses(t *testing.T) {
	logs := captureLog(t)
	cli := &emulatedNginx{}
	m := dnsTestManager(t, cli, nil)
	cli.configPath = m.configPath
	writeHostConf(t, m, "proxy_host_example_com.conf", "8bb3373391259111.allow", "a98f5a74559f0f8d.allow")
	good := string(FormatDNSIncludeFile(dnsPartner, dnsScopeB, 2, ".allow", []string{"203.0.113.7"}))
	writeDNSFile(t, m, "8bb3373391259111.allow", "# npg dns: partner.example.com scope "+dnsScopeA+" gen 1\nallow 198.51.100.999;\n")
	writeDNSFile(t, m, "a98f5a74559f0f8d.allow", good)
	res := m.ApplyDNSIncludes(context.Background())
	if res.Outcome != "signalled" {
		t.Fatalf("result = %+v, want signalled", res)
	}
	if got, _ := readDNSFile(t, m, "8bb3373391259111.allow"); got != "" {
		t.Errorf("refused file = %q, want it emptied", got)
	}
	if got, _ := readDNSFile(t, m, "a98f5a74559f0f8d.allow"); got != good {
		t.Errorf("the other file changed: %q", got)
	}
	if !strings.Contains(logs.String(), "[DNSEntries] ERROR: nginx -t refused the domain include 8bb3373391259111.allow") {
		t.Errorf("the emptied file is not logged as an error:\n%s", logs)
	}
}

// Another host's broken config blocks the apply: nothing is written, nothing
// is reloaded, and the result names that host's file.
func TestApplyDNSIncludesBlockedByAnotherHost(t *testing.T) {
	const upstream = `host not found in upstream "app.internal.example" in /etc/nginx/conf.d/proxy_host_shop_example_com.conf:31`
	cli := &fakeNginxCLI{testErrs: []error{nginxTestFailure(upstream)}}
	m := dnsTestManager(t, cli, nil)
	content := string(FormatDNSIncludeFile(dnsPartner, dnsScopeA, 1, ".allow", []string{"203.0.113.7"}))
	writeDNSFile(t, m, "8bb3373391259111.allow", content)
	res := m.ApplyDNSIncludes(context.Background())
	if res.Outcome != "blocked" || res.BlockingFile != "proxy_host_shop_example_com.conf" || res.Detail != upstream {
		t.Fatalf("result = %+v, want blocked by proxy_host_shop_example_com.conf with nginx's message", res)
	}
	if got, _ := readDNSFile(t, m, "8bb3373391259111.allow"); got != content {
		t.Errorf("a blocked apply changed a file: %q", got)
	}
	if cli.testCalls != 1 || cli.reloadCalls != 0 {
		t.Errorf("nginx -t ran %d time(s) and reload %d, want 1 and 0", cli.testCalls, cli.reloadCalls)
	}
}

// A [warn] naming one host before the [emerg] of another:
// the [emerg] decides.
func TestApplyDNSIncludesReadsOnlyEmergLines(t *testing.T) {
	out := fmt.Errorf("nginx -t failed: exit status 1: 2026/10/15 02:41:28 [warn] 8#8: duplicate network \"198.51.100.7\", value: \"1\", old value: \"1\" in /etc/nginx/conf.d/proxy_host_a_example_com.conf:5\n" +
		"nginx: [warn] duplicate network \"198.51.100.7\", value: \"1\", old value: \"1\" in /etc/nginx/conf.d/proxy_host_a_example_com.conf:5\n" +
		"2026/10/15 02:41:28 [emerg] 8#8: unknown directive \"proxy_passs\" in /etc/nginx/conf.d/proxy_host_b_example_com.conf:12\n" +
		"nginx: [emerg] unknown directive \"proxy_passs\" in /etc/nginx/conf.d/proxy_host_b_example_com.conf:12\n" +
		"nginx: configuration file /etc/nginx/nginx.conf test failed")
	m := dnsTestManager(t, &fakeNginxCLI{testErrs: []error{out}}, nil)
	if res := m.ApplyDNSIncludes(context.Background()); res.Outcome != "blocked" || res.BlockingFile != "proxy_host_b_example_com.conf" {
		t.Fatalf("result = %+v, want blocked by proxy_host_b_example_com.conf", res)
	}
}

func TestApplyDNSIncludesOutcomes(t *testing.T) {
	notRunning := errors.New("nginx -t failed: exit status 1: Error response from daemon: container 4f1e is not running")
	noPid := errors.New(`nginx -s reload failed: exit status 1: nginx: [error] open() "/var/run/nginx.pid" failed (2: No such file or directory)`)
	cases := []struct {
		name    string
		cli     *fakeNginxCLI
		probe   reloadProbe
		outcome string
		snap    bool
	}{
		{"accepted", &fakeNginxCLI{}, &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}, {master: 1, children: []int{10, 20}}}}, "accepted", false},
		{"rejected", &fakeNginxCLI{}, &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}, emerg: []string{rejectedZoneKeyLine}}, "rejected", false},
		{"unconfirmed", &fakeNginxCLI{}, &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}}, "unconfirmed", true},
		{"no snapshot", &fakeNginxCLI{}, &fakeReloadProbe{procs: []fakeProcs{{err: errors.New("docker exec: i/o timeout")}}}, "unconfirmed", false},
		{"no confirmation", &fakeNginxCLI{}, nil, "signalled", false},
		{"container stopped", &fakeNginxCLI{testErrs: []error{notRunning}}, nil, "not_up", false},
		{"nginx not started", &fakeNginxCLI{reloadErrs: []error{noPid}}, nil, "not_up", false},
		{"docker broken", &fakeNginxCLI{testErrs: []error{errors.New("nginx -t failed: exec: \"docker\": executable file not found in $PATH")}}, nil, "failed", false},
	}
	for _, c := range cases {
		m := dnsTestManager(t, c.cli, c.probe)
		res := m.ApplyDNSIncludes(context.Background())
		if res.Outcome != c.outcome || (res.Snapshot != nil) != c.snap {
			t.Errorf("%s: %+v, want %s with snapshot %v", c.name, res, c.outcome, c.snap)
		}
		if c.outcome == "rejected" && res.Detail != cleanEmergLine(rejectedZoneKeyLine) {
			t.Errorf("rejected: Detail = %q, want nginx's line", res.Detail)
		}
	}
}

// The snapshot of an unconfirmed apply answers ReloadTakenSince.
func TestApplyDNSIncludesUnconfirmedSnapshotAnswersLater(t *testing.T) {
	m := dnsTestManager(t, &fakeNginxCLI{}, &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}}})
	res := m.ApplyDNSIncludes(context.Background())
	if res.Outcome != "unconfirmed" || res.Snapshot == nil {
		t.Fatalf("result = %+v, want unconfirmed with a snapshot", res)
	}
	m.reloadProbe = &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10, 30}}}}
	if taken, err := m.ReloadTakenSince(context.Background(), res.Snapshot); err != nil || !taken {
		t.Errorf("ReloadTakenSince = %v, %v; want true, nil", taken, err)
	}
}

// NGINX_SKIP_TEST=true: no nginx, nothing run.
func TestApplyDNSIncludesSkipped(t *testing.T) {
	cli := &fakeNginxCLI{}
	m := dnsTestManager(t, cli, nil)
	m.skipTest = true
	if res := m.ApplyDNSIncludes(context.Background()); res.Outcome != "skipped" {
		t.Fatalf("result = %+v, want skipped", res)
	}
	if cli.testCalls != 0 || cli.reloadCalls != 0 {
		t.Errorf("nginx -t ran %d time(s) and reload %d, want none", cli.testCalls, cli.reloadCalls)
	}
}

// The applier runs no post-reload health probe: its answer is the
// reload's, and a failing probe never turns into a rollback.
func TestApplyDNSIncludesRunsNoHealthProbe(t *testing.T) {
	probeExec := &fakeHealthExec{outputs: []string{""}, errs: []error{errors.New("exit status 22")}}
	m := dnsTestManager(t, &fakeNginxCLI{}, nil)
	m.healthProber = &HealthProber{exec: probeExec}
	if res := m.ApplyDNSIncludes(context.Background()); res.Outcome != "signalled" {
		t.Fatalf("result = %+v, want signalled", res)
	}
	if probeExec.calls != 0 {
		t.Errorf("the health probe ran %d time(s), want none", probeExec.calls)
	}
}

// The hooks hear the applier's reload like any other.
func TestApplyDNSIncludesReloadReachesTheHooks(t *testing.T) {
	m := dnsTestManager(t, &fakeNginxCLI{}, &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}, {master: 1, children: []int{10, 20}}}})
	rec := &recordingHooks{}
	m.SetReloadHooks(rec.hooks())
	if res := m.ApplyDNSIncludes(context.Background()); res.Outcome != "accepted" {
		t.Fatalf("result = %+v, want accepted", res)
	}
	if got := rec.only(t); got.outcome != ReloadAccepted || got.locked {
		t.Errorf("After(%v, %q), locked %v; want accepted, outside the lock", got.token, got.outcome, got.locked)
	}
}

// The applier's reload takes its token from BeforeDNSApply when the hooks
// set one, with confirmation on or off: a hook can tell that reload, which is
// for the include files, from every other. Every other reload takes its
// token from Before, and so does the applier's when BeforeDNSApply is unset.
func TestApplyDNSIncludesTakesItsTokenFromBeforeDNSApply(t *testing.T) {
	ctx := context.Background()
	confirmed := func() reloadProbe {
		return &fakeReloadProbe{procs: []fakeProcs{{master: 1, children: []int{10}}, {master: 1, children: []int{10, 20}}}}
	}
	var heard []string
	hooks := ReloadHooks{
		Before:         func() any { return "before" },
		BeforeDNSApply: func() any { return "dns" },
		After: func(token any, outcome ReloadOutcome, _ *ReloadSnapshot) {
			heard = append(heard, fmt.Sprintf("%v:%s", token, outcome))
		},
	}
	m := dnsTestManager(t, &fakeNginxCLI{}, confirmed())
	m.SetReloadHooks(hooks)
	if res := m.ApplyDNSIncludes(ctx); res.Outcome != "accepted" {
		t.Fatalf("apply: %+v, want accepted", res)
	}
	m.reloadProbe = confirmed()
	if err := m.ReloadNginx(ctx); err != nil {
		t.Fatalf("ReloadNginx: %v", err)
	}
	m.reloadProbe = nil // confirmation off: After hears the signal at once
	if res := m.ApplyDNSIncludes(ctx); res.Outcome != "signalled" {
		t.Fatalf("apply without confirmation: %+v, want signalled", res)
	}
	hooks.BeforeDNSApply = nil
	m.SetReloadHooks(hooks)
	m.reloadProbe = confirmed()
	if res := m.ApplyDNSIncludes(ctx); res.Outcome != "accepted" {
		t.Fatalf("apply without BeforeDNSApply: %+v, want accepted", res)
	}
	if got, want := strings.Join(heard, " "), "dns:accepted before:accepted dns:signalled before:accepted"; got != want {
		t.Errorf("After heard %q, want %q", got, want)
	}
}

// Whatever the files hold and whichever are missing, an apply leaves every
// file with at most the addresses it had: it creates files empty, empties a
// file nginx refuses, and writes nothing else.
func TestApplyDNSIncludesNeverAddsAddresses(t *testing.T) {
	type seg struct{ scope, name string }
	segs := []seg{{dnsScopeA, dnsPartner}, {dnsScopeB, dnsPartner}, {dnsScopeA, dnsOffice}, {"trusted", dnsOffice}, {"prio:global", dnsPartner}}
	pool := []string{"203.0.113.7", "198.51.100.20", "2001:db8::10", "203.0.113.10"}
	rng := rand.New(rand.NewPCG(320, 8))
	for round := 0; round < 100; round++ {
		cli := &emulatedNginx{}
		m := dnsTestManager(t, cli, nil)
		cli.configPath = m.configPath
		before := map[string][]string{} // file -> addresses nginx could allow before
		var refs []string
		for _, s := range segs {
			if rng.IntN(4) == 0 {
				continue // not included by any config
			}
			key := DNSIncludeKey(s.scope, s.name)
			for _, ext := range DNSIncludeExts(s.scope) {
				file := key + ext
				refs = append(refs, file)
				var addrs []string
				for _, a := range pool {
					if rng.IntN(2) == 0 {
						addrs = append(addrs, a)
					}
				}
				switch rng.IntN(4) {
				case 0: // missing
				case 1:
					writeDNSFile(t, m, file, "")
				case 2:
					writeDNSFile(t, m, file, string(FormatDNSIncludeFile(s.name, s.scope, 1, ext, addrs)))
					before[file] = addrs
				case 3:
					bad := "allow 198.51.100.999;\n"
					if ext == ".geo" {
						bad = "198.51.100.999 1;\n"
					}
					writeDNSFile(t, m, file, string(FormatDNSIncludeFile(s.name, s.scope, 1, ext, addrs))+bad)
					before[file] = addrs
				}
			}
		}
		if len(refs) == 0 {
			continue
		}
		rng.Shuffle(len(refs), func(i, j int) { refs[i], refs[j] = refs[j], refs[i] })
		writeHostConf(t, m, "proxy_host_example_com.conf", refs...)
		if res := m.ApplyDNSIncludes(context.Background()); res.Outcome != "signalled" {
			t.Fatalf("round %d: %+v, want signalled", round, res)
		}
		files, err := m.ReadDNSIncludeDir()
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != len(refs) {
			t.Fatalf("round %d: %d file(s) on disk, want the %d included", round, len(files), len(refs))
		}
		for _, f := range files {
			for _, a := range f.Addrs {
				if !slices.Contains(before[f.Key+f.Ext], a) {
					t.Fatalf("round %d: %s%s allows %s, which it did not before", round, f.Key, f.Ext, a)
				}
			}
		}
		if cli.reloadCalls != 1 {
			t.Fatalf("round %d: %d reload(s), want 1", round, cli.reloadCalls)
		}
	}
}

func TestGCDNSIncludeFiles(t *testing.T) {
	m := dnsTestManager(t, &fakeNginxCLI{}, nil)
	old := time.Now().Add(-48 * time.Hour)
	type file struct {
		scope, name string
		addrs       []string
		header      bool
		young       bool
		inConfig    bool
		inDB        bool
		removed     bool
	}
	files := map[string]file{
		"unused, empty, old":      {dnsScopeA, dnsPartner, nil, true, false, false, false, true},
		"still in the database":   {dnsScopeB, dnsPartner, nil, true, false, false, true, false},
		"still in a config":       {dnsScopeA, dnsOffice, nil, true, false, true, false, false},
		"emptied less than a day": {dnsScopeB, dnsOffice, nil, true, true, false, false, false},
		"unused but not empty":    {"trusted", dnsPartner, []string{"203.0.113.7"}, true, false, false, false, false},
		"no header, old":          {"prio:global", dnsPartner, nil, false, false, false, false, true},
		"no header, in a config":  {"prio:global", dnsOffice, nil, false, false, true, false, false},
		"no header, young":        {"rl:global", dnsPartner, nil, false, true, false, false, false},
	}
	inDB := map[string]bool{}
	var configRefs []string
	paths := map[string]string{}
	for what, f := range files {
		ext := DNSIncludeExts(f.scope)[0]
		name := DNSIncludeKey(f.scope, f.name) + ext
		paths[what] = name
		content := ""
		if f.header {
			content = string(FormatDNSIncludeFile(f.name, f.scope, 1, ext, f.addrs))
		}
		writeDNSFile(t, m, name, content)
		if !f.young {
			if err := os.Chtimes(m.dnsIncludeDiskPath(name[:16], ext), old, old); err != nil {
				t.Fatal(err)
			}
		}
		if f.inConfig {
			configRefs = append(configRefs, name)
		}
		if f.inDB {
			inDB[f.scope+"\x00"+f.name] = true
		}
	}
	writeDNSFile(t, m, ".tmp-1", "")
	writeHostConf(t, m, "proxy_host_example_com.conf", configRefs...)
	lockHeld := false
	removed, err := m.GCDNSIncludeFiles(context.Background(), func(scope, name string) bool {
		lockHeld = globalLockHeld()
		return inDB[scope+"\x00"+name]
	}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Errorf("removed %d file(s), want 2", removed)
	}
	for what, f := range files {
		if _, exists := readDNSFile(t, m, paths[what]); exists == f.removed {
			t.Errorf("%s: exists %v, want removed %v", what, exists, f.removed)
		}
	}
	if _, ok := readDNSFile(t, m, ".tmp-1"); !ok {
		t.Error("a file that is not an include file was removed")
	}
	if !lockHeld {
		t.Error("the database was asked outside the nginx lock: a render could reference the file in between")
	}
}

// A config that cannot be read could reference any file: nothing goes.
func TestGCDNSIncludeFilesKeepsEverythingWhenAConfigCannotBeRead(t *testing.T) {
	m := dnsTestManager(t, &fakeNginxCLI{}, nil)
	writeDNSFile(t, m, "0123456789abcdef.allow", "")
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(m.dnsIncludeDiskPath("0123456789abcdef", ".allow"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(m.configPath, "broken.conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	removed, err := m.GCDNSIncludeFiles(context.Background(), func(string, string) bool { return false }, 24*time.Hour)
	if err == nil || removed != 0 {
		t.Fatalf("removed %d, err %v; want 0 and an error", removed, err)
	}
	if _, ok := readDNSFile(t, m, "0123456789abcdef.allow"); !ok {
		t.Error("removed a file while a config could not be read")
	}
}
