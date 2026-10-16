package nginx

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

const (
	dnsTestListID = "00000000-0000-0000-0000-0000000000d1"
	dnsTestHostID = "00000000-0000-0000-0000-0000000000d2"
)

// domainRow is an access list domain row as the repository reads it: the
// placeholder (deny, all) with the name in Hostname.
func domainRow(id, name string, sortOrder int) model.AccessListItem {
	return model.AccessListItem{ID: id, AccessListID: dnsTestListID, Directive: "deny", Address: "all", Hostname: name, SortOrder: sortOrder}
}

func dnsTestList(items ...model.AccessListItem) *model.AccessList {
	return &model.AccessList{ID: dnsTestListID, Name: "partners", Items: items}
}

// accessListBlockLines returns the lines of the first access list block in a
// rendered config, trimmed, without blank lines and its two header comments.
func accessListBlockLines(t *testing.T, out string) []string {
	t.Helper()
	start := strings.Index(out, "    # Access List: ")
	if start < 0 {
		t.Fatalf("no access list block:\n%s", out)
	}
	var lines []string
	for _, l := range strings.Split(out[start:], "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "", strings.HasPrefix(l, "# Access List:"), strings.HasPrefix(l, "# Note:"):
		case strings.HasPrefix(l, "set $block_reason_var "), l == "satisfy any;", strings.HasPrefix(l, "# dns: "),
			strings.HasPrefix(l, "allow "), strings.HasPrefix(l, "deny "), strings.HasPrefix(l, "include "+DNSIncludeRenderDir+"/"):
			lines = append(lines, l)
		default:
			return lines
		}
	}
	return lines
}

// Address rows are rules; domain rows are include lines of the file the DNS
// entry service writes for (acl:<list>, name), each file once. A domain row
// whose file cannot be named is "deny all" in its place, as a version without
// domain rows writes every domain row.
func TestAccessListDomainRowsBecomeIncludes(t *testing.T) {
	skippedWarned.Delete("access list " + dnsTestListID + " domain r6 printer.local")
	logs := captureLog(t)
	list := dnsTestList(
		model.AccessListItem{ID: "r1", Directive: "allow", Address: "192.0.2.0/24"},
		model.AccessListItem{ID: "r2", Directive: "deny", Address: "198.51.100.7", SortOrder: 1},
		domainRow("r3", "partner.example.com", 2),
		domainRow("r4", "office.example.com", 3),
		domainRow("r5", "partner.example.com", 4),
		domainRow("r6", "printer.local", 5),
	)
	var rules []string
	for _, r := range accessListRules(list) {
		rules = append(rules, r.Directive+" "+r.Address)
	}
	if want := "allow 192.0.2.0/24|deny 198.51.100.7|deny all"; strings.Join(rules, "|") != want {
		t.Errorf("rules = %q, want %q", strings.Join(rules, "|"), want)
	}
	scope := model.AccessListDNSScope(dnsTestListID)
	want := []DNSIncludeLine{
		{Name: "partner.example.com", Path: DNSIncludeRenderDir + "/" + DNSIncludeKey(scope, "partner.example.com") + ".allow"},
		{Name: "office.example.com", Path: DNSIncludeRenderDir + "/" + DNSIncludeKey(scope, "office.example.com") + ".allow"},
	}
	if got := accessListDNSIncludes(list); !slices.Equal(got, want) {
		t.Errorf("include lines = %+v, want %+v", got, want)
	}
	if !strings.Contains(logs.String(), `[DNSEntries] WARN: Access list `+dnsTestListID+`: domain entry "printer.local" is not a usable domain name`) {
		t.Errorf("the unusable domain entry is not logged:\n%s", logs)
	}

	// A list ID that is not a UUID names no file: its domain rows are deny all.
	odd := &model.AccessList{ID: "list-1", Items: []model.AccessListItem{domainRow("r7", "partner.example.com", 0)}}
	if got := accessListDNSIncludes(odd); got != nil {
		t.Errorf("include lines of a list without a UUID = %+v, want none", got)
	}
	if got := accessListRules(odd); len(got) != 1 || got[0].Directive != "deny" || got[0].Address != "all" {
		t.Errorf("rules of a list without a UUID = %+v, want deny all", got)
	}
	if accessListDNSIncludes(nil) != nil {
		t.Error("a host without an access list has include lines")
	}
}

// The domains come after the list's address rules, a deny included, and
// before the final deny all: an address the list denies stays denied when a
// domain resolves to it.
func TestAccessListBlockPutsDomainsAfterAddressRules(t *testing.T) {
	list := dnsTestList(
		model.AccessListItem{ID: "r1", Directive: "allow", Address: "192.0.2.0/24"},
		model.AccessListItem{ID: "r2", Directive: "deny", Address: "198.51.100.7", SortOrder: 1},
		domainRow("r3", "partner.example.com", 2),
	)
	got := accessListBlockLines(t, renderForTest(t, ProxyHostConfigData{Host: baseHost(dnsTestHostID, "192.0.2.20", true), AccessList: list}))
	want := []string{
		`set $block_reason_var "access_denied";`,
		"allow 192.0.2.0/24;",
		"deny 198.51.100.7;",
		"# dns: partner.example.com",
		"include " + DNSIncludeRenderDir + "/" + DNSIncludeKey(model.AccessListDNSScope(dnsTestListID), "partner.example.com") + ".allow;",
		"deny all;",
	}
	if !slices.Equal(got, want) {
		t.Errorf("access list block:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A list of domains alone keeps its block and its deny all, so nobody gets in
// while the files are empty; one whose only domain cannot be named is closed
// the same way.
func TestAccessListOfDomainsOnlyStaysClosed(t *testing.T) {
	path := DNSIncludeRenderDir + "/" + DNSIncludeKey(model.AccessListDNSScope(dnsTestListID), "partner.example.com") + ".allow"
	for _, tc := range []struct {
		row  model.AccessListItem
		want []string
	}{
		{domainRow("r1", "partner.example.com", 0), []string{`set $block_reason_var "access_denied";`, "# dns: partner.example.com", "include " + path + ";", "deny all;"}},
		{domainRow("r2", "printer.local", 0), []string{`set $block_reason_var "access_denied";`, "deny all;", "deny all;"}},
	} {
		out := renderForTest(t, ProxyHostConfigData{Host: baseHost(dnsTestHostID, "192.0.2.20", true), AccessList: dnsTestList(tc.row)})
		if got := accessListBlockLines(t, out); !slices.Equal(got, tc.want) {
			t.Errorf("%s: access list block %q, want %q", tc.row.Hostname, got, tc.want)
		}
	}
}

// Before the host config is written, every domain include it renders exists:
// a missing file is created empty, a file the DNS entry service wrote keeps
// its content. An SSL host renders the block twice and gets
// each file once. A host without domain entries gets no directory.
func TestGenerateConfigFullCreatesMissingDomainIncludes(t *testing.T) {
	m, _ := newRequestPathTestManager(t)
	cert := "00000000-0000-0000-0000-0000000000d3"
	if err := os.MkdirAll(filepath.Join(m.certsPath, cert), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.certsPath, cert, "fullchain.pem"), []byte("placeholder"), 0o644); err != nil {
		t.Fatal(err)
	}
	host := baseHost(dnsTestHostID, "192.0.2.20", true)
	host.DomainNames = []string{"domains.example.com"}
	host.SSLEnabled, host.CertificateID = true, &cert
	list := dnsTestList(
		model.AccessListItem{ID: "r1", Directive: "allow", Address: "192.0.2.0/24"},
		domainRow("r2", "partner.example.com", 1),
		domainRow("r3", "office.example.com", 2),
	)
	scope := model.AccessListDNSScope(dnsTestListID)
	partner, office := DNSIncludeKey(scope, "partner.example.com"), DNSIncludeKey(scope, "office.example.com")
	written := FormatDNSIncludeFile("partner.example.com", scope, 4, ".allow", []string{"203.0.113.7"})
	if err := os.MkdirAll(m.dnsIncludeDiskDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.dnsIncludeDiskPath(partner, ".allow"), written, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := m.GenerateConfigFull(context.Background(), ProxyHostConfigData{Host: host, AccessList: list}); err != nil {
		t.Fatalf("GenerateConfigFull: %v", err)
	}
	conf, err := os.ReadFile(filepath.Join(m.configPath, GetConfigFilename(host)))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(conf), "    # Access List: partners\n"); n != 2 {
		t.Fatalf("the access list block renders %d time(s), want twice (HTTP and HTTPS)", n)
	}
	refs, err := m.ScanDNSIncludeReferences()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 || !refs[partner+".allow"] || !refs[office+".allow"] {
		t.Fatalf("the configs include %v, want the files of partner and office", refs)
	}
	if got, err := os.ReadFile(m.dnsIncludeDiskPath(partner, ".allow")); err != nil || !bytes.Equal(got, written) {
		t.Errorf("the render changed the file the DNS entry service wrote: %q (%v)", got, err)
	}
	if info, err := os.Stat(m.dnsIncludeDiskPath(office, ".allow")); err != nil || info.Size() != 0 {
		t.Errorf("the missing file was not created empty (%v)", err)
	}
	if files, err := m.ReadDNSIncludeDir(); err != nil || len(files) != 2 {
		t.Errorf("%d file(s) in the directory (%v), want 2", len(files), err)
	}

	plain, _ := newRequestPathTestManager(t)
	ipOnly := dnsTestList(model.AccessListItem{ID: "r1", Directive: "allow", Address: "192.0.2.0/24"})
	if err := plain.GenerateConfigFull(context.Background(), ProxyHostConfigData{Host: baseHost(dnsTestHostID, "192.0.2.20", true), AccessList: ipOnly}); err != nil {
		t.Fatalf("GenerateConfigFull: %v", err)
	}
	if _, err := os.Stat(plain.dnsIncludeDiskDir()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a host without domain entries created %s (%v)", plain.dnsIncludeDiskDir(), err)
	}
}

// A host config whose domain include cannot be created is not written:
// nginx -t would fail on it, and SyncAll would then remove the host.
func TestGenerateConfigFullWritesNoConfigWithoutItsDomainIncludes(t *testing.T) {
	m, _ := newRequestPathTestManager(t)
	if err := os.MkdirAll(filepath.Dir(m.dnsIncludeDiskDir()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.dnsIncludeDiskDir(), []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	host := baseHost(dnsTestHostID, "192.0.2.20", true)
	err := m.GenerateConfigFull(context.Background(), ProxyHostConfigData{Host: host, AccessList: dnsTestList(domainRow("r1", "partner.example.com", 0))})
	if err == nil || !strings.Contains(err.Error(), "failed to ensure domain include files") {
		t.Fatalf("GenerateConfigFull = %v, want the include error", err)
	}
	if _, statErr := os.Stat(filepath.Join(m.configPath, GetConfigFilename(host))); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the host config was written although its include cannot exist (%v)", statErr)
	}
}
