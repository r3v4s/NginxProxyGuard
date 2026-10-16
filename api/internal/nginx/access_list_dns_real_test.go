package nginx

// An access list's domain entries against a real nginx, skipped unless
// NPG_REAL_NGINX_CONTAINER and NPG_REAL_NGINX_CONFD
// are set (reload_hooks_real_test.go). GenerateConfigFull renders the host
// configs; the container's nginx.conf must load the ModSecurity module,
// because a host config says "modsecurity off". The clients are the
// container's own loopback addresses, the backend a server of the same nginx.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// realHostStatus asks the container's nginx for / on host from the loopback
// address ip until it answers want (old workers can take a request or two
// after a reload), and returns the last answer.
func realHostStatus(t *testing.T, container, host, ip, want string) string {
	t.Helper()
	var got string
	for deadline := time.Now().Add(3 * time.Second); ; {
		out, err := exec.Command("docker", "exec", container, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
			"--interface", ip, "-H", "Host: "+host, "http://127.0.0.1:8080/").CombinedOutput()
		if err != nil {
			t.Fatalf("curl %s from %s: %v: %s", host, ip, err, out)
		}
		got = strings.TrimSpace(string(out))
		if got == want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestRealAccessListDomainEntries(t *testing.T) {
	m, confd := realNginxManager(t)
	container := os.Getenv("NPG_REAL_NGINX_CONTAINER")
	m.httpPort = "8080"
	m.SetEnableIPv6(false)
	ctx := context.Background()

	const partner, shop = "partner.example.com", "shop.example.com"
	listA, listB := "00000000-0000-0000-0000-0000000000e1", "00000000-0000-0000-0000-0000000000e2"
	scopeA, scopeB := model.AccessListDNSScope(listA), model.AccessListDNSScope(listB)
	hostA := baseHost("00000000-0000-0000-0000-0000000000e3", "127.0.0.1", true)
	hostA.DomainNames, hostA.ForwardPort = []string{"domains.example.com"}, 8081
	hostB := baseHost("00000000-0000-0000-0000-0000000000e4", "127.0.0.1", true)
	hostB.DomainNames, hostB.ForwardPort = []string{"names.example.com"}, 8081
	const backendConf = "npg320r2_backend.conf"
	t.Cleanup(func() {
		for _, f := range []string{backendConf, GetConfigFilename(hostA), GetConfigFilename(hostB), "npg_request_path.conf"} {
			_ = os.Remove(filepath.Join(confd, f))
		}
		_ = os.RemoveAll(filepath.Join(confd, "includes"))
	})
	if err := os.WriteFile(filepath.Join(confd, backendConf), []byte("server {\n    listen 127.0.0.1:8081;\n    location / {\n        return 200 \"backend\\n\";\n    }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A: 127.0.0.4 by address, 127.0.0.3 denied by address, two domains.
	dataA := ProxyHostConfigData{Host: hostA, AccessList: &model.AccessList{ID: listA, Name: "partners", Items: []model.AccessListItem{
		{ID: "a1", Directive: "allow", Address: "127.0.0.4"},
		{ID: "a2", Directive: "deny", Address: "127.0.0.3", SortOrder: 1},
		{ID: "a3", Directive: "deny", Address: "all", Hostname: partner, SortOrder: 2},
		{ID: "a4", Directive: "deny", Address: "all", Hostname: shop, SortOrder: 3},
	}}}
	// B: one domain and nothing else.
	dataB := ProxyHostConfigData{Host: hostB, AccessList: &model.AccessList{ID: listB, Name: "partner-only", Items: []model.AccessListItem{
		{ID: "b1", Directive: "deny", Address: "all", Hostname: partner},
	}}}
	for _, d := range []ProxyHostConfigData{dataA, dataB} {
		if err := m.GenerateConfigFull(ctx, d); err != nil {
			t.Fatalf("GenerateConfigFull: %v", err)
		}
	}
	apply := func(step string) {
		t.Helper()
		if res := m.ApplyDNSIncludes(ctx); res.Outcome != "accepted" {
			t.Fatalf("%s: apply = %+v, want accepted (nginx started new workers)", step, res)
		}
	}
	expect := func(step, host, ip, want string) {
		t.Helper()
		if got := realHostStatus(t, container, host, ip, want); got != want {
			t.Errorf("%s: %s from %s = %s, want %s", step, host, ip, got, want)
		}
	}
	publish := func(scope, name string, gen int64, addrs ...string) {
		t.Helper()
		if _, err := m.WriteDNSIncludeFiles(scope, name, gen, addrs); err != nil {
			t.Fatal(err)
		}
	}

	// 1. The render created the three files empty: no domain lets anyone in.
	apply("empty files")
	expect("empty files", "domains.example.com", "127.0.0.2", "403")
	expect("empty files", "domains.example.com", "127.0.0.4", "200")
	expect("empty files", "names.example.com", "127.0.0.2", "403")

	// 2. partner resolves to .2 and .3. On A the list's own deny of .3 comes
	// first; on B, a list of that domain alone, both get in.
	publish(scopeA, partner, 1, "127.0.0.2", "127.0.0.3")
	publish(scopeB, partner, 1, "127.0.0.2", "127.0.0.3")
	apply("published")
	expect("published", "domains.example.com", "127.0.0.2", "200")
	expect("published", "domains.example.com", "127.0.0.3", "403")
	expect("published", "domains.example.com", "127.0.0.5", "403")
	expect("published", "names.example.com", "127.0.0.2", "200")
	expect("published", "names.example.com", "127.0.0.3", "200")

	// 3. B's partner is replaced by .3 alone, and partner leaves A's list
	// (its file is emptied): each list's file changes on its own.
	publish(scopeB, partner, 2, "127.0.0.3")
	publish(scopeA, partner, 2)
	apply("replaced")
	expect("replaced", "names.example.com", "127.0.0.2", "403")
	expect("replaced", "names.example.com", "127.0.0.3", "200")
	expect("replaced", "domains.example.com", "127.0.0.2", "403")

	// 4. A file that went missing: nginx -t blames the host file that
	// includes it, which SyncAll's recovery would remove. Rendering the host
	// creates the file again, empty, and nginx -t passes; B is then closed.
	keyB := DNSIncludeKey(scopeB, partner)
	if err := os.Remove(m.dnsIncludeDiskPath(keyB, ".allow")); err != nil {
		t.Fatal(err)
	}
	want := `open() "` + DNSIncludeRenderDir + "/" + keyB + `.allow" failed (2: No such file or directory) in /etc/nginx/conf.d/` + GetConfigFilename(hostB) + ":"
	if err := m.TestConfig(ctx); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("nginx -t with the file missing = %v, want an error with %q", err, want)
	}
	if err := m.GenerateConfigFull(ctx, dataB); err != nil {
		t.Fatalf("GenerateConfigFull: %v", err)
	}
	if info, err := os.Stat(m.dnsIncludeDiskPath(keyB, ".allow")); err != nil || info.Size() != 0 {
		t.Fatalf("the render did not create the missing file empty (%v)", err)
	}
	if err := m.TestConfig(ctx); err != nil {
		t.Fatalf("nginx -t after the render: %v", err)
	}
	apply("recreated")
	expect("recreated", "names.example.com", "127.0.0.3", "403")
}
