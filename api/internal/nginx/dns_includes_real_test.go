package nginx

// The applier against a real nginx; skipped unless
// NPG_REAL_NGINX_CONTAINER and NPG_REAL_NGINX_CONFD are set, as in
// reload_hooks_real_test.go. The container needs curl (the nginx image has
// it) and no network: clients are its own loopback addresses.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// realStatus asks the container's nginx for / from the loopback address ip
// until it answers want (old workers can take a request or two after a
// reload), and returns the last answer.
func realStatus(t *testing.T, container, ip, want string) string {
	t.Helper()
	var got string
	for deadline := time.Now().Add(3 * time.Second); ; {
		out, err := exec.Command("docker", "exec", container, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
			"--interface", ip, "http://127.0.0.1:8080/").CombinedOutput()
		if err != nil {
			t.Fatalf("curl from %s: %v: %s", ip, err, out)
		}
		got = strings.TrimSpace(string(out))
		if got == want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestRealApplyDNSIncludes(t *testing.T) {
	m, confd := realNginxManager(t)
	container := os.Getenv("NPG_REAL_NGINX_CONTAINER")
	ctx := context.Background()
	keyA, keyB := DNSIncludeKey(dnsScopeA, dnsPartner)+".allow", DNSIncludeKey(dnsScopeB, dnsPartner)+".allow"
	host := filepath.Join(confd, "proxy_host_example_com.conf")
	broken := filepath.Join(confd, "proxy_host_shop_example_com.conf")
	t.Cleanup(func() {
		_ = os.Remove(host)
		_ = os.Remove(broken)
		_ = os.RemoveAll(filepath.Join(confd, "includes"))
	})
	conf := "server {\n    listen 127.0.0.1:8081;\n    location / {\n        return 200 \"backend\\n\";\n    }\n}\n" +
		"server {\n    listen 8080;\n    location / {\n" +
		"        include " + DNSIncludeRenderDir + "/" + keyA + ";\n" +
		"        include " + DNSIncludeRenderDir + "/" + keyB + ";\n" +
		"        deny all;\n        proxy_pass http://127.0.0.1:8081;\n    }\n}\n"
	if err := os.WriteFile(host, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	// Both files are missing: nginx -t names one per run, each is created
	// empty, and nginx takes the reload. Nobody is allowed yet.
	if res := m.ApplyDNSIncludes(ctx); res.Outcome != "accepted" {
		t.Fatalf("missing files: %+v, want accepted", res)
	}
	for _, f := range []string{keyA, keyB} {
		if got, ok := readDNSFile(t, m, f); !ok || got != "" {
			t.Fatalf("%s: %q (exists %v), want an empty file", f, got, ok)
		}
	}
	if got := realStatus(t, container, "127.0.0.2", "403"); got != "403" {
		t.Fatalf("empty files: 127.0.0.2 got %s, want 403", got)
	}

	// The service writes an IPv4-mapped answer: the file holds it unmapped,
	// so it matches the IPv4 client.
	if _, err := m.WriteDNSIncludeFiles(dnsScopeA, dnsPartner, 1, []string{"::ffff:127.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	if res := m.ApplyDNSIncludes(ctx); res.Outcome != "accepted" {
		t.Fatalf("after a write: %+v, want accepted", res)
	}
	if got := realStatus(t, container, "127.0.0.2", "200"); got != "200" {
		t.Fatalf("published 127.0.0.2: got %s, want 200", got)
	}
	if got := realStatus(t, container, "127.0.0.3", "403"); got != "403" {
		t.Fatalf("127.0.0.3: got %s, want 403", got)
	}

	// Another host's broken config blocks the apply. The files stay, and
	// nginx keeps serving what it had.
	before, _ := readDNSFile(t, m, keyA)
	if err := os.WriteFile(broken, []byte("server {\n    listen 8082;\n    npg320r2_unknown_directive on;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := m.ApplyDNSIncludes(ctx)
	if res.Outcome != "blocked" || res.BlockingFile != "proxy_host_shop_example_com.conf" || !strings.Contains(res.Detail, `unknown directive "npg320r2_unknown_directive"`) {
		t.Fatalf("broken host: %+v, want blocked by proxy_host_shop_example_com.conf", res)
	}
	if after, _ := readDNSFile(t, m, keyA); after != before {
		t.Fatalf("a blocked apply changed %s: %q", keyA, after)
	}
	if got := realStatus(t, container, "127.0.0.2", "200"); got != "200" {
		t.Fatalf("while blocked: 127.0.0.2 got %s, want 200 (the running configuration)", got)
	}
	if err := os.Remove(broken); err != nil {
		t.Fatal(err)
	}

	// A file nginx refuses is emptied, never restored: 127.0.0.2 loses access.
	writeDNSFile(t, m, keyA, before+"allow 198.51.100.999;\n")
	if res := m.ApplyDNSIncludes(ctx); res.Outcome != "accepted" {
		t.Fatalf("refused file: %+v, want accepted", res)
	}
	if got, _ := readDNSFile(t, m, keyA); got != "" {
		t.Fatalf("refused file: %q, want it emptied", got)
	}
	if got := realStatus(t, container, "127.0.0.2", "403"); got != "403" {
		t.Fatalf("emptied file: 127.0.0.2 got %s, want 403", got)
	}

	// A file removed behind nginx's back comes back empty.
	if err := os.Remove(m.dnsIncludeDiskPath(keyB[:16], ".allow")); err != nil {
		t.Fatal(err)
	}
	if res := m.ApplyDNSIncludes(ctx); res.Outcome != "accepted" {
		t.Fatalf("removed file: %+v, want accepted", res)
	}
	if _, ok := readDNSFile(t, m, keyB); !ok {
		t.Fatalf("%s was not created again", keyB)
	}

	// GC: both files are included, so neither goes; once the host is gone,
	// both are unused, header-less and old enough.
	unused := func(string, string) bool { return false }
	if removed, err := m.GCDNSIncludeFiles(ctx, unused, 0); err != nil || removed != 0 {
		t.Fatalf("GC with the host in place: removed %d, %v; want 0, nil", removed, err)
	}
	if err := os.Remove(host); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	for _, f := range []string{keyA, keyB} {
		if err := os.Chtimes(m.dnsIncludeDiskPath(f[:16], ".allow"), old, old); err != nil {
			t.Fatal(err)
		}
	}
	if removed, err := m.GCDNSIncludeFiles(ctx, unused, 30*time.Minute); err != nil || removed != 2 {
		t.Fatalf("GC without the host: removed %d, %v; want 2, nil", removed, err)
	}
	if res := m.ApplyDNSIncludes(ctx); res.Outcome != "accepted" {
		t.Fatalf("after the GC: %+v, want accepted", res)
	}

	// The nginx container is down: not_up, not blocked.
	if out, err := exec.Command("docker", "stop", "-t", "1", container).CombinedOutput(); err != nil {
		t.Fatalf("docker stop: %v: %s", err, out)
	}
	if res := m.ApplyDNSIncludes(ctx); res.Outcome != "not_up" {
		t.Fatalf("stopped container: %+v, want not_up", res)
	}
}
