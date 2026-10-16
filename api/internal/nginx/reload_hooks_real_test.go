package nginx

// Checks against a real nginx, skipped unless NPG_REAL_NGINX_CONTAINER names a
// running, disposable container of the nginx image whose /etc/nginx/conf.d is
// the host directory NPG_REAL_NGINX_CONFD, whose nginx.conf includes
// conf.d/*.conf, and whose error log goes to stderr (as in production). The
// tests write into that directory and reload that nginx. Start one with no
// network:
//
//	docker run -d --name npg-real-nginx --network none \
//	  -v <dir>/nginx.conf:/etc/nginx/nginx.conf:ro -v <dir>/conf.d:/etc/nginx/conf.d \
//	  --entrypoint sh nginxproxyguard-nginx:latest \
//	  -c 'ln -sf /dev/stderr /var/log/nginx/error.log; exec nginx -g "daemon off;"'
//	NPG_REAL_NGINX_CONTAINER=npg-real-nginx NPG_REAL_NGINX_CONFD=<dir>/conf.d \
//	  go test ./internal/nginx/ -run TestReal -count=1 -v

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// realNginxManager returns a manager for that container, with reload
// confirmation on, and its conf.d directory.
func realNginxManager(t *testing.T) (*Manager, string) {
	t.Helper()
	name, confd := os.Getenv("NPG_REAL_NGINX_CONTAINER"), os.Getenv("NPG_REAL_NGINX_CONFD")
	if name == "" || confd == "" {
		t.Skip("set NPG_REAL_NGINX_CONTAINER and NPG_REAL_NGINX_CONFD to run against a disposable nginx container")
	}
	t.Setenv("NGINX_CONTAINER", name)
	t.Setenv("NGINX_SKIP_TEST", "false")
	m := NewManager(confd, t.TempDir())
	m.SetHealthProber(NewHealthProber(name, "8080", false))
	return m, confd
}

// realSnapshot reads nginx's processes the way the reload confirmation does.
func realSnapshot(t *testing.T, m *Manager) *ReloadSnapshot {
	t.Helper()
	master, children, err := m.reloadProbe.Children(context.Background())
	if err != nil {
		t.Fatalf("read nginx's processes: %v", err)
	}
	return &ReloadSnapshot{before: reloadSnapshot{master: master, children: children}}
}

// realZoneConf is a server whose limit_req zone takes the key %s. nginx -t
// accepts any key, but a running nginx refuses a reload that changes it.
const realZoneConf = `limit_req_zone %s zone=npg320r2_zone:1m rate=10r/s;
server {
    listen 8080;
    location / {
        limit_req zone=npg320r2_zone;
        return 200 "ok\n";
    }
}
`

func TestRealReloadHooksAndReloadTakenSince(t *testing.T) {
	m, confd := realNginxManager(t)
	ctx := context.Background()
	rec := &recordingHooks{}
	m.SetReloadHooks(rec.hooks())
	conf := filepath.Join(confd, "npg320r2_reload.conf")
	t.Cleanup(func() { _ = os.Remove(conf) })
	write := func(key string) {
		t.Helper()
		if err := os.WriteFile(conf, []byte(fmt.Sprintf(realZoneConf, key)), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := m.TestConfig(ctx); err != nil {
			t.Fatalf("nginx -t: %v", err)
		}
	}

	// A reload nginx takes: new workers.
	write("$binary_remote_addr")
	snap := realSnapshot(t, m)
	if err := m.ReloadNginx(ctx); err != nil {
		t.Fatalf("ReloadNginx: %v", err)
	}
	if taken, err := m.ReloadTakenSince(ctx, snap); err != nil || !taken {
		t.Fatalf("after an accepted reload: ReloadTakenSince = %v, %v; want true, nil", taken, err)
	}

	// A reload nginx refuses: nginx -t passes, the running master keeps its
	// zone's key and its workers.
	write("$remote_addr")
	snap = realSnapshot(t, m)
	if err := m.ReloadNginx(ctx); !errors.Is(err, ErrReloadRejected) {
		t.Fatalf("ReloadNginx = %v, want ErrReloadRejected", err)
	}
	if taken, err := m.ReloadTakenSince(ctx, snap); err != nil || taken {
		t.Fatalf("after a refused reload: ReloadTakenSince = %v, %v; want false, nil", taken, err)
	}

	if len(rec.afters) != 2 {
		t.Fatalf("After was called %d time(s) (%+v), want twice", len(rec.afters), rec.afters)
	}
	if a, b := rec.afters[0], rec.afters[1]; a.token != 1 || a.outcome != ReloadAccepted || b.token != 2 || b.outcome != ReloadRejected {
		t.Fatalf("After calls %+v, want (1, accepted) then (2, rejected)", rec.afters)
	}
}
