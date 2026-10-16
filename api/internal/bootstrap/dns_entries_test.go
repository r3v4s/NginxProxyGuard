package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/repository"
)

func TestDNSEntriesEnvDisabled(t *testing.T) {
	for v, want := range map[string]bool{
		"": false, "0": false, "false": false, "no": false, "off": false,
		"1": true, "true": true, "TRUE": true, "yes": true, " Yes ": true,
	} {
		t.Setenv("NPG_DNS_ENTRIES_DISABLED", v)
		if got := dnsEntriesEnvDisabled(); got != want {
			t.Errorf("NPG_DNS_ENTRIES_DISABLED=%q -> %v, want %v", v, got, want)
		}
	}
}

// Unset leaves the interval to the settings (0). A bad value is ignored; one
// outside 5s..1h is brought inside, below the screen's 30 s minimum on purpose.
func TestDNSEntriesEnvInterval(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want time.Duration
	}{
		{"", 0},
		{"60s", time.Minute},
		{" 30s ", 30 * time.Second},
		{"5s", 5 * time.Second},
		{"1s", 5 * time.Second},
		{"2h", time.Hour},
		{"soon", 0},
		{"60", 0},
		{"0s", 0},
		{"-5s", 0},
	} {
		t.Setenv("NPG_DNS_ENTRIES_INTERVAL", tc.env)
		if got := dnsEntriesEnvInterval(); got != tc.want {
			t.Errorf("NPG_DNS_ENTRIES_INTERVAL=%q -> %v, want %v", tc.env, got, tc.want)
		}
	}
}

func TestDNSEntryOptionsFromTheEnvironment(t *testing.T) {
	t.Setenv("NPG_DNS_ENTRIES_DISABLED", "1")
	t.Setenv("NPG_DNS_ENTRIES_INTERVAL", "5s")
	opts := dnsEntryOptions()
	if !opts.EnvDisabled || opts.EnvInterval != 5*time.Second {
		t.Fatalf("options = %+v, want the switch on and a 5s interval", opts)
	}
	if opts.Policy != nil || opts.Lookuper != nil || opts.Now != nil {
		t.Fatalf("options = %+v, want the service's defaults for the rest", opts)
	}
}

type fakeDNSEnvAudit struct {
	calls int
	err   error
}

func (f *fakeDNSEnvAudit) LogDNSEntriesEnvDisabled(ctx context.Context) error {
	f.calls++
	return f.err
}

type fakeDNSEnvSystemLog struct {
	rows []repository.SystemLog
	err  error
}

func (f *fakeDNSEnvSystemLog) Create(ctx context.Context, l *repository.SystemLog) error {
	f.rows = append(f.rows, *l)
	return f.err
}

// captureDNSEntriesLog sends the standard logger to a buffer until the test ends.
func captureDNSEntriesLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	})
	return &buf
}

// The switch is announced in all three places at every start: a container
// line the log collector files as WARN, a system audit row and a WARN system
// log row of the dns_entries component. A failed write does not stop the rest.
func TestAnnounceDNSEntriesEnvDisabled(t *testing.T) {
	out := captureDNSEntriesLog(t)
	audit := &fakeDNSEnvAudit{err: errors.New("audit insert failed")}
	syslog := &fakeDNSEnvSystemLog{}
	announceDNSEntriesEnvDisabled(context.Background(), audit, syslog)

	if !strings.HasPrefix(out.String(), "[DNSEntries] WARN: NPG_DNS_ENTRIES_DISABLED is set") {
		t.Fatalf("container log = %q, want it to start with the WARN line", out.String())
	}
	if !strings.Contains(out.String(), "could not record NPG_DNS_ENTRIES_DISABLED in the audit log") {
		t.Errorf("container log = %q, want the failed audit write reported", out.String())
	}
	if audit.calls != 1 {
		t.Errorf("audit rows = %d, want 1", audit.calls)
	}
	if len(syslog.rows) != 1 {
		t.Fatalf("system log rows = %d, want 1 even though the audit write failed", len(syslog.rows))
	}
	row := syslog.rows[0]
	if row.Source != repository.SourceScheduler || row.Level != repository.LevelWarn || row.Component != "dns_entries" ||
		row.Message != dnsEntriesEnvDisabledMessage {
		t.Errorf("system log row = %+v", row)
	}
}

// runStartup brings the domain include files in line with the database
// before its first step that writes or reloads nginx config:
// otherwise the boot's reloads would serve the files as they were
// before the API was down, grace expiry undone.
func TestStartupReconcilesDomainFilesBeforeAnyReload(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "startup.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "runStartup" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("runStartup not found in startup.go")
	}
	first := map[string]token.Pos{}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		}
		if _, seen := first[name]; !seen && name != "" {
			first[name] = call.Pos()
		}
		return true
	})
	at, ok := first["startDNSEntries"]
	if !ok {
		t.Fatal("runStartup does not call startDNSEntries")
	}
	for _, later := range []string{"mainNginxConfStep", "filterSubscriptionStep", "SyncAllConfigs",
		"GenerateDefaultServerConfig", "GenerateAllRedirectConfigsAndReload"} {
		pos, ok := first[later]
		if !ok {
			t.Errorf("runStartup no longer calls %s; check where startDNSEntries belongs", later)
			continue
		}
		if pos < at {
			t.Errorf("runStartup calls %s before startDNSEntries", later)
		}
	}
}
