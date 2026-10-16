package nginx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

// Domain entries (#320) reach nginx through one include file per (scope,
// name): the addresses NPG published for the name, as "allow <addr>;" lines
// (.allow) or "<addr> 1;" geo lines (.geo). A rendered config holds only the
// file's path, a hash of the scope and the name, so a render depends on the
// database alone. The DNS entry service writes the files; the render, the
// applier and the service's boot pass create missing ones empty, because
// nginx -t fails on a missing include and SyncAll then removes the host that
// includes it. Nothing here ever writes an address the caller did not pass,
// and nothing restores an older content: that could bring back an address a
// revocation removed.

// DNSIncludeRenderDir is where rendered configs find the files. Go writes
// them under the manager's configPath (NGINX_CONFIG_PATH); in production both
// are the same directory.
const DNSIncludeRenderDir = "/etc/nginx/conf.d/includes/npg_dns"

// dnsIncludeHeaderPrefix starts a file's first line, its header.
const dnsIncludeHeaderPrefix = "# npg dns: "

var (
	// dnsIncludeHeader is a whole header line; name and scope are checked
	// again with the model's rules.
	dnsIncludeHeader = regexp.MustCompile(`^# npg dns: (\S+) scope (\S+) gen (\d{1,18})$`)
	// dnsIncludeFileName is a file name in the directory. Anything else (a
	// writeFileAtomic ".tmp-*" left by a crash, a file of a later version) is
	// not one of these files.
	dnsIncludeFileName = regexp.MustCompile(`^([0-9a-f]{16})(\.allow|\.geo)$`)
	dnsIncludeKeyRe    = regexp.MustCompile(`^[0-9a-f]{16}$`)
	// dnsIncludeRef is an include of one of the files, as a config renders it.
	dnsIncludeRef = regexp.MustCompile(regexp.QuoteMeta(DNSIncludeRenderDir) + `/([0-9a-f]{16})(\.allow|\.geo)\b`)
)

// DNSIncludeKey is the file name of a (scope, name) without its extension:
// the first 16 hex digits of sha256("npg-dns-v1\x00" + scope + "\x00" +
// name). No stored text reaches a path.
func DNSIncludeKey(scope, name string) string {
	sum := sha256.Sum256([]byte("npg-dns-v1\x00" + scope + "\x00" + name))
	return hex.EncodeToString(sum[:])[:16]
}

// DNSIncludeExts returns the extensions of a scope's files: ".allow" for an
// access list, ".geo" for the exception lists, both for the global trusted
// list; nil for a scope model.ParseDNSScope refuses.
func DNSIncludeExts(scope string) []string {
	kind, _, ok := model.ParseDNSScope(scope)
	if !ok {
		return nil
	}
	switch kind {
	case model.DNSScopeKindAccessList:
		return []string{".allow"}
	case model.DNSScopeKindURIBlock, model.DNSScopeKindPriority, model.DNSScopeKindRateLimit:
		return []string{".geo"}
	case model.DNSScopeKindTrusted:
		return []string{".allow", ".geo"}
	}
	return nil
}

// DNSIncludeRenderPath is the path a config includes for (scope, name) and
// ext, or "" when the scope, the name (model.ValidateDNSName) or the
// extension is not one of a file.
func DNSIncludeRenderPath(scope, name, ext string) string {
	if !slices.Contains(DNSIncludeExts(scope), ext) || model.ValidateDNSName(name) != nil {
		return ""
	}
	return DNSIncludeRenderDir + "/" + DNSIncludeKey(scope, name) + ext
}

// FormatDNSIncludeFile returns a file's content: the header
// "# npg dns: <name> scope <scope> gen <gen>", then one line per address,
// "allow <addr>;" for ".allow" and "<addr> 1;" for ".geo". The header is
// left out unless name, scope and gen are valid, so no unchecked text ever
// reaches the file. Addresses are written as canonicalDNSIncludeAddrs
// returns them; anything that is not one IP address is left out. nil for any
// other extension.
func FormatDNSIncludeFile(name, scope string, gen int64, ext string, addrs []string) []byte {
	var line func(addr string) string
	switch ext {
	case ".allow":
		line = func(addr string) string { return "allow " + addr + ";\n" }
	case ".geo":
		line = func(addr string) string { return addr + " 1;\n" }
	default:
		return nil
	}
	var b strings.Builder
	if _, _, ok := model.ParseDNSScope(scope); ok && model.ValidateDNSName(name) == nil && gen >= 0 {
		b.WriteString(dnsIncludeHeaderPrefix + name + " scope " + scope + " gen " + strconv.FormatInt(gen, 10) + "\n")
	}
	kept, _ := canonicalDNSIncludeAddrs(addrs)
	for _, a := range kept {
		b.WriteString(line(a))
	}
	return []byte(b.String())
}

// ParseDNSIncludeHeader reads a file's first line. ok is false unless it is
// a header FormatDNSIncludeFile writes, with a valid name and scope.
func ParseDNSIncludeHeader(line string) (name, scope string, gen int64, ok bool) {
	m := dnsIncludeHeader.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
	if m == nil {
		return "", "", 0, false
	}
	if _, _, valid := model.ParseDNSScope(m[2]); !valid || model.ValidateDNSName(m[1]) != nil {
		return "", "", 0, false
	}
	gen, err := strconv.ParseInt(m[3], 10, 64)
	if err != nil {
		return "", "", 0, false
	}
	return m[1], m[2], gen, true
}

// canonicalDNSIncludeAddrs returns the IP addresses in addrs as a file
// holds them: parsed, IPv4-mapped IPv6 unmapped (an "allow ::ffff:a.b.c.d;"
// passes nginx -t but never matches the IPv4 client),
// deduplicated, sorted, in netip's text form. A CIDR range, "all", an
// address with a zone or any other text is dropped and counted: one bad line
// fails every nginx -t and keeps nginx from starting.
func canonicalDNSIncludeAddrs(addrs []string) (kept []string, dropped int) {
	parsed := make([]netip.Addr, 0, len(addrs))
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			dropped++
			continue
		}
		parsed = append(parsed, a.Unmap())
	}
	slices.SortFunc(parsed, func(a, b netip.Addr) int { return a.Compare(b) })
	parsed = slices.Compact(parsed)
	kept = make([]string, len(parsed))
	for i, a := range parsed {
		kept[i] = a.String()
	}
	return kept, dropped
}

// DNSIncludeFile is one file of the directory as ReadDNSIncludeDir read it.
// Name, Scope and Gen come from its header, which counts (HasHeader) only
// when it names a (scope, name) whose key and extensions match the file; a
// file the render or the applier created has none. Empty: no line nginx
// reads (nothing, the header, comments). Addrs: the addresses of its
// "allow <addr>;" or "<addr> 1;" lines, in file order.
type DNSIncludeFile struct {
	Key, Ext, Name, Scope string
	Gen                   int64
	HasHeader, Empty      bool
	ModTime               time.Time
	Addrs                 []string
}

func (m *Manager) dnsIncludeDiskDir() string {
	return filepath.Join(m.configPath, "includes", "npg_dns")
}

func (m *Manager) dnsIncludeDiskPath(key, ext string) string {
	return filepath.Join(m.dnsIncludeDiskDir(), key+ext)
}

// WriteDNSIncludeFiles writes every file of (scope, name) with the header
// generation gen and the addresses addrs, atomically (writeFileAtomic), and
// leaves a file alone when it already holds exactly that. changed reports
// whether any file was written. An invalid scope, name or gen writes nothing.
// It takes no lock: the DNS entry service calls it under its own.
func (m *Manager) WriteDNSIncludeFiles(scope, name string, gen int64, addrs []string) (changed bool, err error) {
	exts := DNSIncludeExts(scope)
	if exts == nil {
		return false, fmt.Errorf("domain entry files: invalid scope %q", scope)
	}
	if err := model.ValidateDNSName(name); err != nil {
		return false, fmt.Errorf("domain entry files: invalid name %q: %w", name, err)
	}
	if gen < 0 {
		return false, fmt.Errorf("domain entry files: invalid generation %d for %s", gen, name)
	}
	if _, dropped := canonicalDNSIncludeAddrs(addrs); dropped > 0 {
		warnSkippedOnce("dns-include-addrs\x00"+scope+"\x00"+name,
			"[DNSEntries] WARN: %d address(es) of %s (%s) are not single IP addresses and are left out of its include file", dropped, name, scope)
	}
	key := DNSIncludeKey(scope, name)
	for _, ext := range exts {
		content := FormatDNSIncludeFile(name, scope, gen, ext, addrs)
		path := m.dnsIncludeDiskPath(key, ext)
		if old, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(old, content) {
			continue
		}
		if err := m.writeFileAtomic(path, content, 0644); err != nil {
			return changed, fmt.Errorf("write domain include %s%s of %s (%s): %w", key, ext, name, scope, err)
		}
		changed = true
	}
	return changed, nil
}

// ReadDNSIncludeDir reads every file of the directory, in name order. A
// missing directory has none.
func (m *Manager) ReadDNSIncludeDir() ([]DNSIncludeFile, error) {
	dir := m.dnsIncludeDiskDir()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read domain include directory: %w", err)
	}
	var files []DNSIncludeFile
	for _, e := range entries {
		parts := dnsIncludeFileName.FindStringSubmatch(e.Name())
		if parts == nil || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		var data []byte
		if err == nil {
			data, err = os.ReadFile(filepath.Join(dir, e.Name()))
		}
		if errors.Is(err, fs.ErrNotExist) {
			continue // removed meanwhile
		}
		if err != nil {
			return nil, fmt.Errorf("read domain include %s: %w", e.Name(), err)
		}
		f := DNSIncludeFile{Key: parts[1], Ext: parts[2], ModTime: info.ModTime()}
		parseDNSIncludeContent(&f, data)
		files = append(files, f)
	}
	return files, nil
}

// parseDNSIncludeContent fills f's header and line fields from data.
func parseDNSIncludeContent(f *DNSIncludeFile, data []byte) {
	f.Empty = true
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if i == 0 {
			name, scope, gen, ok := ParseDNSIncludeHeader(line)
			if ok && DNSIncludeKey(scope, name) == f.Key && slices.Contains(DNSIncludeExts(scope), f.Ext) {
				f.Name, f.Scope, f.Gen, f.HasHeader = name, scope, gen, true
				continue
			}
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f.Empty = false
		if addr, ok := parseDNSIncludeLine(line, f.Ext); ok {
			f.Addrs = append(f.Addrs, addr)
		}
	}
}

// parseDNSIncludeLine returns the address of one line FormatDNSIncludeFile
// writes for ext.
func parseDNSIncludeLine(line, ext string) (string, bool) {
	var s string
	var ok bool
	switch ext {
	case ".allow":
		if s, ok = strings.CutPrefix(line, "allow "); ok {
			s, ok = strings.CutSuffix(s, ";")
		}
	case ".geo":
		s, ok = strings.CutSuffix(line, " 1;")
	}
	if !ok {
		return "", false
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", false
	}
	return a.String(), true
}

// ScanDNSIncludeReferences returns the files ("<key><ext>") that conf.d/*.conf
// and nginx.conf include. On an error the map holds what could be read, and
// the error names the first file that could not: a caller that deletes files
// must not use it then.
func (m *Manager) ScanDNSIncludeReferences() (map[string]bool, error) {
	refs := make(map[string]bool)
	paths, err := filepath.Glob(filepath.Join(m.configPath, "*.conf"))
	if err != nil {
		return refs, err
	}
	paths = append(paths, filepath.Join(filepath.Dir(m.configPath), "nginx.conf"))
	var firstErr error
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue // removed meanwhile, or no nginx.conf yet
		}
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("scan %s for domain includes: %w", filepath.Base(p), err)
			}
			continue
		}
		for _, ref := range dnsIncludeRef.FindAllSubmatch(data, -1) {
			refs[string(ref[1])+string(ref[2])] = true
		}
	}
	return refs, firstErr
}

// EnsureDNSIncludeFile creates the file key+ext empty when it is missing
// (O_EXCL: never over a file someone wrote meanwhile). An existing file keeps
// its content and gets a fresh modification time, best effort: a render
// outside the nginx lock may be about to include it, and the GC removes only
// files that have been empty for a day.
func (m *Manager) EnsureDNSIncludeFile(key, ext string) error {
	if !dnsIncludeKeyRe.MatchString(key) || (ext != ".allow" && ext != ".geo") {
		return fmt.Errorf("invalid domain include file %q", key+ext)
	}
	if err := os.MkdirAll(m.dnsIncludeDiskDir(), 0755); err != nil {
		return fmt.Errorf("create domain include directory: %w", err)
	}
	path := m.dnsIncludeDiskPath(key, ext)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err == nil {
		return f.Close()
	}
	if errors.Is(err, fs.ErrExist) {
		now := time.Now()
		_ = os.Chtimes(path, now, now) // EPERM on a file the API did not create: harmless
		return nil
	}
	return fmt.Errorf("create domain include %s%s: %w", key, ext, err)
}

// DNSApplyResult is what ApplyDNSIncludes did. Outcome is one of:
//
//	accepted, rejected, unconfirmed, signalled: nginx -t passed and the
//	  reload went out (ReloadOutcome; signalled = confirmation off, and
//	  unconfirmed without Snapshot = the processes could not be read before
//	  the signal)
//	blocked:  nginx fails on an [emerg] no npg_dns file is to blame for, or
//	  that the repairs could not clear; BlockingFile is the file nginx
//	  names ("proxy_host_shop_example_com.conf"), Detail its message
//	failed:   no [emerg] to go by (docker, I/O, a cancelled context)
//	not_up:   the nginx container, or nginx in it, is not running
//	skipped:  NGINX_SKIP_TEST=true, so there is no nginx to apply to
//
// Snapshot is the process snapshot taken before an unconfirmed signal, for
// ReloadTakenSince. Detail and BlockingFile hold only nginx's own words.
type DNSApplyResult struct {
	Outcome      string
	Detail       string
	BlockingFile string
	Snapshot     *ReloadSnapshot
}

// Outcomes of DNSApplyResult besides the reload ones.
const (
	dnsApplyBlocked = "blocked"
	dnsApplyFailed  = "failed"
	dnsApplyNotUp   = "not_up"
	dnsApplySkipped = "skipped"
)

var (
	// nginxEmergMessage is an [emerg] message of nginx -t's output, in
	// either form nginx prints it: the error log line
	// ("2026/10/15 02:36:40 [emerg] 8#8: <msg>") or the console line
	// ("nginx: [emerg] <msg>"). Other levels are skipped: a duplicate
	// network [warn] names some other host's file.
	nginxEmergMessage = regexp.MustCompile(`\[emerg\] (?:\d+#\d+: )?(?:\*\d+ )?([^\r\n]*)`)
	// dnsIncludeMissing is nginx -t naming a missing npg_dns file. The
	// location after it is the including file, never the npg_dns one.
	dnsIncludeMissing = regexp.MustCompile(`^open\(\) "` + regexp.QuoteMeta(DNSIncludeRenderDir) +
		`/([0-9a-f]{16})(\.allow|\.geo)" failed \(2: No such file or directory\)`)
	// dnsIncludeAtFault is an [emerg] located inside an npg_dns file.
	dnsIncludeAtFault = regexp.MustCompile(` in ` + regexp.QuoteMeta(DNSIncludeRenderDir) + `/([0-9a-f]{16})(\.allow|\.geo):\d+$`)
	// nginxEmergFile is the file an [emerg] message is located in.
	nginxEmergFile = regexp.MustCompile(` in (/\S+):\d+$`)
)

// firstEmergMessage returns nginx's first [emerg] message in text, or "".
func firstEmergMessage(text string) string {
	if m := nginxEmergMessage.FindStringSubmatch(text); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// ApplyDNSIncludes makes nginx load the npg_dns files as they are on disk:
// under the nginx lock it runs nginx -t, repairs what an npg_dns file is to
// blame for (testDNSIncludesRepairing), and signals a reload
// (reloadNginxOutcome). It writes no address, runs no post-reload health
// probe and never rolls a file back. The reload hooks hear of its reload
// like of any other, before it returns; its token comes from
// ReloadHooks.BeforeDNSApply when that is set.
func (m *Manager) ApplyDNSIncludes(ctx context.Context) DNSApplyResult {
	if m.skipTest {
		return DNSApplyResult{Outcome: dnsApplySkipped}
	}
	var (
		atSignal ReloadOutcome   // what reloadNginxOutcome knew when it returned
		snap     *ReloadSnapshot // the snapshot executeWithLockOutcome confirms against
	)
	confirmed, err := m.executeWithLockOutcome(ctx, func() error {
		if err := m.testDNSIncludesRepairing(ctx); err != nil {
			return err
		}
		outcome, err := m.reloadNginxOutcome(ctx, true)
		if err != nil {
			return err
		}
		atSignal = outcome
		if p := m.pendingReload; p != nil {
			snap = &ReloadSnapshot{before: p.before}
		}
		return nil
	})
	if err != nil {
		return dnsApplyFailure(err)
	}
	outcome := confirmed
	if outcome == "" {
		outcome = atSignal
	}
	res := DNSApplyResult{Outcome: string(outcome)}
	if outcome == ReloadUnconfirmed {
		res.Snapshot = snap
	}
	return res
}

// dnsApplyFailure sorts the error of a failed apply.
func dnsApplyFailure(err error) DNSApplyResult {
	var rejected *ReloadRejectedError
	if errors.As(err, &rejected) {
		return DNSApplyResult{Outcome: string(ReloadRejected), Detail: rejected.Detail}
	}
	if notUpYet(err) {
		return DNSApplyResult{Outcome: dnsApplyNotUp}
	}
	msg := firstEmergMessage(err.Error())
	if msg == "" {
		return DNSApplyResult{Outcome: dnsApplyFailed}
	}
	res := DNSApplyResult{Outcome: dnsApplyBlocked, Detail: cleanEmergLine(msg)}
	if loc := nginxEmergFile.FindStringSubmatch(msg); loc != nil {
		res.BlockingFile = filepath.Base(loc[1])
	}
	return res
}

// testDNSIncludesRepairing runs nginx -t (with testConfigWithRetry's retries
// for docker hiccups) and repairs what an npg_dns file is to blame for.
// nginx -t stops at its first [emerg], so each run names one problem:
//   - a missing npg_dns file is created empty (EnsureDNSIncludeFile);
//   - an [emerg] inside an npg_dns file (in theory impossible: the files hold
//     a comment and netip's output) empties that file, header and all.
//
// Each file is repaired at most once, and there are at most as many repairs
// as files the configs include, plus one for an include written after the
// scan. Anything else is returned as it is. Must run within executeWithLock.
func (m *Manager) testDNSIncludesRepairing(ctx context.Context) error {
	var refs map[string]bool // read at the first repair
	repaired := make(map[string]bool)
	for {
		err := m.testConfigWithRetry(ctx)
		if err == nil {
			return nil
		}
		msg := firstEmergMessage(err.Error())
		missing := dnsIncludeMissing.FindStringSubmatch(msg)
		atFault := dnsIncludeAtFault.FindStringSubmatch(msg)
		var file []string
		switch {
		case missing != nil:
			file = missing[1:3]
		case atFault != nil:
			file = atFault[1:3]
		default:
			return err
		}
		key, ext := file[0], file[1]
		if refs == nil {
			refs, _ = m.ScanDNSIncludeReferences() // only a bound: what it could read will do
		}
		if repaired[key+ext] || len(repaired) > len(refs) {
			return err
		}
		repaired[key+ext] = true
		if missing != nil {
			if ensureErr := m.EnsureDNSIncludeFile(key, ext); ensureErr != nil {
				log.Printf("[DNSEntries] ERROR: nginx -t names the missing domain include %s%s, and creating it failed: %v", key, ext, ensureErr)
				return err
			}
			log.Printf("[DNSEntries] WARN: nginx -t named the missing domain include %s%s; created it empty", key, ext)
			continue
		}
		if writeErr := m.writeFileAtomic(m.dnsIncludeDiskPath(key, ext), nil, 0644); writeErr != nil {
			log.Printf("[DNSEntries] ERROR: nginx -t refuses the domain include %s%s (%s), and emptying it failed: %v", key, ext, cleanEmergLine(msg), writeErr)
			return err
		}
		log.Printf("[DNSEntries] ERROR: nginx -t refused the domain include %s%s (%s); emptied it, so it allows no one until the next write", key, ext, cleanEmergLine(msg))
	}
}

// GCDNSIncludeFiles removes, under the nginx lock, the files nothing needs: a
// file no config includes (a fresh ScanDNSIncludeReferences in the lock),
// unchanged for more than minEmptyAge, and either without a header or
// empty with a header naming a (scope, name) that referenced reports unused.
// referenced runs under the nginx lock: it may read the database but must
// not take the DNS entry service's lock. A nil referenced keeps every file
// with a header. If the configs cannot all be read, nothing is removed.
func (m *Manager) GCDNSIncludeFiles(ctx context.Context, referenced func(scope, name string) bool, minEmptyAge time.Duration) (removed int, err error) {
	err = m.executeWithLock(ctx, func() error {
		files, err := m.ReadDNSIncludeDir()
		if err != nil || len(files) == 0 {
			return err
		}
		refs, err := m.ScanDNSIncludeReferences()
		if err != nil {
			return err
		}
		for _, f := range files {
			if refs[f.Key+f.Ext] || time.Since(f.ModTime) <= minEmptyAge {
				continue
			}
			if f.HasHeader && (!f.Empty || referenced == nil || referenced(f.Scope, f.Name)) {
				continue
			}
			path := m.dnsIncludeDiskPath(f.Key, f.Ext)
			// A render outside the lock may have refreshed it since it was
			// read (EnsureDNSIncludeFile).
			if info, statErr := os.Lstat(path); statErr != nil || !info.ModTime().Equal(f.ModTime) {
				continue
			}
			if rmErr := os.Remove(path); rmErr != nil {
				log.Printf("[DNSEntries] WARN: could not remove the unused domain include %s%s: %v", f.Key, f.Ext, rmErr)
				continue
			}
			removed++
		}
		return nil
	})
	return removed, err
}
