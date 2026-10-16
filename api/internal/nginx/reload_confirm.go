package nginx

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/metrics"
)

// ErrReloadRejected is what errors.Is matches when the running nginx did not
// take a reload. nginx -t passed and the files on disk are the ones the
// database describes, but the master refused them and kept its previous
// configuration, while `nginx -s reload` still exited 0. The master checks
// more than nginx -t does: a limit_req zone it already has may not change its
// key, and a port it is to listen on may be taken.
//
// Callers keep the files. Restoring the previous ones would undo a change
// nginx -t accepted and leave the database and the disk apart, and the
// restart that applies a refused reload would then load the undone state.
var ErrReloadRejected = errors.New("nginx kept its previous configuration")

// ReloadRejectedError is the error of a refused reload. Detail is the [emerg]
// line nginx logged for it without its timestamp, or "" when none was found.
// Error() leaves Detail out: handlers sort errors by words in their text, and
// nginx's line may hold one of them ("invalid ..."), which would turn this
// into a 400.
type ReloadRejectedError struct {
	Detail string
}

func (e *ReloadRejectedError) Error() string {
	const saved = "the change is saved, but the running nginx refused to load it and keeps its previous configuration"
	switch {
	case strings.Contains(e.Detail, "bind()"):
		// The kept file listens on the port, so nginx, which runs on the
		// host network and restarts by itself, cannot start again while
		// another program holds it: a restart would take every site down.
		return saved + "; a port it is to listen on is in use, and nginx cannot start again while that port is taken, so do not restart it: free the port, or change or delete the host that listens on it"
	case strings.Contains(e.Detail, "shared memory zone"), strings.Contains(e.Detail, "previously it used"):
		return saved + "; restart the nginx container to apply it"
	}
	return saved + "; nginx's reason is in the nginx container's log"
}

// Is makes errors.Is(err, ErrReloadRejected) match.
func (e *ReloadRejectedError) Is(target error) bool { return target == ErrReloadRejected }

// reloadProbe reads what confirming a reload needs from the nginx container.
// Tests substitute a fake.
type reloadProbe interface {
	// Children returns the pid of nginx's master process and the pids of its
	// children: the workers, and the cache manager and loader.
	Children(ctx context.Context) (master int, children map[int]bool, err error)
	// EmergSince returns the [emerg] lines nginx logged at or after since.
	EmergSince(ctx context.Context, since time.Time) ([]string, error)
}

// dockerReloadProbe reads the nginx container through docker.
type dockerReloadProbe struct {
	containerName string
	exec          healthExecutor // docker exec <container> ...
	// command builds the docker logs command; nil is exec.CommandContext.
	// Tests substitute one that prints what docker logs would.
	command func(ctx context.Context, name string, args ...string) *exec.Cmd
}

// nginxProcsScript prints the master's pid, then the /proc/<pid>/stat line of
// every process in the container. The fourth field of a stat line is the
// process's parent, so the master's children are found without reading any
// command line: the docker exec running this, the pgrep upForDeferredSteps
// runs and an operator's shell are not the master's children, whatever their
// command lines say. The second field is the process's name, the name of the
// program it runs: "nginx" for the workers and the cache manager and loader,
// whose command lines nginx rewrites but whose name it leaves alone.
const nginxProcsScript = "cat /var/run/nginx.pid && cat /proc/[0-9]*/stat 2>/dev/null; true"

func (p *dockerReloadProbe) Children(ctx context.Context) (int, map[int]bool, error) {
	out, err := p.exec.Exec(ctx, "sh", "-c", nginxProcsScript)
	if err != nil {
		return 0, nil, fmt.Errorf("read nginx processes: %w", err)
	}
	return parseNginxProcs(out)
}

// parseNginxProcs reads nginxProcsScript's output: the master's pid and the
// pids of its children named nginx. Only the name tells them apart: nginx is
// PID 1 in the nginx image, so the entrypoint's background loops are the
// master's children from the start, and a process orphaned in the container
// becomes one.
func parseNginxProcs(out string) (int, map[int]bool, error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	master, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil || master <= 0 {
		return 0, nil, fmt.Errorf("read nginx master pid: %.120q", lines[0])
	}
	children := make(map[int]bool)
	for _, line := range lines[1:] {
		// "<pid> (<name>) <state> <ppid> ...": the name may hold spaces and
		// parentheses, so it runs from the first "(" to the last ")", and the
		// fields after it are counted from there.
		open := strings.IndexByte(line, '(')
		end := strings.LastIndexByte(line, ')')
		if open < 0 || end < open || line[open+1:end] != "nginx" {
			continue
		}
		tail := strings.Fields(line[end+1:])
		if len(tail) < 2 {
			continue
		}
		pid, pidErr := strconv.Atoi(strings.TrimSpace(line[:open]))
		ppid, ppidErr := strconv.Atoi(tail[1])
		if pidErr != nil || ppidErr != nil {
			continue
		}
		if ppid == master {
			children[pid] = true
		}
	}
	return master, children, nil
}

func (p *dockerReloadProbe) EmergSince(ctx context.Context, since time.Time) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerExecTimeout)
	defer cancel()
	// nginx writes its error log to stderr (nginx/scripts/docker-entrypoint.sh),
	// which docker keeps as the container's log, and docker logs prints the
	// container's stderr on its own stderr. Only that is read. The container's
	// stdout is busy: the access log and ModSecurity's audit log go there, and
	// an audit line can run to about 1MB, so docker logs' stdout goes to the
	// null device (Stdout nil). With --since alone, docker reads the log files
	// from their start to find the lines after since. --tail bounds that:
	// docker reads at most 5000 lines back from the end and keeps those after
	// since, and the check a second after the signal needs only that second's
	// lines.
	command := p.command
	if command == nil {
		command = exec.CommandContext
	}
	cmd := command(ctx, "docker", "logs", "--since", since.UTC().Format(time.RFC3339Nano), "--tail", "5000", p.containerName)
	cmd.Stdout = nil
	out, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("docker logs: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("docker logs: %w", err)
	}
	lines, readErr := emergLines(out)
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("docker logs: %w", err)
	}
	if readErr != nil {
		return nil, fmt.Errorf("docker logs: %w", readErr)
	}
	return lines, nil
}

// emergLines returns the lines in r, the nginx container's stderr as docker
// logs prints it, that nginx's error log wrote at the emerg level. Whatever
// else the container writes there can hold any text, at any length, and the
// access log and ModSecurity's audit log, whose lines run to about 1MB, would
// be there too if they were ever sent to stderr. So a line counts only when it
// starts with emergPrefix, and lines of any length are read past (a
// bufio.Scanner stops at the first line longer than its buffer). An nginx log
// line is at most 2KB (NGX_MAX_ERROR_STR), so only the first piece of each
// line is looked at.
func emergLines(r io.Reader) ([]string, error) {
	br := bufio.NewReader(r)
	var lines []string
	atStart := true // the next piece ReadLine returns begins a line
	for {
		piece, more, err := br.ReadLine()
		if err == io.EOF {
			return lines, nil
		}
		if err != nil {
			return lines, err
		}
		if atStart && emergPrefix.Match(piece) {
			lines = append(lines, string(piece))
		}
		atStart = !more
	}
}

// emergPrefix is what nginx's error log puts before the message of an emerg
// line: "2026/10/11 09:00:00 [emerg] 1#1: ". emergLines keeps the lines that
// start with it, and cleanEmergLine cuts it off.
var emergPrefix = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[emerg\] \d+#\d+: (?:\*\d+ )?`)

// cleanEmergLine returns line without its timestamp and pid, cut to 300 bytes.
func cleanEmergLine(line string) string {
	msg := strings.TrimSpace(emergPrefix.ReplaceAllString(strings.TrimSpace(line), ""))
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// reloadSnapshot is nginx's process tree just before a reload signal.
type reloadSnapshot struct {
	master   int
	children map[int]bool
}

// tookReload reports whether nginx's processes, as reloadProbe.Children read
// them, show that nginx loaded its files after s was taken: a new master (it
// read the files on disk when it started), or a child of the master that was
// not there (a reload nginx takes starts new workers; one it refuses keeps
// the old ones).
func (s reloadSnapshot) tookReload(master int, children map[int]bool) bool {
	if master != s.master {
		return true
	}
	for pid := range children {
		if !s.children[pid] {
			return true
		}
	}
	return false
}

// pendingReload is a reload signalled inside executeWithLock, which confirms
// it once the lock is released. token is what the reload hooks' Before
// returned for it, and hooks the hooks to report its outcome to
// (pendingReload.report).
type pendingReload struct {
	before reloadSnapshot
	sentAt time.Time
	token  any
	hooks  ReloadHooks
}

// reloadLogChecks are the times after the signal at which confirmReload reads
// nginx's log while it waits, besides once at the end. A master that refuses
// a reload logs it at once, but one that takes it can need a while to start
// its new workers (about 0.6s for 60 WAF hosts on one CPU), and reading the
// log at every poll would run docker logs ten times a second.
var reloadLogChecks = []time.Duration{time.Second, 3 * time.Second}

// confirmReload waits for nginx to show what it did with the reload signalled
// at sentAt. A reload nginx takes starts new workers, children of the master
// that were not there before; one it refuses keeps the old ones and leaves an
// [emerg] line in its log. A refusal returns ReloadRejected and
// *ReloadRejectedError. When nginx shows neither within the wait, the reload
// is reported as taken (a nil error), with a warning and the "unconfirmed"
// count: failing saves on that guess would, on slow hardware, report good
// saves as refused. The outcome says which it was: ReloadAccepted,
// ReloadRejected or ReloadUnconfirmed.
func (m *Manager) confirmReload(ctx context.Context, before reloadSnapshot, sentAt time.Time) (ReloadOutcome, error) {
	start := time.Now()
	wait := m.reloadConfirmWait
	if wait <= 0 {
		wait = config.ReloadConfirmTimeout
	}
	every := m.reloadConfirmEvery
	if every <= 0 {
		every = config.ReloadConfirmPoll
	}
	deadline := start.Add(wait)
	checks := reloadLogChecks
	done := func(result string) {
		metrics.NginxReloadConfirmTotal.WithLabelValues(result).Inc()
		metrics.NginxReloadConfirmSeconds.Observe(time.Since(start).Seconds())
	}
	// The last failed reads of nginx's processes and of its log. Each log
	// read covers everything since the signal, so one that works clears
	// logErr.
	var procErr, logErr error
	for {
		master, children, err := m.reloadProbe.Children(ctx)
		if err != nil {
			procErr = err
		} else if before.tookReload(master, children) {
			done("accepted")
			return ReloadAccepted, nil
		}
		last := !time.Now().Before(deadline)
		readLog := last
		for len(checks) > 0 && time.Since(start) >= checks[0] {
			checks = checks[1:]
			readLog = true
		}
		if readLog {
			// Any [emerg] line since the signal counts against this reload.
			// For a port in use nginx retries bind() five times, 500ms apart,
			// so a reload signalled within about 2.5s of one it refused that
			// way can see the earlier one's lines and be reported as refused
			// too. Either way its files are kept, and the next reload that
			// nginx takes applies them.
			lines, err := m.reloadProbe.EmergSince(ctx, sentAt)
			logErr = err
			if err == nil && len(lines) > 0 {
				done("rejected")
				// The first line names the cause: for a port in use, the
				// bind() line with the address, where the last one is
				// "still could not bind()".
				detail := cleanEmergLine(lines[0])
				log.Printf("[ERROR] [NginxReload] nginx refused the reload and keeps its previous configuration: %s", detail)
				return ReloadRejected, &ReloadRejectedError{Detail: detail}
			}
		}
		if last {
			done("unconfirmed")
			switch {
			case logErr != nil:
				log.Printf("[WARN] [NginxReload] nginx started no new worker within %v of the reload, and its log could not be read (%v); the reload is reported as applied", wait, logErr)
			case procErr != nil:
				log.Printf("[WARN] [NginxReload] nginx logged no error for the reload, and its processes could not be read (%v) to see whether it started new workers within %v; the reload is reported as applied", procErr, wait)
			default:
				log.Printf("[WARN] [NginxReload] nginx started no new worker within %v of the reload and logged no error; the reload is reported as applied", wait)
			}
			return ReloadUnconfirmed, nil
		}
		select {
		case <-ctx.Done():
			done("unconfirmed")
			log.Printf("[WARN] [NginxReload] stopped waiting for nginx to take the reload: %v", ctx.Err())
			return ReloadUnconfirmed, nil
		case <-time.After(every):
		}
	}
}
