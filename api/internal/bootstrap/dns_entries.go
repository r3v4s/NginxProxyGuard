package bootstrap

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// Domain entries (#320) environment. Both are optional and read once at
// start; the settings screen shows when they override it.
//
//	NPG_DNS_ENTRIES_DISABLED=1     emergency switch: every domain entry stays
//	                               closed whatever the settings say
//	NPG_DNS_ENTRIES_INTERVAL=60s   check interval over the settings value
const (
	// dnsEntriesIntervalMin is below the settings screen's 30 s so the E2E
	// stack can check every 5 s.
	dnsEntriesIntervalMin = 5 * time.Second
	dnsEntriesIntervalMax = time.Hour
)

// dnsEntriesEnvDisabledMessage is the startup warning while the emergency
// switch is set: in the container log, in the system log, and the reason for
// the dns_entries_env_disabled audit row. A restarted container keeps its
// environment, so it says to recreate the container.
const dnsEntriesEnvDisabledMessage = "NPG_DNS_ENTRIES_DISABLED is set: every domain entry stays closed and no client is allowed through a domain name, whatever the settings say. Remove it and recreate the API container (docker compose up -d) to use domain entries again."

// dnsEntriesEnvDisabled reads NPG_DNS_ENTRIES_DISABLED like DiskGuard reads
// its switch: 1, true or yes, in any case, spaces ignored.
func dnsEntriesEnvDisabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("NPG_DNS_ENTRIES_DISABLED")))
	return v == "1" || v == "true" || v == "yes"
}

// dnsEntriesEnvInterval reads NPG_DNS_ENTRIES_INTERVAL, a Go duration. Unset
// is 0: the settings decide. A value that is not a positive duration is
// reported and ignored; one outside 5s..1h is reported and brought inside.
func dnsEntriesEnvInterval() time.Duration {
	v := strings.TrimSpace(os.Getenv("NPG_DNS_ENTRIES_INTERVAL"))
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("[DNSEntries] WARN: ignoring NPG_DNS_ENTRIES_INTERVAL=%q: not a positive duration such as 60s", v)
		return 0
	}
	switch {
	case d < dnsEntriesIntervalMin:
		log.Printf("[DNSEntries] WARN: NPG_DNS_ENTRIES_INTERVAL=%s is below %s; using %s", d, dnsEntriesIntervalMin, dnsEntriesIntervalMin)
		return dnsEntriesIntervalMin
	case d > dnsEntriesIntervalMax:
		log.Printf("[DNSEntries] WARN: NPG_DNS_ENTRIES_INTERVAL=%s is above %s; using %s", d, dnsEntriesIntervalMax, dnsEntriesIntervalMax)
		return dnsEntriesIntervalMax
	}
	return d
}

// dnsEntryOptions is the DNS entry service's environment, read once: the
// service, the startup announcement and the settings screen's lock all go by
// this one reading.
func dnsEntryOptions() service.DNSEntryOptions {
	return service.DNSEntryOptions{
		EnvDisabled: dnsEntriesEnvDisabled(),
		EnvInterval: dnsEntriesEnvInterval(),
	}
}

// initDNSEntries builds the DNS entry service and hooks it into every nginx
// reload. It runs in InitServices, after the services it reads, and so
// before InitHandlers: NewSystemSettingsHandler can start a reload, and a
// reload before SetReloadHooks would go unrecorded.
func initDNSEntries(nginxManager *nginx.Manager, repos *Repositories, svcs *Services) {
	svcs.DNSEntries = service.NewDNSEntryService(service.DNSEntryDeps{
		States:    repos.DNSEntry,
		Settings:  repos.SystemSettings,
		Global:    repos.GlobalSettings,
		Hosts:     repos.ProxyHost,
		Builder:   svcs.ProxyHost,
		SelfIPs:   repos.DDNS,
		Bans:      repos.RateLimit,
		Nginx:     nginxManager,
		Audit:     svcs.Audit,
		SystemLog: repos.SystemLog,
	}, dnsEntryOptions())
	nginxManager.SetReloadHooks(svcs.DNSEntries.ReloadHooks())
	// The exception lists' saves and a clone hand their domain names to it.
	svcs.Security.SetDNSEntries(svcs.DNSEntries)
	svcs.ProxyHost.SetDNSEntries(svcs.DNSEntries)
}

// startDNSEntries is the domain entries' boot step. It runs
// before anything reloads nginx: it gives every name in use a state row,
// closes names whose grace ran out while the API was down, writes every
// include file, and creates, empty, the ones a configuration names but the
// disk lacks. It asks no DNS server and does not need nginx. Then, once per
// start, it says so when the emergency switch is set.
func startDNSEntries(ctx context.Context, c *Container) {
	svc := c.Services.DNSEntries
	if svc == nil {
		return
	}
	if err := svc.ReconcileFiles(ctx, true); err != nil {
		log.Printf("[DNSEntries] WARN: could not bring the domain include files in line with the database at startup; the first check retries: %v", err)
	}
	if svc.EnvDisabled() {
		announceDNSEntriesEnvDisabled(ctx, c.Services.Audit, c.Repositories.SystemLog)
	}
}

// dnsEnvAuditor and dnsEnvSystemLog are the two writers of the startup
// announcement (*service.AuditService, *repository.SystemLogRepository).
type dnsEnvAuditor interface {
	LogDNSEntriesEnvDisabled(ctx context.Context) error
}

type dnsEnvSystemLog interface {
	Create(ctx context.Context, log *repository.SystemLog) error
}

// announceDNSEntriesEnvDisabled records that the emergency switch is set: a
// WARN container line, the dns_entries_env_disabled audit row (user system)
// and a system log row. A failed write is logged and does not stop the
// others.
func announceDNSEntriesEnvDisabled(ctx context.Context, audit dnsEnvAuditor, syslog dnsEnvSystemLog) {
	log.Printf("[DNSEntries] WARN: %s", dnsEntriesEnvDisabledMessage)
	if err := audit.LogDNSEntriesEnvDisabled(ctx); err != nil {
		log.Printf("[DNSEntries] WARN: could not record NPG_DNS_ENTRIES_DISABLED in the audit log: %v", err)
	}
	if err := syslog.Create(ctx, &repository.SystemLog{
		Source:    repository.SourceScheduler,
		Level:     repository.LevelWarn,
		Message:   dnsEntriesEnvDisabledMessage,
		Component: "dns_entries",
	}); err != nil {
		log.Printf("[DNSEntries] WARN: could not record NPG_DNS_ENTRIES_DISABLED in the system log: %v", err)
	}
}
