package service

import (
	"context"
	"net/http"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// AuditService logs admin activities to the audit_logs table
type AuditService struct {
	repo *repository.AuditLogRepository
}

func NewAuditService(repo *repository.AuditLogRepository) *AuditService {
	return &AuditService{repo: repo}
}

// AuditContext holds user context information for audit logging
type AuditContext struct {
	UserID    string
	Username  string
	IPAddress string
	UserAgent string
}

// GetAuditContextFromEcho extracts audit context from Echo context
func GetAuditContextFromEcho(c interface {
	Get(string) interface{}
	RealIP() string
	Request() interface{ UserAgent() string }
}) AuditContext {
	ctx := AuditContext{
		Username: "system",
	}

	if userID, ok := c.Get("user_id").(string); ok {
		ctx.UserID = userID
	}
	if username, ok := c.Get("username").(string); ok {
		ctx.Username = username
	}
	ctx.IPAddress = c.RealIP()
	if req := c.Request(); req != nil {
		ctx.UserAgent = req.UserAgent()
	}

	return ctx
}

// ContextWithAudit adds audit information to a context from Echo context
func ContextWithAudit(ctx context.Context, c interface {
	Get(string) interface{}
	RealIP() string
	Request() *http.Request
}) context.Context {
	if userID, ok := c.Get("user_id").(string); ok {
		ctx = context.WithValue(ctx, "user_id", userID)
	}
	if username, ok := c.Get("username").(string); ok {
		ctx = context.WithValue(ctx, "username", username)
	}
	ctx = context.WithValue(ctx, "client_ip", c.RealIP())
	if req := c.Request(); req != nil {
		ctx = context.WithValue(ctx, "user_agent", req.UserAgent())
	}
	return ctx
}

// logEntry creates an audit log entry
func (s *AuditService) logEntry(ctx context.Context, action, resource, resourceID, resourceName string, details map[string]interface{}) error {
	// Get user info from context if available
	username := "system"
	userID := ""
	ipAddress := ""
	userAgent := ""

	if user, ok := ctx.Value("user").(*model.User); ok && user != nil {
		username = user.Username
		userID = user.ID
	}
	if u, ok := ctx.Value("username").(string); ok && u != "" {
		username = u
	}
	if uid, ok := ctx.Value("user_id").(string); ok && uid != "" {
		userID = uid
	}
	if ip, ok := ctx.Value("client_ip").(string); ok {
		ipAddress = ip
	}
	if ua, ok := ctx.Value("user_agent").(string); ok {
		userAgent = ua
	}

	// Add resource name to details if not already present
	if details == nil {
		details = make(map[string]interface{})
	}
	if resourceName != "" {
		details["name"] = resourceName
	}

	entry := &model.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
	}

	return s.repo.Log(ctx, entry)
}

// logEntryWithUser creates an audit log entry with explicit user info
func (s *AuditService) logEntryWithUser(ctx context.Context, userID, username, ipAddress, userAgent, action, resource, resourceID, resourceName string, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	if resourceName != "" {
		details["name"] = resourceName
	}

	entry := &model.AuditLogEntry{
		UserID:     userID,
		Username:   username,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
	}

	return s.repo.Log(ctx, entry)
}

// LogProxyHostCreate logs proxy host creation
func (s *AuditService) LogProxyHostCreate(ctx context.Context, domains []string, destination string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "proxy_host_created", "proxy_host", "", domainStr, map[string]interface{}{
		"domain_names": domains,
		"destination":  destination,
	})
}

// LogProxyHostUpdate logs proxy host update
func (s *AuditService) LogProxyHostUpdate(ctx context.Context, domains []string, changes map[string]interface{}) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "proxy_host_updated", "proxy_host", "", domainStr, changes)
}

// LogProxyHostDelete logs proxy host deletion
func (s *AuditService) LogProxyHostDelete(ctx context.Context, domains []string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "proxy_host_deleted", "proxy_host", "", domainStr, nil)
}

// LogProxyHostClone logs proxy host cloning
func (s *AuditService) LogProxyHostClone(ctx context.Context, sourceDomains []string, targetDomains []string) error {
	sourceDomainStr := ""
	if len(sourceDomains) > 0 {
		sourceDomainStr = sourceDomains[0]
	}
	targetDomainStr := ""
	if len(targetDomains) > 0 {
		targetDomainStr = targetDomains[0]
	}
	return s.logEntry(ctx, "proxy_host_cloned", "proxy_host", "", targetDomainStr, map[string]interface{}{
		"source_domains": sourceDomains,
		"target_domains": targetDomains,
		"source_domain":  sourceDomainStr,
	})
}

// LogProxyHostToggle logs proxy host enable/disable
func (s *AuditService) LogProxyHostToggle(ctx context.Context, domains []string, enabled bool) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	action := "proxy_host_enabled"
	if !enabled {
		action = "proxy_host_disabled"
	}
	return s.logEntry(ctx, action, "proxy_host", "", domainStr, map[string]interface{}{
		"enabled": enabled,
	})
}

// LogCertificateCreate logs certificate creation
func (s *AuditService) LogCertificateCreate(ctx context.Context, domains []string, certType string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "certificate_created", "certificate", "", domainStr, map[string]interface{}{
		"domain_names": domains,
		"type":         certType,
	})
}

// LogCertificateUpdate logs certificate update (e.g. custom cert replacement)
func (s *AuditService) LogCertificateUpdate(ctx context.Context, domains []string, certType string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "certificate_updated", "certificate", "", domainStr, map[string]interface{}{
		"domain_names": domains,
		"type":         certType,
	})
}

// LogCertificateDelete logs certificate deletion
func (s *AuditService) LogCertificateDelete(ctx context.Context, domains []string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "certificate_deleted", "certificate", "", domainStr, nil)
}

// LogCertificateRenewed logs certificate renewal
func (s *AuditService) LogCertificateRenewed(ctx context.Context, domains []string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "certificate_renewed", "certificate", "", domainStr, map[string]interface{}{
		"domain_names": domains,
	})
}

// LogCertificateDownload logs certificate download
func (s *AuditService) LogCertificateDownload(ctx context.Context, domains []string, downloadType string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "certificate_downloaded", "certificate", "", domainStr, map[string]interface{}{
		"domain_names":  domains,
		"download_type": downloadType,
	})
}

// LogSettingsUpdate logs global settings update
func (s *AuditService) LogSettingsUpdate(ctx context.Context, settingName string, details map[string]interface{}) error {
	return s.logEntry(ctx, "settings_updated", "settings", "", settingName, details)
}

// LogGlobalGeoUpdate logs a change to the global geo restriction default (#198).
func (s *AuditService) LogGlobalGeoUpdate(ctx context.Context) error {
	return s.logEntry(ctx, "global_geo_updated", "settings", "", "Global Geo Restriction", nil)
}

// LogGlobalBotFilterUpdate logs a change to the global bot-filter default (#198).
func (s *AuditService) LogGlobalBotFilterUpdate(ctx context.Context) error {
	return s.logEntry(ctx, "global_bot_filter_updated", "settings", "", "Global Bot Filter", nil)
}

// LogGlobalSecurityHeadersUpdate logs a change to the global security-headers default (#198).
func (s *AuditService) LogGlobalSecurityHeadersUpdate(ctx context.Context) error {
	return s.logEntry(ctx, "global_security_headers_updated", "settings", "", "Global Security Headers", nil)
}

// LogGlobalCloudProvidersUpdate logs a change to the global cloud-provider default (#198).
func (s *AuditService) LogGlobalCloudProvidersUpdate(ctx context.Context) error {
	return s.logEntry(ctx, "global_cloud_providers_updated", "settings", "", "Global Cloud Provider Blocking", nil)
}

// LogGlobalRateLimitUpdate logs a change to the global rate-limit default (#198 slice 5).
func (s *AuditService) LogGlobalRateLimitUpdate(ctx context.Context) error {
	return s.logEntry(ctx, "global_rate_limit_updated", "settings", "", "Global Rate Limit", nil)
}

// LogGlobalWAFUpdate logs a change to the global WAF default (#198 slice 6).
func (s *AuditService) LogGlobalWAFUpdate(ctx context.Context) error {
	return s.logEntry(ctx, "global_waf_updated", "settings", "", "Global WAF", nil)
}

// LogCloudflareTunnelUpdate logs a change to the Cloudflare Tunnel settings.
func (s *AuditService) LogCloudflareTunnelUpdate(ctx context.Context) error {
	return s.logEntry(ctx, "cloudflare_tunnel_updated", "settings", "", "Cloudflare Tunnel", nil)
}

// ─── Identity administration (#222) ─────────────────────────────────────
//
// Role and permission changes are exactly the events that must never lose their
// actor, so they go through the same ContextWithAudit path as every other
// mutation. audit_logs.user_id is ON DELETE SET NULL, but the denormalized
// username column survives a deleted actor.

func (s *AuditService) LogRoleCreate(ctx context.Context, name string, permCount int) error {
	return s.logEntry(ctx, "role_created", "role", "", name,
		map[string]interface{}{"permissions": permCount})
}

func (s *AuditService) LogRoleUpdate(ctx context.Context, name string, permCount int) error {
	return s.logEntry(ctx, "role_updated", "role", "", name,
		map[string]interface{}{"permissions": permCount})
}

func (s *AuditService) LogRoleDelete(ctx context.Context, name string) error {
	return s.logEntry(ctx, "role_deleted", "role", "", name, nil)
}

func (s *AuditService) LogUserCreate(ctx context.Context, username, roleName string) error {
	return s.logEntry(ctx, "user_created", "user", "", username,
		map[string]interface{}{"role": roleName})
}

func (s *AuditService) LogUserRoleAssign(ctx context.Context, username, roleName string) error {
	return s.logEntry(ctx, "user_role_assigned", "user", "", username,
		map[string]interface{}{"role": roleName})
}

func (s *AuditService) LogUserPasswordReset(ctx context.Context, username string) error {
	return s.logEntry(ctx, "user_password_reset", "user", "", username, nil)
}

// LogUserEmailChange records that an account's SSO linking address changed.
// The address is not recorded: the audit trail is exportable and this runs on a
// public-facing box, so who and when is what belongs here. (#240)
func (s *AuditService) LogUserEmailChange(ctx context.Context, username string) error {
	return s.logEntry(ctx, "user_email_changed", "user", "", username, nil)
}

// LogUserDelete records how many API tokens went with the account, because that
// is the part of a deletion that silently breaks automation. (#222 D8)
func (s *AuditService) LogUserDelete(ctx context.Context, username string, apiTokenCount int) error {
	return s.logEntry(ctx, "user_deleted", "user", "", username,
		map[string]interface{}{"api_tokens_removed": apiTokenCount})
}

// LogSecurityFeatureUpdate logs security feature changes
func (s *AuditService) LogSecurityFeatureUpdate(ctx context.Context, resource string, hostDomain string, enabled bool, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["enabled"] = enabled
	details["host"] = hostDomain

	action := resource + "_updated"
	if enabled {
		action = resource + "_enabled"
	} else {
		action = resource + "_disabled"
	}

	return s.logEntry(ctx, action, resource, "", hostDomain, details)
}

// LogRateLimitUpdate logs rate limit changes
func (s *AuditService) LogRateLimitUpdate(ctx context.Context, hostDomain string, enabled bool, details map[string]interface{}) error {
	return s.LogSecurityFeatureUpdate(ctx, "rate_limit", hostDomain, enabled, details)
}

// LogBotFilterUpdate logs bot filter changes
func (s *AuditService) LogBotFilterUpdate(ctx context.Context, hostDomain string, enabled bool, details map[string]interface{}) error {
	return s.LogSecurityFeatureUpdate(ctx, "bot_filter", hostDomain, enabled, details)
}

// LogSecurityHeadersUpdate logs security headers changes
func (s *AuditService) LogSecurityHeadersUpdate(ctx context.Context, hostDomain string, enabled bool, details map[string]interface{}) error {
	return s.LogSecurityFeatureUpdate(ctx, "security_headers", hostDomain, enabled, details)
}

// LogUpstreamUpdate logs upstream changes
func (s *AuditService) LogUpstreamUpdate(ctx context.Context, hostDomain string, details map[string]interface{}) error {
	return s.logEntry(ctx, "upstream_updated", "upstream", "", hostDomain, details)
}

// LogBackupCreate logs backup creation
func (s *AuditService) LogBackupCreate(ctx context.Context, filename string) error {
	return s.logEntry(ctx, "backup_created", "backup", "", filename, nil)
}

// LogBackupRestore logs backup restoration. extra adds details (nil adds
// none): a restore names the domain entries it brought back and those that
// wait for review (#320). It cannot replace "action" or "name".
func (s *AuditService) LogBackupRestore(ctx context.Context, filename string, extra map[string]interface{}) error {
	details := map[string]interface{}{"action": "restore"}
	for k, v := range extra {
		if k != "action" && k != "name" {
			details[k] = v
		}
	}
	return s.logEntry(ctx, "backup_restored", "backup", "", filename, details)
}

// LogBackupDelete logs backup deletion
func (s *AuditService) LogBackupDelete(ctx context.Context, filename string) error {
	return s.logEntry(ctx, "backup_deleted", "backup", "", filename, nil)
}

// LogWAFEnabled logs WAF being enabled
func (s *AuditService) LogWAFEnabled(ctx context.Context, hostDomain string) error {
	return s.logEntry(ctx, "waf_enabled", "waf", "", hostDomain, nil)
}

// LogWAFDisabled logs WAF being disabled
func (s *AuditService) LogWAFDisabled(ctx context.Context, hostDomain string) error {
	return s.logEntry(ctx, "waf_disabled", "waf", "", hostDomain, nil)
}

// LogWAFRulesUpdated logs WAF rules being updated
func (s *AuditService) LogWAFRulesUpdated(ctx context.Context, hostDomain string, details map[string]interface{}) error {
	return s.logEntry(ctx, "waf_rules_updated", "waf", "", hostDomain, details)
}

// LogUserLogin logs user login
func (s *AuditService) LogUserLogin(ctx context.Context, username, ipAddress, userAgent string) error {
	return s.logEntry(ctx, "user_login", "user", "", username, map[string]interface{}{
		"ip_address": ipAddress,
		"user_agent": userAgent,
	})
}

// LogUserLoginFailed logs a failed admin-UI login attempt so operators can
// see brute-force activity in the audit log (API-token denials were already
// audited; UI login failures previously left no operator-visible trace).
func (s *AuditService) LogUserLoginFailed(ctx context.Context, username, ipAddress, userAgent, reason string) error {
	// A failed login has no authenticated user in context, so logEntry would
	// record actor="system" and leave ip_address/user_agent NULL — putting the
	// attacker's IP only in the details JSONB the audit UI doesn't surface.
	// Use logEntryWithUser so the attempted username + IP + UA land in the real
	// operator-visible columns. userID stays empty (no account is implied).
	return s.logEntryWithUser(ctx, "", username, ipAddress, userAgent, "user_login_failed", "user", "", username, map[string]interface{}{
		"reason": reason,
	})
}

// LogUserLogout logs user logout
func (s *AuditService) LogUserLogout(ctx context.Context, username string) error {
	return s.logEntry(ctx, "user_logout", "user", "", username, nil)
}

// LogPasswordChanged logs password change
func (s *AuditService) LogPasswordChanged(ctx context.Context, username string) error {
	return s.logEntry(ctx, "password_changed", "user", "", username, nil)
}

// LogUsernameChanged logs username change
func (s *AuditService) LogUsernameChanged(ctx context.Context, oldUsername, newUsername string) error {
	return s.logEntry(ctx, "username_changed", "user", "", newUsername, map[string]interface{}{
		"old_username": oldUsername,
		"new_username": newUsername,
	})
}

// Log2FAEnabled logs 2FA being enabled
func (s *AuditService) Log2FAEnabled(ctx context.Context, username string) error {
	return s.logEntry(ctx, "totp_enabled", "user", "", username, nil)
}

// Log2FADisabled logs 2FA being disabled
func (s *AuditService) Log2FADisabled(ctx context.Context, username string) error {
	return s.logEntry(ctx, "totp_disabled", "user", "", username, nil)
}

// Log2FAFailed records a rejected 2FA code.
//
// Only the successes were audited, so a rejection left nothing anywhere: the
// same 401 and the same "Invalid 2FA code" whether the stored secret had been
// rotated out from under the user, the host clock had drifted past the ±30s
// window, or the code was simply wrong. That is why #305 arrived as "the code
// is correct but it says it is wrong" with nothing further to go on — neither
// the reporter nor a maintainer reading their logs could tell the three apart.
//
// stage says which door was being tried ("login" or "enable"); reason carries
// what the server could tell about it. logEntryWithUser is used rather than
// logEntry because the login-side rejection has no authenticated user in
// context, and the attempted username and IP belong in the operator-visible
// columns rather than buried in the details JSONB.
func (s *AuditService) Log2FAFailed(ctx context.Context, username, ipAddress, userAgent, stage, reason string) error {
	return s.logEntryWithUser(ctx, "", username, ipAddress, userAgent, "totp_failed", "user", "", username, map[string]interface{}{
		"stage":  stage,
		"reason": reason,
	})
}

// LogAccessListCreated logs access list creation
func (s *AuditService) LogAccessListCreated(ctx context.Context, name string) error {
	return s.logEntry(ctx, "access_list_created", "access_list", "", name, nil)
}

// LogAccessListUpdated logs access list update
func (s *AuditService) LogAccessListUpdated(ctx context.Context, name string, details map[string]interface{}) error {
	return s.logEntry(ctx, "access_list_updated", "access_list", "", name, details)
}

// LogAccessListDeleted logs access list deletion
func (s *AuditService) LogAccessListDeleted(ctx context.Context, name string) error {
	return s.logEntry(ctx, "access_list_deleted", "access_list", "", name, nil)
}

// ─── Domain entries (#320) ──────────────────────────────────────────────
//
// resource_type "dns_entry". resource_name is one domain name (at most 253
// characters, so it fits varchar(255)), a fixed word, or empty — never a list
// of names. No helper uses the "name" details key: logEntry overwrites it
// with resource_name. Audit rows may carry addresses (they stay on the box);
// notifications never do.

// dnsAuditNamesMax caps the names a dns_entry_revoke_blocked row lists;
// names_total carries the full count.
const dnsAuditNamesMax = 20

// LogDNSEntryConfirmed records that an operator approved a name in review:
// the addresses NPG observed and now allows, the CNAME target it pinned, and
// the scopes that use the name.
func (s *AuditService) LogDNSEntryConfirmed(ctx context.Context, name string, addrs []string, canonical string, scopes []string) error {
	return s.logEntry(ctx, "dns_entry_confirmed", "dns_entry", "", name, map[string]interface{}{
		"addresses":      auditStrings(addrs),
		"canonical_name": canonical,
		"scopes":         auditStrings(scopes),
	})
}

// LogDNSEntryApplyRequested records "Apply now" and its outcome, a reload
// nginx refused included.
func (s *AuditService) LogDNSEntryApplyRequested(ctx context.Context, outcome string) error {
	return s.logEntry(ctx, "dns_entry_apply_requested", "dns_entry", "", "", map[string]interface{}{
		"outcome": outcome,
	})
}

// LogDNSEntryApplied records that nginx took a new address set of a name:
// the record of which addresses were trusted from when. before is nil when
// NPG does not know what nginx held (after a restart) and is stored as null,
// which an empty list would not say.
func (s *AuditService) LogDNSEntryApplied(ctx context.Context, name string, before, after []string, gen int64) error {
	return s.logEntry(ctx, "dns_entry_applied", "dns_entry", "", name, map[string]interface{}{
		"before":     before,
		"after":      auditStrings(after),
		"generation": gen,
	})
}

// LogDNSEntryReviewNeeded records that a name entered review and was closed.
func (s *AuditService) LogDNSEntryReviewNeeded(ctx context.Context, name, reason string) error {
	return s.logEntry(ctx, "dns_entry_review_needed", "dns_entry", "", name, map[string]interface{}{
		"reason": reason,
	})
}

// LogDNSEntryRevokeBlocked records that nginx still allowed addresses NPG had
// removed because an apply failed (blocked true), or that it no longer does
// (blocked false). It lists at most dnsAuditNamesMax names.
func (s *AuditService) LogDNSEntryRevokeBlocked(ctx context.Context, blocked bool, outcome, file string, names []string) error {
	shown := names
	if len(shown) > dnsAuditNamesMax {
		shown = shown[:dnsAuditNamesMax]
	}
	return s.logEntry(ctx, "dns_entry_revoke_blocked", "dns_entry", "", "revoke", map[string]interface{}{
		"blocked":     blocked,
		"outcome":     outcome,
		"file":        file,
		"names":       auditStrings(shown),
		"names_total": len(names),
	})
}

// LogDNSEntriesEnvDisabled records, once per start, that
// NPG_DNS_ENTRIES_DISABLED keeps every domain entry closed whatever the
// settings say.
func (s *AuditService) LogDNSEntriesEnvDisabled(ctx context.Context) error {
	return s.logEntry(ctx, "dns_entries_env_disabled", "dns_entry", "", "", map[string]interface{}{})
}

// LogDNSEntrySettingsChanged records the domain entry tunables an operator
// changed, as {key: [before, after]} for the changed keys only. changes is
// copied: logEntry adds "name" to the map it is given.
func (s *AuditService) LogDNSEntrySettingsChanged(ctx context.Context, changes map[string]interface{}) error {
	details := make(map[string]interface{}, len(changes)+1)
	for k, v := range changes {
		details[k] = v
	}
	return s.logEntry(ctx, "dns_entry_settings_changed", "settings", "", "dns_entry_settings", details)
}

// auditStrings returns list, or an empty list for nil, so a details value
// reads [] rather than null where null would mean "unknown".
func auditStrings(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// LogRedirectHostCreated logs redirect host creation
func (s *AuditService) LogRedirectHostCreated(ctx context.Context, domains []string, destination string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "redirect_host_created", "redirect_host", "", domainStr, map[string]interface{}{
		"domain_names": domains,
		"destination":  destination,
	})
}

// LogRedirectHostUpdated logs redirect host update
func (s *AuditService) LogRedirectHostUpdated(ctx context.Context, domains []string, details map[string]interface{}) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "redirect_host_updated", "redirect_host", "", domainStr, details)
}

// LogRedirectHostDeleted logs redirect host deletion
func (s *AuditService) LogRedirectHostDeleted(ctx context.Context, domains []string) error {
	domainStr := ""
	if len(domains) > 0 {
		domainStr = domains[0]
	}
	return s.logEntry(ctx, "redirect_host_deleted", "redirect_host", "", domainStr, nil)
}

// LogAPITokenCreated logs API token creation
func (s *AuditService) LogAPITokenCreated(ctx context.Context, tokenName string) error {
	return s.logEntry(ctx, "api_token_created", "api_token", "", tokenName, map[string]interface{}{
		"token_name": tokenName,
	})
}

// LogAPITokenUpdated logs API token update
func (s *AuditService) LogAPITokenUpdated(ctx context.Context, tokenName string, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["token_name"] = tokenName
	return s.logEntry(ctx, "api_token_updated", "api_token", "", tokenName, details)
}

// LogAPITokenRevoked logs API token revocation
func (s *AuditService) LogAPITokenRevoked(ctx context.Context, tokenName string) error {
	return s.logEntry(ctx, "api_token_revoked", "api_token", "", tokenName, map[string]interface{}{
		"token_name": tokenName,
	})
}

// LogAPITokenDeleted logs API token deletion
func (s *AuditService) LogAPITokenDeleted(ctx context.Context, tokenName string) error {
	return s.logEntry(ctx, "api_token_deleted", "api_token", "", tokenName, map[string]interface{}{
		"token_name": tokenName,
	})
}

// LogGeoRestrictionUpdated logs geo restriction changes
func (s *AuditService) LogGeoRestrictionUpdated(ctx context.Context, hostDomain string, details map[string]interface{}) error {
	return s.logEntry(ctx, "geo_restriction_updated", "geo_restriction", "", hostDomain, details)
}

// LogFail2banUpdate logs fail2ban changes
func (s *AuditService) LogFail2banUpdate(ctx context.Context, hostDomain string, enabled bool, details map[string]interface{}) error {
	return s.LogSecurityFeatureUpdate(ctx, "fail2ban", hostDomain, enabled, details)
}

// LogIPBanned logs IP ban action
func (s *AuditService) LogIPBanned(ctx context.Context, ipAddress string, reason string, banTime int) error {
	return s.logEntry(ctx, "ip_banned", "banned_ip", "", ipAddress, map[string]interface{}{
		"ip":       ipAddress,
		"reason":   reason,
		"ban_time": banTime,
	})
}

// LogIPUnbanned logs IP unban action
func (s *AuditService) LogIPUnbanned(ctx context.Context, ipAddress string) error {
	return s.logEntry(ctx, "ip_unbanned", "banned_ip", "", ipAddress, nil)
}

// LogIPBanDurationChanged records a re-dated ban. The duration is recorded, not
// the resulting timestamp, because "made permanent" and "extended by a day" are
// what an auditor is looking for. (#252)
func (s *AuditService) LogIPBanDurationChanged(ctx context.Context, ipAddress string, seconds int) error {
	return s.logEntry(ctx, "ip_ban_duration_changed", "banned_ip", "", ipAddress,
		map[string]interface{}{"ban_time_seconds": seconds, "permanent": seconds == 0})
}

// LogIPsBulkUnbanned logs a bulk unban action with the count of IPs removed.
func (s *AuditService) LogIPsBulkUnbanned(ctx context.Context, count int64) error {
	return s.logEntry(ctx, "ip_bulk_unbanned", "banned_ip", "", "", map[string]interface{}{
		"count": count,
	})
}

// LogFilterSubscriptionCreated logs filter subscription creation
func (s *AuditService) LogFilterSubscriptionCreated(ctx context.Context, name, url string) error {
	return s.logEntry(ctx, "filter_subscription_created", "filter_subscription", "", name, map[string]interface{}{
		"url": url,
	})
}

// LogFilterSubscriptionUpdated logs filter subscription update
func (s *AuditService) LogFilterSubscriptionUpdated(ctx context.Context, name string) error {
	return s.logEntry(ctx, "filter_subscription_updated", "filter_subscription", "", name, nil)
}

// LogFilterSubscriptionDeleted logs filter subscription deletion
func (s *AuditService) LogFilterSubscriptionDeleted(ctx context.Context, name string) error {
	return s.logEntry(ctx, "filter_subscription_deleted", "filter_subscription", "", name, nil)
}

// LogFilterSubscriptionRefreshed logs filter subscription refresh
func (s *AuditService) LogFilterSubscriptionRefreshed(ctx context.Context, name string) error {
	return s.logEntry(ctx, "filter_subscription_refreshed", "filter_subscription", "", name, nil)
}

// LogFilterSubscriptionCatalogSubscribe logs catalog subscription
func (s *AuditService) LogFilterSubscriptionCatalogSubscribe(ctx context.Context, count int) error {
	return s.logEntry(ctx, "filter_subscription_catalog_subscribe", "filter_subscription", "", "", map[string]interface{}{
		"count": count,
	})
}
