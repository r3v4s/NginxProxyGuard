// Domain entries (#320). These mirror the JSON of api/internal/model/dns_entry.go
// and dns_entry_settings.go. The Go structs have no omitempty on their slices,
// so every list here may arrive as null.

export type DNSEntryStatusCode =
  | 'pending'
  | 'ok'
  | 'stale'
  | 'expired'
  | 'rejected'
  | 'not_found'
  | 'needs_review';

export type DNSReviewReason = 'cname_changed' | 'reappeared' | 'unstable';

export type DNSWarning = 'self_ip' | 'banned' | 'cgnat' | 'partial_rejected' | 'ipv6_listen' | 'duplicate';

/** Why the last apply failed while a change still waits for nginx. */
export type DNSBlockedReason = 'blocked' | 'failed' | 'rejected' | 'not_up';

/** One address family's last answer; "unknown" before the first one. */
export type DNSFamilyStateCode = 'unknown' | 'ok' | 'not_found' | 'transient' | 'rejected';

export interface DNSFamilyStatus {
  state: DNSFamilyStateCode;
  /** The lookup or policy code (timeout, not_found, private, ...); left out when there is none. */
  code?: string;
}

export interface DNSEntryStatus {
  hostname: string;
  status: DNSEntryStatusCode;
  review_reason: DNSReviewReason | null;
  disabled: boolean;
  addresses: string[] | null;
  pending_addresses: string[] | null;
  next_apply_at: string | null;
  applied: boolean;
  revoke_pending: boolean;
  blocked_reason: DNSBlockedReason | null;
  /** Sent only to callers with proxy:read. */
  blocking_file: string | null;
  observed_addresses: string[] | null;
  canonical_name: string | null;
  observed_canonical_name: string | null;
  /** Keyed "ipv4" and "ipv6". */
  families: Record<string, DNSFamilyStatus> | null;
  /** "banned" reaches only callers with waf:read. */
  warnings: DNSWarning[] | null;
  error_code: string | null;
  stale_until: string | null;
  last_checked_at: string | null;
  last_changed_at: string | null;
}

/** A proxy host, named by its first domain. */
export interface DNSHostRef {
  id: string;
  domain: string;
}

/** Body of a dns-confirm request: the values the operator was shown. */
export interface DNSConfirmRequest {
  hostname: string;
  expected_addresses: string[];
  expected_canonical_name?: string;
}

export interface DNSEntrySettings {
  enabled: boolean;
  check_interval_seconds: number;
  min_reload_gap_seconds: number;
  stale_grace_hours: number;
  not_found_checks: number;
  max_changes_per_day: number;
  max_per_list: number;
  max_total: number;
  max_addresses_per_family: number;
}

/** One place a name is used, as the overview shows it. */
export interface DNSEntryUse {
  scope: string;
  /** access_list, uri_block, priority_allow, rate_limit or trusted. */
  kind: string;
  /** The key of this use's include file (npg_dns/<key>.allow), as nginx's messages name it. */
  key: string;
  /**
   * The list or proxy host the use belongs to. A global list's use has
   * owner_id "global" and no name; the global trusted list's has neither.
   */
  owner_id: string;
  owner_name: string;
}

export interface DNSEntryOverviewEntry extends DNSEntryStatus {
  /** Only the uses the caller may read. */
  uses: DNSEntryUse[] | null;
  hidden_uses: number;
  login_bypass_hosts: number;
}

export interface DNSApplyState {
  last_dns_reload_at: string | null;
  pending_additions: number;
  revoke_pending: number;
  blocked_outcome: DNSBlockedReason | null;
  blocked_detail: string | null;
  blocking_file: string | null;
  next_retry_at: string | null;
}

export interface DNSEntryOverview {
  /** Effective values: the environment switches applied. */
  settings: DNSEntrySettings;
  env_disabled: boolean;
  env_interval_seconds: number | null;
  total_names: number;
  apply: DNSApplyState;
  entries: DNSEntryOverviewEntry[] | null;
}

export interface DNSApplyResponse {
  outcome: string;
  detail: string | null;
  blocking_file: string | null;
}
