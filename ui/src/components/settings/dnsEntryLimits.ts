import type { DNSEntrySettings } from '../../types/dnsEntries';

// The domain entry tunables of Settings › Domain entries (DDNS) (#320).

/**
 * Ranges and defaults the server uses (api/internal/model/dns_entry_settings.go,
 * the DNSEntry*Min/Max/Default constants). Kept identical so the form never
 * offers a value the server refuses: change both files together.
 */
export const DNS_ENTRY_LIMITS = {
  check_interval_seconds: { min: 30, max: 3600, def: 60 },
  min_reload_gap_seconds: { min: 60, max: 3600, def: 300 },
  stale_grace_hours: { min: 1, max: 168, def: 24 },
  not_found_checks: { min: 1, max: 10, def: 2 },
  max_changes_per_day: { min: 2, max: 48, def: 6 },
  max_per_list: { min: 1, max: 64, def: 16 },
  max_total: { min: 1, max: 256, def: 64 },
  max_addresses_per_family: { min: 1, max: 16, def: 4 },
} as const;

/** A numeric tunable: every key of DNSEntrySettings except enabled. */
export type DnsEntryNumberField = keyof typeof DNS_ENTRY_LIMITS;

export type DnsEntryFieldGroup = 'lookup' | 'apply' | 'limits';

/** The form's sections in order, and the numbers each one holds. */
export const DNS_ENTRY_FIELD_GROUPS: ReadonlyArray<{ key: DnsEntryFieldGroup; fields: readonly DnsEntryNumberField[] }> = [
  { key: 'lookup', fields: ['check_interval_seconds', 'stale_grace_hours', 'not_found_checks', 'max_addresses_per_family'] },
  { key: 'apply', fields: ['min_reload_gap_seconds', 'max_changes_per_day'] },
  { key: 'limits', fields: ['max_per_list', 'max_total'] },
];

/** What the operator changed in the form. A key left out keeps its stored value. */
export type DnsEntrySettingsDraft = Partial<DNSEntrySettings>;

const NUMBER_FIELDS = Object.keys(DNS_ENTRY_LIMITS) as DnsEntryNumberField[];

/** True when value is a whole number inside the server's range for field. */
export function inDnsEntryRange(field: DnsEntryNumberField, value: unknown): boolean {
  const { min, max } = DNS_ENTRY_LIMITS[field];
  return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;
}

/**
 * The edited numbers outside their range. Only edited keys are checked: the
 * stored value comes back from the server already clamped into range.
 */
export function invalidDnsEntryFields(draft: DnsEntrySettingsDraft): DnsEntryNumberField[] {
  return NUMBER_FIELDS.filter((field) => field in draft && !inDnsEntryRange(field, draft[field]));
}

/**
 * The dns_entry_settings of a save: the edited keys whose value differs from
 * the stored one, nothing else. The server merges this over the STORED value,
 * so a key left out keeps what is stored: never a default, and never the off
 * that NPG_DNS_ENTRIES_DISABLED forces on the value in effect. Empty when
 * nothing changed.
 */
export function dnsEntrySettingsPatch(stored: DNSEntrySettings, draft: DnsEntrySettingsDraft): DnsEntrySettingsDraft {
  const patch: DnsEntrySettingsDraft = {};
  if (draft.enabled !== undefined && draft.enabled !== stored.enabled) {
    patch.enabled = draft.enabled;
  }
  for (const field of NUMBER_FIELDS) {
    const value = draft[field];
    if (value !== undefined && value !== stored[field]) {
      patch[field] = value;
    }
  }
  return patch;
}
