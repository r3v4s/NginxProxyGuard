import { apiGet, apiPost } from './client';
import type { DNSApplyResponse, DNSEntryOverview } from '../types/dnsEntries';

// Domain entries (#320): the settings sub-tab's overview and "Apply now". The
// tunables themselves are read and saved through GET/PUT /system-settings
// (dns_entry_settings), like every other system setting.

const BASE = '/api/v1/dns-entries';

/**
 * Every domain in use, and every one nginx may still allow after it was
 * removed, with its state and the places that use it; the apply state; the
 * settings in effect and the environment switches. Needs settings:read.
 * Places the caller may not read come only as a count (hidden_uses).
 */
export async function getDNSEntries(): Promise<DNSEntryOverview> {
  return apiGet<DNSEntryOverview>(BASE);
}

/**
 * "Apply now": nginx -t and a reload at once (settings:write). Every outcome
 * is a 200 with what happened, except a reload nginx refused: that is a 409
 * nginx_reload_rejected (isNginxReloadRefusal).
 */
export async function applyDNSEntriesNow(): Promise<DNSApplyResponse> {
  return apiPost<DNSApplyResponse>(`${BASE}/apply`);
}
