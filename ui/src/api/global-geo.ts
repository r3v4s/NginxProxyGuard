import { apiGet, apiPost, apiPut } from './client'
import type { DNSConfirmRequest, DNSEntryStatus } from '../types/dnsEntries'

/**
 * Global GeoIP restriction default. Mirrors the backend contract at
 * `GET/PUT /api/v1/settings/global-geo`. Hosts with per-host geo set to
 * "inherit" fall back to this default; updating it regenerates all
 * inheriting hosts server-side.
 */
export interface GlobalGeoRestriction {
  id?: string
  enabled: boolean
  mode: 'whitelist' | 'blacklist'
  countries: string[]
  allowed_ips: string[]
  allow_private_ips: boolean
  allow_search_bots: boolean
  challenge_mode: boolean
  created_at?: string
  updated_at?: string
  // Priority allow domains (#320): left out of a PUT keeps them, [] clears
  // them. GET also sends their state and the entries of allowed_ips the
  // configs leave out (not an address, saved by an older version).
  allowed_hostnames?: string[]
  allowed_hostname_status?: DNSEntryStatus[]
  allowed_ips_ignored?: string[]
}

export async function getGlobalGeo(): Promise<GlobalGeoRestriction> {
  return apiGet<GlobalGeoRestriction>('/api/v1/settings/global-geo')
}

export async function updateGlobalGeo(
  req: Partial<GlobalGeoRestriction>,
): Promise<GlobalGeoRestriction> {
  return apiPut<GlobalGeoRestriction>('/api/v1/settings/global-geo', req)
}

/** Allows a priority allow domain in review again, with the values the operator was shown (#320). */
export async function confirmGlobalGeoDNS(body: DNSConfirmRequest): Promise<DNSEntryStatus> {
  return apiPost<DNSEntryStatus>('/api/v1/settings/global-geo/dns-confirm', body)
}
