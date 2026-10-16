import type { DNSEntryStatus, DNSHostRef } from './dnsEntries';

/** How the API classified a stored rule (#320). */
export type AccessListItemKind = 'address' | 'hostname' | 'legacy';

export interface AccessListItem {
  id: string;
  access_list_id: string;
  directive: 'allow' | 'deny';
  address: string;
  description?: string;
  sort_order: number;
  created_at: string;
  kind?: AccessListItemKind;
  /** Legacy rows only: "ignored" (an allow nginx never got) or "deny_all" (enforced as deny all). */
  effect?: 'ignored' | 'deny_all';
  /** Domain rows only; omitted when unknown (the server could not read the state). */
  dns?: DNSEntryStatus | null;
}

export interface AccessList {
  id: string;
  name: string;
  description?: string;
  satisfy_any: boolean;
  pass_auth: boolean;
  items: AccessListItem[];
  /** Hosts with a login that this list lets a domain's address skip; hosts is null without proxy:read. */
  login_bypass_hosts?: { count: number; hosts: DNSHostRef[] | null };
  created_at: string;
  updated_at: string;
}

export interface CreateAccessListRequest {
  name: string;
  description?: string;
  satisfy_any?: boolean;
  pass_auth?: boolean;
  items?: {
    directive: 'allow' | 'deny';
    address: string;
    description?: string;
    sort_order?: number;
    kind?: AccessListItemKind;
  }[];
}

export interface RedirectHost {
  id: string;
  domain_names: string[];
  forward_scheme: string;
  forward_domain_name: string;
  forward_path: string;
  preserve_path: boolean;
  redirect_code: number;
  ssl_enabled: boolean;
  certificate_id?: string;
  ssl_force_https: boolean;
  enabled: boolean;
  block_exploits: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateRedirectHostRequest {
  domain_names: string[];
  forward_scheme?: string;
  forward_domain_name: string;
  forward_path?: string;
  preserve_path?: boolean;
  redirect_code?: number;
  ssl_enabled?: boolean;
  certificate_id?: string;
  ssl_force_https?: boolean;
  enabled?: boolean;
  block_exploits?: boolean;
}

export interface GeoRestriction {
  id: string;
  proxy_host_id: string;
  mode: 'whitelist' | 'blacklist';
  countries: string[];
  allowed_ips: string[];
  allow_private_ips: boolean;
  allow_search_bots: boolean;
  enabled: boolean;
  challenge_mode: boolean;
  disable_global: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateGeoRestrictionRequest {
  mode: 'whitelist' | 'blacklist';
  countries: string[];
  allowed_ips?: string[];
  allow_private_ips?: boolean;
  allow_search_bots?: boolean;
  enabled?: boolean;
  challenge_mode?: boolean;
  disable_global?: boolean;
}
