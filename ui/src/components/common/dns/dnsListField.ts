import { DNS_NAME_ERROR_CODES, classifyEntry, toAsciiName } from './dnsName';

// The domain fields of the exception lists (#320): URI block exceptions,
// priority allow, rate limit exceptions and the global trusted list. Each
// list keeps its domains in a field of its own beside its IP field; these are
// the helpers the screens share around DnsHostnamesField.

/** How often a list polls while dnsNeedsPolling says something is on its way. */
export const DNS_POLL_MS = 10000;

/** A save's refusal of a domain field: of one name, or of the whole list. */
export interface DnsNamesError {
  /** The refused name as it was sent; absent when the refusal is about the list. */
  name?: string;
  code?: string;
  /** The server's sentence, for a code the UI has no text for. */
  message?: string;
}

const FIELD_INDEX = /^([a-z_]+)\[(\d+)\]$/;

/**
 * The refusals in err that are about the domain field `field` of a save that
 * sent `sent`: a 400 naming field[i] is about sent[i], and one naming the
 * field, or a domain limit (code limit, which can name the total), is about
 * the list. Empty when err is about something else.
 */
export function dnsNamesErrorsOf(err: unknown, field: string, sent: readonly string[] | null | undefined): DnsNamesError[] {
  if (!(err instanceof Error)) return [];
  const e = err as Error & { field?: string; code?: string };
  if (e.code === 'limit' || e.field === field) return [{ code: e.code, message: e.message }];
  const m = FIELD_INDEX.exec(e.field ?? '');
  if (!m || m[1] !== field) return [];
  return [{ name: (sent ?? [])[Number(m[2])], code: e.code, message: e.message }];
}

const LIST_ERROR_CODES = ['limit', 'duplicate_hostname', 'hostname_in_ip_field'];

/** The i18n key ("namespace:path") that explains a code, or null to show the server's sentence. */
export function dnsErrorTextKey(code: string | undefined): string | null {
  if (!code) return null;
  if (DNS_NAME_ERROR_CODES.includes(code)) return `dnsEntries:nameErrors.${code}`;
  if (LIST_ERROR_CODES.includes(code)) return `dnsEntries:listErrors.${code}`;
  return null;
}

/** The name an entry of an IP field becomes when moved to the domains, or null when it is not one. */
export function movableName(entry: string): string | null {
  const result = toAsciiName(entry);
  return 'ascii' in result ? result.ascii : null;
}

/** The entries that are domain names: typed into an IP field, where they do nothing. */
export function domainLikeEntries(entries: readonly string[]): string[] {
  return entries.filter((entry) => classifyEntry(entry).kind === 'hostname');
}

/**
 * The entries of ignored (as the server reports them: trimmed) that lines
 * still holds, once each and in ignored's order: an entry already removed
 * from the field is not offered again.
 */
export function ignoredStillIn(ignored: readonly string[] | null | undefined, lines: readonly string[]): string[] {
  const present = new Set(lines.map((line) => line.trim()));
  return [...new Set(ignored ?? [])].filter((entry) => present.has(entry));
}

/** text without the lines that are entry once trimmed. */
export function withoutLine(text: string, entry: string): string {
  return text
    .split('\n')
    .filter((line) => line.trim() !== entry)
    .join('\n');
}

/** names with name added at the end, unless it is there already. */
export function withName(names: readonly string[] | null | undefined, name: string): string[] {
  const list = names ?? [];
  return list.includes(name) ? [...list] : [...list, name];
}

/**
 * A list's GET as a string, without the state of its domains (the
 * *_hostname_status fields): it changes when the list does, not when a lookup
 * does. A screen that copies a GET into a draft copies again only when this
 * changes, so the poll that refreshes the state never throws an edit away.
 */
export function dnsConfigKey(data: unknown): string {
  return JSON.stringify(data ?? null, (key, value) => (key.endsWith('_hostname_status') ? undefined : value));
}
