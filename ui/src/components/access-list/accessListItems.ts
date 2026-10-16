import type { AccessList, AccessListItem, AccessListItemKind, CreateAccessListRequest } from '../../types/access';
import { DNS_NAME_ERROR_CODES, classifyEntry } from '../common/dns/dnsName';

// The access-list form's rows and the request built from them (#320).
//
// The request lists IP rules and legacy rows in form order, then domain rows:
// nginx evaluates rules in order and domains come after every IP rule, so an IP
// this list denies stays denied. Legacy rows go back verbatim at their place: a
// legacy deny is enforced as "deny all" where it stands, so moving it would let
// the allows below it start matching. sort_order is the request index, and a 400
// names items[i] by that index, so rowOfRequestIndex maps it back to a row.

export type RuleDirective = 'allow' | 'deny';
export type LegacyEffect = 'ignored' | 'deny_all';
export type RuleField = 'directive' | 'address' | 'description';

export interface AccessRuleRow {
  key: string;
  directive: RuleDirective;
  address: string;
  description: string;
  /**
   * Set on rows the API reports as kind "legacy": a name saved before domain
   * entries existed. They are read-only and are sent back unchanged.
   */
  legacy?: LegacyEffect;
}

export type AccessListRequestItem = NonNullable<CreateAccessListRequest['items']>[number];

export interface RowError {
  code?: string;
  /** The server's sentence, for a code the UI has no text for. */
  message?: string;
}

export interface BuiltItems {
  items: AccessListRequestItem[];
  /** rowOfRequestIndex[i] is the index in rows of request item i. */
  rowOfRequestIndex: number[];
  /** Checks that failed, by row key. Nothing is sent while this is not empty. */
  errors: Record<string, RowError>;
}

let rowSeq = 0;

export function blankRow(): AccessRuleRow {
  rowSeq += 1;
  return { key: `rule-${rowSeq}`, directive: 'allow', address: '', description: '' };
}

/** The kind of a stored rule. A rule without a kind is never read as a domain. */
export function itemKind(item: AccessListItem): AccessListItemKind {
  if (item.kind) return item.kind;
  const entry = classifyEntry(item.address);
  return entry.kind === 'ip' || entry.kind === 'all' ? 'address' : 'legacy';
}

/** The form rows of a stored list, in stored order, with one blank row to type into when there is no editable rule. */
export function rowsFromList(list: AccessList | null): AccessRuleRow[] {
  const rows: AccessRuleRow[] = [];
  for (const item of list?.items ?? []) {
    const kind = itemKind(item);
    const row: AccessRuleRow = {
      ...blankRow(),
      directive: kind === 'hostname' ? 'allow' : item.directive,
      address: item.address,
      description: item.description ?? '',
    };
    if (kind === 'legacy') {
      row.legacy = item.effect ?? (item.directive === 'deny' ? 'deny_all' : 'ignored');
    }
    rows.push(row);
  }
  if (!rows.some((row) => !row.legacy)) rows.push(blankRow());
  return rows;
}

/** The items of a save request, or the rows that stop it. Blank rows are left out. */
export function buildItemsRequest(rows: AccessRuleRow[]): BuiltItems {
  const errors: Record<string, RowError> = {};
  const head: Array<{ item: AccessListRequestItem; row: number }> = [];
  const tail: Array<{ item: AccessListRequestItem; row: number }> = [];
  const names = new Set<string>();
  let denyAllRow = -1;

  rows.forEach((row, index) => {
    const description = row.description || undefined;
    if (row.legacy) {
      head.push({ item: { directive: row.directive, address: row.address, description, kind: 'legacy' }, row: index });
      if (row.directive === 'deny' && denyAllRow < 0) denyAllRow = index;
      return;
    }
    const address = row.address.trim();
    if (address === '') return;
    const entry = classifyEntry(address);
    if (entry.kind === 'all' || entry.kind === 'ip') {
      head.push({ item: { directive: row.directive, address, description, kind: 'address' }, row: index });
      if (entry.kind === 'all' && row.directive === 'deny' && denyAllRow < 0) denyAllRow = index;
      return;
    }
    if (entry.kind === 'invalid' || !entry.ascii) {
      errors[row.key] = { code: entry.code };
      return;
    }
    if (row.directive === 'deny') {
      errors[row.key] = { code: 'deny_hostname' };
      return;
    }
    if (names.has(entry.ascii)) {
      errors[row.key] = { code: 'duplicate_hostname' };
      return;
    }
    names.add(entry.ascii);
    tail.push({ item: { directive: 'allow', address: entry.ascii, description, kind: 'hostname' }, row: index });
  });

  // A "deny all" before the domains (an IP rule, or a legacy deny enforced as
  // one) means no domain can ever match: the server refuses that list and
  // names the first such rule, so the form marks that rule too.
  if (denyAllRow >= 0 && tail.length > 0) {
    errors[rows[denyAllRow].key] = { code: 'deny_all_with_hostname' };
  }

  const ordered = head.concat(tail);
  return {
    items: ordered.map((entry, i) => ({ ...entry.item, sort_order: i })),
    rowOfRequestIndex: ordered.map((entry) => entry.row),
    errors,
  };
}

/** Whether a legacy row can become a domain entry: an allow whose name passes the rules. */
export function canMoveToDomain(row: AccessRuleRow): boolean {
  return row.legacy === 'ignored' && row.directive === 'allow' && classifyEntry(row.address).kind === 'hostname';
}

export interface ItemFieldError {
  requestIndex: number;
  field: string;
  code?: string;
  message: string;
}

const ITEM_PATH = /^items\[(\d+)\]\.([a-z_]+)/;

/** The request item a 400 names: from the body's field, else from the start of its message. */
export function itemFieldError(err: unknown): ItemFieldError | null {
  if (!(err instanceof Error)) return null;
  const e = err as Error & { field?: string; code?: string };
  const m = ITEM_PATH.exec(e.field ?? '') || ITEM_PATH.exec(e.message);
  if (!m) return null;
  return { requestIndex: Number(m[1]), field: m[2], code: e.code, message: e.message };
}

const LIST_ERROR_CODES = ['hostname_needs_kind', 'deny_hostname', 'duplicate_hostname', 'deny_all_with_hostname', 'legacy_not_in_list', 'limit'];

/** The i18n key ("namespace:path") that explains an error code, or null to show the server's sentence. */
export function errorTextKey(code: string | undefined): string | null {
  if (!code) return null;
  if (DNS_NAME_ERROR_CODES.includes(code)) return `dnsEntries:nameErrors.${code}`;
  if (LIST_ERROR_CODES.includes(code)) return `accessControl:errors.${code}`;
  return null;
}
