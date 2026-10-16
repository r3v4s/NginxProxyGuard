import type { DNSEntryOverview, DNSEntryOverviewEntry, DNSEntryUse } from '../../types/dnsEntries';
import { dnsNeedsPolling } from '../common/dns/dnsName';

// Pure helpers of the domain entry overview (#320).

export type DnsNoticeTone = 'success' | 'info' | 'warning' | 'error';

/** A message on the settings sub-tab. */
export interface DnsNotice {
  tone: DnsNoticeTone;
  text: string;
  /** nginx's own line or the blocking file, shown in mono under the text. */
  details?: string;
}

/**
 * True while the overview shows something still on its way: an addition
 * nginx has not loaded, a removal nginx still allows, a first answer, or an
 * address waiting for its turn. The screen polls only then.
 */
export function dnsOverviewNeedsPolling(ov: DNSEntryOverview | undefined): boolean {
  if (!ov) return false;
  return ov.apply.pending_additions > 0 || ov.apply.revoke_pending > 0 || dnsNeedsPolling(ov.entries ?? []);
}

/**
 * The access list whose confirm route "Allow again" goes through for this
 * name: the first one the caller can see. A confirm opens the name in every
 * place that uses it, and the server checks the write permission of each.
 */
export function confirmListOf(entry: DNSEntryOverviewEntry): string | null {
  const use = (entry.uses ?? []).find((u) => u.kind === 'access_list' && u.owner_id !== '');
  return use ? use.owner_id : null;
}

/** The first max uses as chips, and the rest for a "+N". */
export function splitUses(uses: DNSEntryUse[] | null, max: number): { shown: DNSEntryUse[]; rest: DNSEntryUse[] } {
  const all = uses ?? [];
  return { shown: all.slice(0, max), rest: all.slice(max) };
}

/**
 * How the result of "Apply now" reads: success when nginx took the files (a
 * signal without a probe counts as taken, as it does for a save), info when
 * that is not known yet or nginx tests are off, a warning while nginx is not
 * up, an error when the apply failed.
 */
export function applyOutcomeTone(outcome: string): DnsNoticeTone {
  switch (outcome) {
    case 'accepted':
    case 'signalled':
      return 'success';
    case 'not_up':
      return 'warning';
    case 'blocked':
    case 'failed':
    case 'rejected':
      return 'error';
    default:
      return 'info';
  }
}

/** Outcomes the screen has its own sentence for (overview.applyResult.<outcome>). */
export const DNS_APPLY_OUTCOMES: readonly string[] = [
  'accepted',
  'signalled',
  'unconfirmed',
  'skipped',
  'blocked',
  'failed',
  'not_up',
  'rejected',
];
