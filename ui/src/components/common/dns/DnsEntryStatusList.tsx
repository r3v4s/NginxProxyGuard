import { useTranslation } from 'react-i18next';
import type { DNSEntryStatus } from '../../../types/dnsEntries';
import { DnsStatusBadge } from './DnsStatusBadge';
import { familyStateKey, formatDnsTime } from './dnsName';

/** One domain as a list shows it. status is null until the server has checked the name. */
export interface DnsEntryRow {
  hostname: string;
  description?: string;
  status: DNSEntryStatus | null;
}

interface DnsEntryStatusListProps {
  entries: DnsEntryRow[];
  /** Shows "Allow again" on names in review. The caller passes its own write permission. */
  canConfirm: boolean;
  onConfirm: (hostname: string) => void;
}

// A domain can carry many addresses; show a few and count the rest so one
// name cannot stretch the card (memory: unbounded list in card UI).
const VISIBLE_ADDRESSES = 4;

const FAMILIES = ['ipv4', 'ipv6'];

function AddressList({ addresses }: { addresses: string[] }) {
  const { t } = useTranslation('dnsEntries');
  const shown = addresses.slice(0, VISIBLE_ADDRESSES);
  const rest = addresses.slice(VISIBLE_ADDRESSES);
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      {shown.map((address) => (
        <span key={address} className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-slate-700 dark:bg-slate-700/60 dark:text-slate-200">
          {address}
        </span>
      ))}
      {rest.length > 0 && (
        <span className="text-xs text-slate-500 dark:text-slate-400" title={rest.join(', ')}>
          {t('list.more', { count: rest.length })}
        </span>
      )}
    </span>
  );
}

function EntryDetails({ hostname, status }: { hostname: string; status: DNSEntryStatus }) {
  const { t, i18n } = useTranslation('dnsEntries');
  const time = (iso: string | null) => formatDnsTime(iso, i18n.language);
  const addresses = status.addresses ?? [];
  const pending = status.pending_addresses ?? [];
  const warnings = status.warnings ?? [];
  const familyProblems = FAMILIES.filter((family) => {
    const state = familyStateKey(status.families?.[family]?.state);
    return state === 'transient' || state === 'rejected';
  });

  return (
    <div className="mt-1.5 space-y-1 text-xs">
      {status.status === 'needs_review' && status.review_reason && (
        <p className="text-orange-700 dark:text-orange-300">
          {t(`review.${status.review_reason}`, {
            from: status.canonical_name || '-',
            to: status.observed_canonical_name || '-',
          })}
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {addresses.length > 0 ? (
          <AddressList addresses={addresses} />
        ) : (
          <span className="text-slate-500 dark:text-slate-400">{t('list.noAddresses')}</span>
        )}
        {status.canonical_name && status.canonical_name !== hostname && (
          <span className="rounded bg-slate-100 px-1.5 py-0.5 text-slate-600 dark:bg-slate-700/60 dark:text-slate-300">
            {t('list.canonical', { name: status.canonical_name })}
          </span>
        )}
        {warnings.map((warning) => (
          <span
            key={warning}
            title={t(`warningHelp.${warning}`, { defaultValue: '' })}
            className="rounded bg-amber-100 px-1.5 py-0.5 font-medium text-amber-800 dark:bg-amber-900/30 dark:text-amber-300"
          >
            {t(`warnings.${warning}`, { defaultValue: warning })}
          </span>
        ))}
      </div>

      {pending.length > 0 && (
        <p className="text-amber-700 dark:text-amber-300">
          {status.next_apply_at
            ? t('list.pendingAt', { time: time(status.next_apply_at), addresses: pending.join(', ') })
            : t('list.pending', { addresses: pending.join(', ') })}
        </p>
      )}

      {status.blocked_reason && (
        <p className={status.revoke_pending ? 'text-red-700 dark:text-red-300' : 'text-amber-700 dark:text-amber-300'}>
          {t('list.notAppliedBecause', { reason: t(`blocked.${status.blocked_reason}`, { defaultValue: status.blocked_reason }) })}
          {status.blocking_file && <span className="ml-1 font-mono">{t('blocked.file', { file: status.blocking_file })}</span>}
        </p>
      )}

      {!status.blocked_reason && !status.applied && !status.revoke_pending && addresses.length > 0 && (
        <p className="text-slate-500 dark:text-slate-400">{t('list.notApplied')}</p>
      )}

      {familyProblems.map((family) => {
        const fam = status.families?.[family];
        const state = t(`familyState.${familyStateKey(fam?.state)}`);
        const code = fam?.code ? t(`errorCodes.${fam.code}`, { defaultValue: fam.code }) : '';
        return (
          <p key={family} className="text-slate-600 dark:text-slate-300">
            {code
              ? t('list.familyWithCode', { family: t(`families.${family}`), state, code })
              : t('list.family', { family: t(`families.${family}`), state })}
          </p>
        );
      })}

      {status.status === 'stale' && status.stale_until && (
        <p className="text-amber-700 dark:text-amber-300">{t('list.staleUntil', { time: time(status.stale_until) })}</p>
      )}

      {status.error_code && familyProblems.length === 0 && (
        <p className="text-slate-600 dark:text-slate-300">
          {t('list.lastError', { code: t(`errorCodes.${status.error_code}`, { defaultValue: status.error_code }) })}
        </p>
      )}

      <p className="text-slate-400 dark:text-slate-500">
        {status.last_checked_at ? t('list.checkedAt', { time: time(status.last_checked_at) }) : t('list.neverChecked')}
      </p>
    </div>
  );
}

/**
 * The domains of one list with their DNS state: status, allowed addresses,
 * what waits for nginx, warnings, and "Allow again" for a name in review.
 * Everything comes in through props, so other lists can reuse it.
 */
export function DnsEntryStatusList({ entries, canConfirm, onConfirm }: DnsEntryStatusListProps) {
  const { t } = useTranslation('dnsEntries');
  return (
    <ul className="space-y-2">
      {entries.map((entry) => (
        <li
          key={entry.hostname}
          data-testid="dns-entry"
          data-hostname={entry.hostname}
          className="rounded-lg border border-slate-200 bg-white px-3 py-2 dark:border-slate-700 dark:bg-slate-800/60"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="break-all font-mono text-sm text-slate-800 dark:text-slate-100">{entry.hostname}</span>
            <DnsStatusBadge status={entry.status} />
            {entry.description && (
              <span className="text-xs text-slate-500 dark:text-slate-400">- {entry.description}</span>
            )}
            {canConfirm && entry.status?.status === 'needs_review' && (
              <button
                type="button"
                onClick={() => onConfirm(entry.hostname)}
                className="ml-auto rounded-md bg-orange-600 px-2.5 py-1 text-xs font-medium text-white transition-colors hover:bg-orange-700 dark:bg-orange-500 dark:hover:bg-orange-600"
              >
                {t('actions.confirm')}
              </button>
            )}
          </div>
          {entry.status && <EntryDetails hostname={entry.hostname} status={entry.status} />}
        </li>
      ))}
    </ul>
  );
}
