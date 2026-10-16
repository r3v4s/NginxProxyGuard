import { useTranslation } from 'react-i18next';
import type { DNSEntryOverviewEntry } from '../../types/dnsEntries';
import { DnsStatusBadge } from '../common/dns/DnsStatusBadge';
import { formatDnsTime } from '../common/dns/dnsName';
import { confirmListOf, splitUses } from './dnsEntryOverview';

interface DnsEntryOverviewTableProps {
  entries: DNSEntryOverviewEntry[];
  /** The caller may confirm through an access list (access:write). */
  canConfirm: boolean;
  /** Opens "Allow again" for a name, through the given access list. */
  onConfirm: (hostname: string, listId: string) => void;
}

// A name can carry many addresses and many uses: show a few and count the
// rest so one row cannot stretch the table (memory: unbounded list in card UI).
const VISIBLE_ADDRESSES = 4;
const VISIBLE_USES = 3;

const chip = 'rounded px-1.5 py-0.5 text-xs';

/**
 * Every domain in use: where it is used, its state, the
 * addresses nginx allows, warnings, hosts where it skips a login, and
 * "Allow again" for a name in review.
 */
export default function DnsEntryOverviewTable({ entries, canConfirm, onConfirm }: DnsEntryOverviewTableProps) {
  const { t, i18n } = useTranslation('dnsEntries');
  const time = (iso: string | null) => formatDnsTime(iso, i18n.language);

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[48rem] text-sm">
        <thead>
          <tr className="border-b border-slate-200 text-left text-xs font-semibold uppercase tracking-wide text-slate-500 dark:border-slate-700 dark:text-slate-400">
            <th scope="col" className="px-3 py-2">{t('overview.columns.name')}</th>
            <th scope="col" className="px-3 py-2">{t('overview.columns.uses')}</th>
            <th scope="col" className="px-3 py-2">{t('overview.columns.status')}</th>
            <th scope="col" className="px-3 py-2">{t('overview.columns.addresses')}</th>
            <th scope="col" className="px-3 py-2">{t('overview.columns.warnings')}</th>
            <th scope="col" className="px-3 py-2">
              <span className="sr-only">{t('overview.columns.actions')}</span>
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-700/60">
          {entries.map((entry) => {
            const addresses = entry.addresses ?? [];
            const pending = entry.pending_addresses ?? [];
            const warnings = entry.warnings ?? [];
            const { shown, rest } = splitUses(entry.uses, VISIBLE_USES);
            const listId = confirmListOf(entry);
            const pendingText =
              pending.slice(0, VISIBLE_ADDRESSES).join(', ') +
              (pending.length > VISIBLE_ADDRESSES ? ` ${t('list.more', { count: pending.length - VISIBLE_ADDRESSES })}` : '');
            return (
              <tr key={entry.hostname} data-testid="dns-overview-row" data-hostname={entry.hostname} className="align-top">
                <td className="px-3 py-3">
                  <span className="break-all font-mono text-sm text-slate-800 dark:text-slate-100">{entry.hostname}</span>
                  {entry.canonical_name && entry.canonical_name !== entry.hostname && (
                    <span className="mt-1 block break-all text-xs text-slate-500 dark:text-slate-400">
                      {t('list.canonical', { name: entry.canonical_name })}
                    </span>
                  )}
                  <span className="mt-1 block text-xs text-slate-400 dark:text-slate-500">
                    {entry.last_checked_at
                      ? t('list.checkedAt', { time: time(entry.last_checked_at) })
                      : t('list.neverChecked')}
                  </span>
                </td>

                <td className="px-3 py-3">
                  <div className="flex flex-wrap gap-1">
                    {shown.map((use) => (
                      <span
                        key={use.scope}
                        className={`${chip} bg-indigo-50 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300`}
                      >
                        {t('overview.use', {
                          kind: t(`overview.useKinds.${use.kind}`, { defaultValue: use.kind }),
                          name: use.owner_name,
                        })}
                      </span>
                    ))}
                    {rest.length > 0 && (
                      <span
                        className="text-xs text-slate-500 dark:text-slate-400"
                        title={rest.map((use) => use.owner_name).join(', ')}
                      >
                        {t('list.more', { count: rest.length })}
                      </span>
                    )}
                    {entry.hidden_uses > 0 && (
                      <span
                        className={`${chip} bg-slate-100 text-slate-600 dark:bg-slate-700/60 dark:text-slate-300`}
                        title={t('overview.hiddenUsesHelp')}
                      >
                        {t('overview.hiddenUses', { count: entry.hidden_uses })}
                      </span>
                    )}
                    {shown.length === 0 && entry.hidden_uses === 0 && (
                      <span className="text-xs text-slate-500 dark:text-slate-400">{t('overview.noUses')}</span>
                    )}
                  </div>
                </td>

                <td className="px-3 py-3">
                  <DnsStatusBadge status={entry} />
                  {entry.status === 'needs_review' && entry.review_reason && (
                    <p className="mt-1 text-xs text-orange-700 dark:text-orange-300">
                      {t(`review.${entry.review_reason}`, {
                        from: entry.canonical_name || '-',
                        to: entry.observed_canonical_name || '-',
                      })}
                    </p>
                  )}
                  {entry.blocked_reason && (
                    <p
                      className={`mt-1 text-xs ${entry.revoke_pending ? 'text-red-700 dark:text-red-300' : 'text-amber-700 dark:text-amber-300'}`}
                    >
                      {t('list.notAppliedBecause', {
                        reason: t(`blocked.${entry.blocked_reason}`, { defaultValue: entry.blocked_reason }),
                      })}
                      {entry.blocking_file && (
                        <span className="ml-1 font-mono">{t('blocked.file', { file: entry.blocking_file })}</span>
                      )}
                    </p>
                  )}
                  {!entry.blocked_reason && !entry.applied && !entry.revoke_pending && addresses.length > 0 && (
                    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('list.notApplied')}</p>
                  )}
                  {entry.status === 'stale' && entry.stale_until && (
                    <p className="mt-1 text-xs text-amber-700 dark:text-amber-300">
                      {t('list.staleUntil', { time: time(entry.stale_until) })}
                    </p>
                  )}
                  {entry.error_code && (
                    <p className="mt-1 text-xs text-slate-600 dark:text-slate-300">
                      {t('list.lastError', {
                        code: t(`errorCodes.${entry.error_code}`, { defaultValue: entry.error_code }),
                      })}
                    </p>
                  )}
                </td>

                <td className="px-3 py-3">
                  {addresses.length > 0 ? (
                    <div className="flex flex-wrap items-center gap-1">
                      {addresses.slice(0, VISIBLE_ADDRESSES).map((address) => (
                        <span
                          key={address}
                          className={`${chip} bg-slate-100 font-mono text-slate-700 dark:bg-slate-700/60 dark:text-slate-200`}
                        >
                          {address}
                        </span>
                      ))}
                      {addresses.length > VISIBLE_ADDRESSES && (
                        <span
                          className="text-xs text-slate-500 dark:text-slate-400"
                          title={addresses.slice(VISIBLE_ADDRESSES).join(', ')}
                        >
                          {t('list.more', { count: addresses.length - VISIBLE_ADDRESSES })}
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="text-xs text-slate-500 dark:text-slate-400">{t('list.noAddresses')}</span>
                  )}
                  {pending.length > 0 && (
                    <p className="mt-1 text-xs text-amber-700 dark:text-amber-300">
                      {entry.next_apply_at
                        ? t('list.pendingAt', { time: time(entry.next_apply_at), addresses: pendingText })
                        : t('list.pending', { addresses: pendingText })}
                    </p>
                  )}
                </td>

                <td className="px-3 py-3">
                  <div className="flex flex-wrap gap-1">
                    {warnings.map((warning) => (
                      <span
                        key={warning}
                        title={t(`warningHelp.${warning}`, { defaultValue: '' })}
                        className={`${chip} bg-amber-100 font-medium text-amber-800 dark:bg-amber-900/30 dark:text-amber-300`}
                      >
                        {t(`warnings.${warning}`, { defaultValue: warning })}
                      </span>
                    ))}
                    {entry.login_bypass_hosts > 0 && (
                      <span
                        data-testid="dns-login-bypass"
                        title={t('overview.loginBypassHelp')}
                        className={`${chip} bg-orange-100 font-medium text-orange-800 dark:bg-orange-900/30 dark:text-orange-300`}
                      >
                        {t('overview.loginBypass', { count: entry.login_bypass_hosts })}
                      </span>
                    )}
                    {warnings.length === 0 && entry.login_bypass_hosts === 0 && (
                      <span className="text-xs text-slate-400 dark:text-slate-500">-</span>
                    )}
                  </div>
                </td>

                <td className="px-3 py-3 text-right">
                  {canConfirm && entry.status === 'needs_review' && listId && (
                    <button
                      type="button"
                      onClick={() => onConfirm(entry.hostname, listId)}
                      className="whitespace-nowrap rounded-md bg-orange-600 px-2.5 py-1 text-xs font-medium text-white transition-colors hover:bg-orange-700 dark:bg-orange-500 dark:hover:bg-orange-600"
                    >
                      {t('actions.confirm')}
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
