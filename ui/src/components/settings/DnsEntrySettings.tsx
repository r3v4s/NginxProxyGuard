import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { confirmAccessListDNS } from '../../api/access';
import type { ApiError } from '../../api/client';
import { getDNSEntries } from '../../api/dnsEntries';
import { getSystemSettings } from '../../api/settings';
import { usePageVisibility } from '../../hooks/usePageVisibility';
import { usePermissions } from '../../hooks/usePermissions';
import { DnsConfirmDialog } from '../common/dns/DnsConfirmDialog';
import { XIcon } from '../common/listui';
import DnsEntryApplyBar from './DnsEntryApplyBar';
import DnsEntryOverviewTable from './DnsEntryOverviewTable';
import DnsEntryTunablesCard from './DnsEntryTunablesCard';
import { dnsOverviewNeedsPolling, type DnsNotice, type DnsNoticeTone } from './dnsEntryOverview';

const NOTICE_STYLES: Record<DnsNoticeTone, string> = {
  success:
    'border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-800/60 dark:bg-emerald-900/20 dark:text-emerald-200',
  info: 'border-blue-200 bg-blue-50 text-blue-800 dark:border-blue-800/60 dark:bg-blue-900/20 dark:text-blue-200',
  warning: 'border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-800/60 dark:bg-amber-900/20 dark:text-amber-200',
  error: 'border-red-200 bg-red-50 text-red-800 dark:border-red-800/60 dark:bg-red-900/20 dark:text-red-200',
};

const card =
  'rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition-colors dark:border-slate-700 dark:bg-slate-800';
const skeleton = 'h-24 animate-pulse rounded-lg bg-slate-100 dark:bg-slate-700/50';

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Settings › Security › Domain entries (DDNS) (#320): the tunables,
 * every domain in use with its state, the apply state and "Apply now".
 */
export default function DnsEntrySettings() {
  const { t } = useTranslation(['dnsEntries', 'navigation', 'common']);
  const queryClient = useQueryClient();
  const { can, isLoading: permissionsLoading } = usePermissions();
  // Both GETs need settings:read. Ask only once the role is known: the
  // permission hook allows everything while /auth/me loads, and a role
  // without settings that opens this URL directly must fire no request.
  const canRead = !permissionsLoading && can('settings:read');
  const canWrite = can('settings:write');
  // "Allow again" goes through an access list's confirm route.
  const canConfirm = can('access:write');
  const isVisible = usePageVisibility();
  const [notice, setNotice] = useState<DnsNotice | null>(null);
  const [confirming, setConfirming] = useState<{ hostname: string; listId: string } | null>(null);

  const settingsQuery = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
    enabled: canRead,
  });
  const overviewQuery = useQuery({
    queryKey: ['dns-entries'],
    queryFn: getDNSEntries,
    enabled: canRead,
    // Poll only on a visible tab while something waits (BackupManager pattern).
    refetchInterval: (query) => (isVisible && dnsOverviewNeedsPolling(query.state.data) ? 10_000 : false),
  });

  // A success fades out; a problem stays until the next message or Close.
  useEffect(() => {
    if (notice?.tone !== 'success') return undefined;
    const timer = setTimeout(() => setNotice(null), 5000);
    return () => clearTimeout(timer);
  }, [notice]);

  if (!permissionsLoading && !can('settings:read')) {
    return (
      <div className="rounded-lg border border-slate-200 bg-white p-8 text-center dark:border-slate-700 dark:bg-slate-800">
        <p className="text-sm font-medium text-slate-700 dark:text-slate-200">{t('navigation:noPermission.title')}</p>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('navigation:noPermission.hint')}</p>
      </div>
    );
  }

  const stored = settingsQuery.data?.dns_entry_settings;
  const overview = overviewQuery.data;
  const entries = overview?.entries ?? [];
  const reviewCount = entries.filter((entry) => entry.status === 'needs_review').length;
  const confirmEntry = confirming ? entries.find((entry) => entry.hostname === confirming.hostname) : undefined;

  const finishConfirm = (hostname: string, refusal?: ApiError) => {
    setConfirming(null);
    queryClient.invalidateQueries({ queryKey: ['dns-entries'] });
    queryClient.invalidateQueries({ queryKey: ['access-lists'] });
    queryClient.invalidateQueries({ queryKey: ['accessLists'] });
    setNotice(
      refusal
        ? { tone: 'warning', text: t('overview.confirmReloadRejected', { name: hostname }), details: refusal.details }
        : { tone: 'success', text: t('overview.confirmed', { name: hostname }) },
    );
  };

  return (
    <div className="space-y-6" data-testid="dns-entry-settings">
      <div className="rounded-xl border border-blue-200 bg-blue-50 p-4 dark:border-blue-800/60 dark:bg-blue-900/20">
        <h2 className="text-base font-semibold text-blue-900 dark:text-blue-100">{t('settings.title')}</h2>
        <p className="mt-1 text-sm text-blue-900 dark:text-blue-100">{t('settings.description')}</p>
        <p className="mt-2 text-xs text-blue-800 dark:text-blue-200">{t('guide.common')}</p>
        <p className="mt-1 text-xs text-blue-800 dark:text-blue-200">{t('guide.ipv6')}</p>
      </div>

      {notice && (
        <div
          role="status"
          data-testid="dns-entry-notice"
          className={`flex items-start justify-between gap-3 rounded-lg border px-4 py-3 text-sm ${NOTICE_STYLES[notice.tone]}`}
        >
          <div className="min-w-0">
            <p>{notice.text}</p>
            {notice.details && (
              <p className="mt-1 whitespace-pre-wrap break-all font-mono text-xs">{notice.details}</p>
            )}
          </div>
          <button
            type="button"
            onClick={() => setNotice(null)}
            aria-label={t('common:buttons.close')}
            className="shrink-0 rounded p-1 hover:bg-black/5 dark:hover:bg-white/10"
          >
            <XIcon className="h-4 w-4" />
          </button>
        </div>
      )}

      {overview && !overview.settings.enabled && (
        <div
          role="alert"
          className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-medium text-amber-800 dark:border-amber-800/60 dark:bg-amber-900/20 dark:text-amber-200"
        >
          {overview.env_disabled ? t('settings.envDisabledBanner') : t('settings.disabledBanner')}
        </div>
      )}

      {stored ? (
        <DnsEntryTunablesCard
          stored={stored}
          envDisabled={overview?.env_disabled}
          envIntervalSeconds={overview?.env_interval_seconds}
          totalNames={overview?.total_names}
          canWrite={canWrite}
          onMessage={setNotice}
        />
      ) : (
        <div className={card}>
          {settingsQuery.error ? (
            <p className="text-sm text-red-700 dark:text-red-300">
              {t('settings.loadError', { error: errorText(settingsQuery.error) })}
            </p>
          ) : (
            <div className={skeleton} />
          )}
        </div>
      )}

      <section className={card}>
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t('overview.title')}</h3>
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('overview.description')}</p>
          </div>
          {overview && (
            <div className="flex flex-wrap items-center gap-2 text-xs">
              {reviewCount > 0 && (
                <span className="rounded-md bg-orange-50 px-2 py-0.5 font-semibold text-orange-700 dark:bg-orange-900/20 dark:text-orange-300">
                  {t('overview.needsReview', { count: reviewCount })}
                </span>
              )}
              <span className="text-slate-500 dark:text-slate-400">
                {t('overview.total', { count: overview.total_names, max: overview.settings.max_total })}
              </span>
            </div>
          )}
        </div>
        {!overview ? (
          overviewQuery.error ? (
            <p className="text-sm text-red-700 dark:text-red-300">
              {t('overview.loadError', { error: errorText(overviewQuery.error) })}
            </p>
          ) : (
            <div className={skeleton} />
          )
        ) : (
          <div className="space-y-4">
            {overviewQuery.error && (
              <p className="text-sm text-red-700 dark:text-red-300">
                {t('overview.loadError', { error: errorText(overviewQuery.error) })}
              </p>
            )}
            <DnsEntryApplyBar apply={overview.apply} canWrite={canWrite} onMessage={setNotice} />
            {entries.length === 0 ? (
              <p className="text-sm text-slate-500 dark:text-slate-400">{t('overview.empty')}</p>
            ) : (
              <DnsEntryOverviewTable
                entries={entries}
                canConfirm={canConfirm}
                onConfirm={(hostname, listId) => setConfirming({ hostname, listId })}
              />
            )}
          </div>
        )}
      </section>

      {confirming && confirmEntry && (
        <DnsConfirmDialog
          key={confirming.hostname}
          status={confirmEntry}
          onSubmit={(req) => confirmAccessListDNS(confirming.listId, req)}
          onRefetch={() => {
            void overviewQuery.refetch();
          }}
          onFinished={(refusal) => finishConfirm(confirming.hostname, refusal)}
          onClose={() => setConfirming(null)}
        />
      )}
    </div>
  );
}
