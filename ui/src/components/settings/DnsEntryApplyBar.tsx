import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { isNginxReloadRefusal } from '../../api/client';
import { applyDNSEntriesNow } from '../../api/dnsEntries';
import type { DNSApplyState } from '../../types/dnsEntries';
import { HelpTip } from '../common/HelpTip';
import { formatDnsTime } from '../common/dns/dnsName';
import { applyOutcomeTone, DNS_APPLY_OUTCOMES, type DnsNotice } from './dnsEntryOverview';

interface DnsEntryApplyBarProps {
  apply: DNSApplyState;
  canWrite: boolean;
  onMessage: (notice: DnsNotice) => void;
}

/**
 * The apply line of the overview: the last DNS apply, what
 * waits for nginx, why the last apply failed, and "Apply now". The blocking
 * file and nginx's message arrive only for callers with proxy:read.
 */
export default function DnsEntryApplyBar({ apply, canWrite, onMessage }: DnsEntryApplyBarProps) {
  const { t, i18n } = useTranslation('dnsEntries');
  const queryClient = useQueryClient();
  const time = (iso: string | null) => formatDnsTime(iso, i18n.language);

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['dns-entries'] });
    // The access list screens show the same per-name state.
    queryClient.invalidateQueries({ queryKey: ['access-lists'] });
    queryClient.invalidateQueries({ queryKey: ['accessLists'] });
  };

  const applyNow = useMutation({
    mutationFn: () => applyDNSEntriesNow(),
    onSuccess: (res) => {
      refresh();
      const details = [res.blocking_file, res.detail].filter((s): s is string => !!s).join('\n');
      onMessage({
        tone: applyOutcomeTone(res.outcome),
        text: DNS_APPLY_OUTCOMES.includes(res.outcome)
          ? t(`overview.applyResult.${res.outcome}`)
          : t('overview.applyResult.other', { outcome: res.outcome }),
        details: details || undefined,
      });
    },
    onError: (err: Error) => {
      refresh();
      if (isNginxReloadRefusal(err)) {
        // The files stay as written; the running nginx keeps its configuration.
        onMessage({ tone: 'error', text: t('overview.applyResult.rejected'), details: err.details });
        return;
      }
      onMessage({ tone: 'error', text: t('overview.applyResult.error', { error: err.message }) });
    },
  });

  const blockedReason = apply.blocked_outcome
    ? t(`blocked.${apply.blocked_outcome}`, { defaultValue: apply.blocked_outcome })
    : '';

  return (
    <div className="flex flex-col gap-3 border-b border-slate-200 pb-4 dark:border-slate-700 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0 space-y-1 text-sm">
        <p className="text-slate-700 dark:text-slate-200">
          {apply.last_dns_reload_at
            ? t('overview.apply.lastReload', { time: time(apply.last_dns_reload_at) })
            : t('overview.apply.noReload')}
        </p>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <span
            className={apply.pending_additions > 0 ? 'text-amber-700 dark:text-amber-300' : 'text-slate-500 dark:text-slate-400'}
          >
            {t('overview.apply.pendingAdditions', { count: apply.pending_additions })}
          </span>
          <div className="inline-flex items-center">
            <span
              className={
                apply.revoke_pending > 0 ? 'font-semibold text-red-700 dark:text-red-300' : 'text-slate-500 dark:text-slate-400'
              }
            >
              {t('overview.apply.revokePending', { count: apply.revoke_pending })}
            </span>
            <HelpTip contentKey="overview.apply.revokePendingHelp" ns="dnsEntries" />
          </div>
        </div>
        {apply.blocked_outcome && (
          <div className="mt-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-red-800 dark:border-red-800/60 dark:bg-red-900/20 dark:text-red-200">
            <p className="font-medium">{t('overview.apply.blockedTitle', { reason: blockedReason })}</p>
            {apply.blocking_file && (
              <p className="mt-1 break-all font-mono text-xs">
                {t('overview.apply.blockingFile', { file: apply.blocking_file })}
              </p>
            )}
            {apply.blocked_detail && <p className="mt-1 break-all font-mono text-xs">{apply.blocked_detail}</p>}
            {apply.next_retry_at && (
              <p className="mt-1 text-xs">{t('overview.apply.nextRetry', { time: time(apply.next_retry_at) })}</p>
            )}
          </div>
        )}
      </div>
      {canWrite && (
        <div className="flex shrink-0 items-center">
          <button
            type="button"
            data-testid="dns-entries-apply"
            onClick={() => applyNow.mutate()}
            disabled={applyNow.isPending}
            className="rounded-lg bg-blue-600 px-4 py-2 text-[13px] font-semibold text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
          >
            {applyNow.isPending ? t('overview.apply.applying') : t('overview.apply.button')}
          </button>
          <HelpTip contentKey="overview.apply.buttonHelp" ns="dnsEntries" />
        </div>
      )}
    </div>
  );
}
