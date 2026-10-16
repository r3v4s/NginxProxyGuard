import { useTranslation } from 'react-i18next';
import type { DNSEntryStatus } from '../../../types/dnsEntries';

interface Tone {
  pill: string;
  dot: string;
}

const GREEN: Tone = { pill: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300', dot: 'bg-emerald-500' };
const GREY: Tone = { pill: 'bg-slate-100 text-slate-600 dark:bg-slate-700/50 dark:text-slate-300', dot: 'bg-slate-400' };
const AMBER: Tone = { pill: 'bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300', dot: 'bg-amber-500' };
const RED: Tone = { pill: 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300', dot: 'bg-red-500' };
const ORANGE: Tone = { pill: 'bg-orange-50 text-orange-700 dark:bg-orange-900/20 dark:text-orange-300', dot: 'bg-orange-500' };

const TONES: Record<string, Tone> = {
  ok: GREEN,
  pending: GREY,
  stale: AMBER,
  expired: RED,
  rejected: RED,
  not_found: RED,
  needs_review: ORANGE,
};

function Pill({ tone, label, title, status }: { tone: Tone; label: string; title?: string; status?: string }) {
  return (
    <span
      title={title}
      data-status={status}
      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ${tone.pill}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${tone.dot}`} />
      {label}
    </span>
  );
}

/**
 * The state of one domain entry, plus a grey pill when the feature is off and a
 * red one while a removed address is still allowed by the running nginx.
 */
export function DnsStatusBadge({ status }: { status: DNSEntryStatus | null }) {
  const { t } = useTranslation('dnsEntries');
  if (!status) {
    return <Pill tone={GREY} label={t('status.unknown')} status="unknown" />;
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <Pill
        tone={TONES[status.status] ?? GREY}
        label={t(`status.${status.status}`, { defaultValue: status.status })}
        status={status.status}
      />
      {status.disabled && <Pill tone={GREY} label={t('status.disabled')} title={t('status.disabledHelp')} />}
      {status.revoke_pending && <Pill tone={RED} label={t('status.revokePending')} title={t('status.revokePendingHelp')} />}
    </span>
  );
}
