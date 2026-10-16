import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ApiError, isNginxReloadRefusal } from '../../../api/client';
import type { DNSConfirmRequest, DNSEntryStatus } from '../../../types/dnsEntries';
import { ModalShell } from '../ModalShell';

type Notice = 'lookup_unavailable' | 'observation_changed' | 'not_in_review';

const NOTICE_KEYS: Record<Notice, string> = {
  lookup_unavailable: 'confirm.lookupUnavailable',
  observation_changed: 'confirm.observationChanged',
  not_in_review: 'confirm.notInReview',
};

interface DnsConfirmDialogProps {
  /** The name in review, from the caller's latest data. Mount with key={hostname}. */
  status: DNSEntryStatus;
  /** Sends the confirm request for this name; the caller knows the route. */
  onSubmit: (req: DNSConfirmRequest) => Promise<unknown>;
  /** Re-reads the caller's data so the dialog shows the server's newest observation. */
  onRefetch: () => void;
  /** Confirmed (refusal undefined), or confirmed but nginx refused the reload. */
  onFinished: (refusal?: ApiError) => void;
  onClose: () => void;
}

/** What the dialog shows of the server's answer, and sends back as expected. */
interface Observation {
  addresses: string[];
  canonical: string | null;
}

function observationOf(status: DNSEntryStatus): Observation {
  return { addresses: status.observed_addresses ?? [], canonical: status.observed_canonical_name ?? null };
}

/** An answer the operator can approve: one with an address. Anything else is not held. */
function heldOf(status: DNSEntryStatus): Observation | null {
  const observation = observationOf(status);
  return observation.addresses.length > 0 ? observation : null;
}

/**
 * "Allow again" for a domain in review (#320). It shows what the
 * server resolved and sends exactly that as the expected values; the server
 * resolves again and publishes only its own answer. A changed answer or a failed
 * lookup is a 409: the dialog re-reads the data and stays open.
 *
 * The answer shown is held from the moment the dialog opens: a background
 * refetch (the poll, a tab shown again) never swaps what the operator is about
 * to approve. Only after the server refused a confirm does the dialog show the
 * screen's newest answer, under the notice that says so, and hold the next one
 * that arrives (the re-read it asked for). A click holds what it sends.
 */
export function DnsConfirmDialog({ status, onSubmit, onRefetch, onFinished, onClose }: DnsConfirmDialogProps) {
  const { t } = useTranslation(['dnsEntries', 'common']);
  const [submitting, setSubmitting] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [error, setError] = useState<{ message: string; details?: string } | null>(null);
  // null: nothing held, show the caller's latest data (nothing approvable yet,
  // or the server refused what was held).
  const [held, setHeld] = useState<Observation | null>(() => heldOf(status));
  const [seen, setSeen] = useState(status);
  if (status !== seen) {
    setSeen(status);
    if (held === null) setHeld(heldOf(status));
  }

  const shown = held ?? observationOf(status);
  const observed = shown.addresses;
  const inReview = status.status === 'needs_review';
  const canSubmit = inReview && observed.length > 0 && !submitting;

  const submit = async () => {
    setHeld(shown);
    setSubmitting(true);
    setNotice(null);
    setError(null);
    const req: DNSConfirmRequest = { hostname: status.hostname, expected_addresses: observed };
    if (shown.canonical) req.expected_canonical_name = shown.canonical;
    try {
      await onSubmit(req);
      onFinished();
    } catch (err) {
      if (isNginxReloadRefusal(err)) {
        onFinished(err);
      } else if (
        err instanceof ApiError &&
        (err.code === 'lookup_unavailable' || err.code === 'observation_changed' || err.code === 'not_in_review')
      ) {
        setNotice(err.code);
        setHeld(null);
        onRefetch();
      } else {
        setError({
          message: err instanceof Error ? err.message : t('confirm.failed'),
          details: err instanceof ApiError ? err.details : undefined,
        });
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <ModalShell isOpen onClose={onClose} closeOnBackdrop={false} panelClassName="max-w-md" labelledById="dns-confirm-title">
      <div className="p-6">
        <h3 id="dns-confirm-title" className="break-all text-lg font-semibold text-slate-900 dark:text-white">
          {t('confirm.title', { name: status.hostname })}
        </h3>
        {status.review_reason && (
          <p className="mt-2 text-sm text-orange-700 dark:text-orange-300">
            {t(`review.${status.review_reason}`, {
              from: status.canonical_name || '-',
              to: shown.canonical || '-',
            })}
          </p>
        )}
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">{t('guide.review')}</p>

        <p className="mt-4 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
          {t('confirm.observed')}
        </p>
        {observed.length > 0 ? (
          <ul className="mt-1 max-h-32 overflow-y-auto rounded-lg bg-slate-50 px-3 py-2 font-mono text-xs text-slate-700 dark:bg-slate-700/50 dark:text-slate-200">
            {observed.map((address) => (
              <li key={address} className="break-all">
                {address}
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{t('confirm.noObserved')}</p>
        )}
        {shown.canonical && (
          <p className="mt-2 break-all text-xs text-slate-600 dark:text-slate-300">
            {t('confirm.canonical', { name: shown.canonical })}
          </p>
        )}
        {status.canonical_name && status.canonical_name !== shown.canonical && (
          <p className="mt-1 break-all text-xs text-slate-500 dark:text-slate-400">
            {t('confirm.pinned', { name: status.canonical_name })}
          </p>
        )}
        <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">{t('confirm.serverDecides')}</p>

        {(notice || !inReview) && (
          <p className="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-900/20 dark:text-amber-200">
            {t(NOTICE_KEYS[notice ?? 'not_in_review'])}
          </p>
        )}
        {error && (
          <div className="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/30 dark:text-red-300">
            <p>{error.message}</p>
            {error.details && <p className="mt-1 break-all font-mono text-xs">{error.details}</p>}
          </div>
        )}

        <div className="mt-6 flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700"
          >
            {t('common:buttons.cancel')}
          </button>
          <button
            type="button"
            onClick={submit}
            disabled={!canSubmit}
            className="rounded-lg bg-orange-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-orange-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-orange-500 dark:hover:bg-orange-600"
          >
            {submitting ? t('confirm.submitting') : t('confirm.submit')}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}
