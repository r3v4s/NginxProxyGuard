import { useEffect, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import type { ApiError } from '../../../api/client';
import type { DNSConfirmRequest, DNSEntryStatus } from '../../../types/dnsEntries';
import { HelpTip } from '../HelpTip';
import { XIcon } from '../listui';
import { DnsConfirmDialog } from './DnsConfirmDialog';
import { DnsEntryStatusList, type DnsEntryRow } from './DnsEntryStatusList';
import { DnsNameInput } from './DnsNameInput';
import type { DnsNamesError } from './dnsListField';

interface DnsHostnamesFieldProps {
  /** The list's domains as the screen holds them: saved, or edited and not saved yet. */
  names: string[];
  onChange: (names: string[]) => void;
  /** The state of the saved domains, from the list's GET. */
  statuses: DNSEntryStatus[] | null | undefined;
  /**
   * The list's write permission (usePermissions().can): without it the field
   * is read-only and has no "Allow again". The server decides either way.
   */
  canWrite: boolean;
  /** Sends "Allow again" for a name in review to the list's own route. */
  onConfirm: (req: DNSConfirmRequest) => Promise<unknown>;
  /** Re-reads the list: after a confirm, and when the server refused one. */
  onRefetch: () => void;
  /** What these domains do and do not get past in this list (spec §15.4). */
  note?: ReactNode;
  /** A save's refusals of a name (on its chip) or of the list. */
  errors?: readonly DnsNamesError[];
  /** Holds the input while a save is on its way, without hiding it. */
  disabled?: boolean;
}

/**
 * What a screen hands a shared list editor (PriorityAllowIPs,
 * RateLimitFields) for its domains: their state, the screen's write
 * permission, its confirm route and its last save's refusals.
 */
export type DnsListDomains = Pick<DnsHostnamesFieldProps, 'statuses' | 'canWrite' | 'onConfirm' | 'onRefetch' | 'errors'>;

/**
 * The domains of an exception list (#320): the chip input, what this list
 * lets them do, and the DNS state of the saved ones with "Allow again" for a
 * name in review. A domain has one state wherever it is used, so a confirm
 * here allows it in every list that holds it; the server checks the write
 * permission of each of them.
 *
 * E2E: the field is data-testid="dns-hostnames-field", its chips are
 * dns-name-chip and its state rows dns-entry, both with data-hostname.
 */
export function DnsHostnamesField({
  names,
  onChange,
  statuses,
  canWrite,
  onConfirm,
  onRefetch,
  note,
  errors,
  disabled = false,
}: DnsHostnamesFieldProps) {
  const { t } = useTranslation('dnsEntries');
  const [confirming, setConfirming] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<ApiError | null>(null);

  // A name that is not saved yet has no state; it shows only as a chip.
  const byName = new Map((statuses ?? []).map((s) => [s.hostname, s] as const));
  const rows: DnsEntryRow[] = names
    .filter((name) => byName.has(name))
    .map((name) => ({ hostname: name, status: byName.get(name) ?? null }));
  const confirmStatus = confirming ? (byName.get(confirming) ?? null) : null;
  // The name left the list (removed, or the list re-read without it): close
  // "Allow again" rather than leave it waiting to come back.
  if (confirming && !confirmStatus) setConfirming(null);

  // The field also sits inside modals (the host form, the URI block host
  // dialog), whose Escape handlers listen on document. While "Allow again" is
  // open, Escape closes only it: caught on window before it reaches them.
  useEffect(() => {
    if (!confirming) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.preventDefault();
      e.stopPropagation();
      setConfirming(null);
    };
    window.addEventListener('keydown', onKeyDown, true);
    return () => window.removeEventListener('keydown', onKeyDown, true);
  }, [confirming]);

  return (
    <div data-testid="dns-hostnames-field" className="space-y-2">
      <div className="flex items-center gap-2">
        <h4 className="text-sm font-medium text-slate-900 dark:text-white">{t('field.title')}</h4>
        <HelpTip contentKey="field.help" ns="dnsEntries" />
      </div>

      {note && (
        <div
          role="note"
          className="rounded-lg border border-sky-200 bg-sky-50/70 px-3 py-2 text-xs text-sky-900 dark:border-sky-800/60 dark:bg-sky-900/20 dark:text-sky-200"
        >
          {note}
        </div>
      )}

      <DnsNameInput names={names} onChange={onChange} errors={errors} disabled={disabled} readOnly={!canWrite} />
      {!canWrite && <p className="text-xs text-slate-500 dark:text-slate-400">{t('field.readOnly')}</p>}

      {rows.length > 0 && (
        <DnsEntryStatusList entries={rows} canConfirm={canWrite} onConfirm={(hostname) => setConfirming(hostname)} />
      )}

      {names.length > 0 && (
        <p className="flex items-start gap-1.5 text-xs text-slate-500 dark:text-slate-400">
          <span>{t('guide.common')}</span>
          <HelpTip contentKey="guide.ipv6" ns="dnsEntries" />
        </p>
      )}

      {refusal && (
        <div
          role="status"
          className="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:border-amber-800/60 dark:bg-amber-900/20 dark:text-amber-200"
        >
          <div className="min-w-0 flex-1">
            <p>{t('field.confirmReloadRejected')}</p>
            {refusal.details && <p className="mt-1 break-all font-mono text-xs">{refusal.details}</p>}
          </div>
          <button
            type="button"
            onClick={() => setRefusal(null)}
            aria-label={t('common:buttons.close')}
            title={t('common:buttons.close')}
            className="rounded p-1 opacity-70 hover:opacity-100"
          >
            <XIcon />
          </button>
        </div>
      )}

      {/* On document.body: a modal around the field would otherwise hold the
          dialog in its own panel (its transform makes it the fixed box). */}
      {confirming &&
        confirmStatus &&
        createPortal(
          <DnsConfirmDialog
            key={confirming}
            status={confirmStatus}
            onSubmit={onConfirm}
            onRefetch={onRefetch}
            onFinished={(err) => {
              setConfirming(null);
              setRefusal(err ?? null);
              onRefetch();
            }}
            onClose={() => setConfirming(null)}
          />,
          document.body,
        )}
    </div>
  );
}
