import { useTranslation } from 'react-i18next';
import { movableName } from './dnsListField';

interface IgnoredEntriesProps {
  /**
   * Entries of a list's IP field that the configs leave out (the GET's
   * *_ignored), still in the field: not an address, saved by an older version.
   */
  entries: string[];
  /** Moves an entry out of the IP field into the domains, as name. */
  onMove: (entry: string, name: string) => void;
  /** Removes an entry from the IP field. */
  onRemove: (entry: string) => void;
  /** Read-only: the entries without their buttons. */
  disabled?: boolean;
}

/**
 * "Entries not applied" of an IP field (#320): what an older version saved
 * there that is not an address, such as a DDNS name, which nginx never used.
 * Each stays as it is until the operator acts: "Move to domain" (only for an
 * entry that passes the name rules) turns it into a domain, so an unrelated
 * save never starts trusting a name.
 */
export function IgnoredEntries({ entries, onMove, onRemove, disabled = false }: IgnoredEntriesProps) {
  const { t } = useTranslation('dnsEntries');
  if (entries.length === 0) return null;

  return (
    <div
      data-testid="dns-ignored-entries"
      className="rounded-lg border border-amber-200 bg-amber-50/60 p-3 dark:border-amber-800/60 dark:bg-amber-900/10"
    >
      <h5 className="text-xs font-semibold uppercase tracking-wider text-amber-800 dark:text-amber-300">
        {t('ignored.title')}
      </h5>
      <p className="mt-1 text-xs text-amber-700 dark:text-amber-300/80">{t('ignored.help')}</p>
      <ul className="mt-2 space-y-1.5">
        {entries.map((entry) => {
          const name = movableName(entry);
          return (
            <li key={entry} data-testid="dns-ignored-entry" data-entry={entry} className="flex flex-wrap items-center gap-2 text-sm">
              <span className="min-w-0 break-all font-mono text-slate-700 dark:text-slate-200">{entry}</span>
              {!disabled && (
                <span className="ml-auto flex items-center gap-1">
                  {name && (
                    <button
                      type="button"
                      onClick={() => onMove(entry, name)}
                      className="rounded-md border border-sky-300 px-2 py-1 text-xs font-medium text-sky-700 transition-colors hover:bg-sky-50 dark:border-sky-700 dark:text-sky-300 dark:hover:bg-sky-900/30"
                    >
                      {t('ignored.move')}
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => onRemove(entry)}
                    aria-label={t('ignored.remove')}
                    title={t('ignored.remove')}
                    className="rounded-md p-1.5 text-slate-400 transition-colors hover:text-red-700 dark:hover:text-red-300"
                  >
                    <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
