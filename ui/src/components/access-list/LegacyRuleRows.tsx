import { useTranslation } from 'react-i18next';
import { canMoveToDomain, errorTextKey, type AccessRuleRow, type RowError } from './accessListItems';

interface LegacyRuleRowsProps {
  /** The legacy rows, in form order. */
  rows: AccessRuleRow[];
  errors: Record<string, RowError>;
  onMove: (key: string) => void;
  onRemove: (key: string) => void;
}

/**
 * Rules an older version saved with a name in the address (#320).
 * nginx never got the allows, and a deny is enforced as "deny all" in its place.
 * They are shown read-only and saved back unchanged; only "Move to domain" (an
 * allow whose name passes the rules) turns one into a domain entry, so an
 * unrelated save never creates new trust.
 */
export function LegacyRuleRows({ rows, errors, onMove, onRemove }: LegacyRuleRowsProps) {
  const { t } = useTranslation(['accessControl', 'dnsEntries']);
  if (rows.length === 0) return null;

  return (
    <div className="rounded-lg border border-amber-200 bg-amber-50/60 p-4 dark:border-amber-800/60 dark:bg-amber-900/10">
      <h4 className="text-xs font-semibold uppercase tracking-wider text-amber-800 dark:text-amber-300">
        {t('form.legacyTitle')}
      </h4>
      <p className="mt-1 text-xs text-amber-700 dark:text-amber-300/80">{t('form.legacyHelp')}</p>
      <ul className="mt-3 space-y-2">
        {rows.map((row) => {
          const error = errors[row.key];
          const key = error ? errorTextKey(error.code) : null;
          return (
            <li key={row.key} data-testid="legacy-rule" className="text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`rounded px-1.5 py-0.5 text-xs font-medium ${
                    row.legacy === 'deny_all'
                      ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
                      : 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-300'
                  }`}
                >
                  {row.legacy === 'deny_all' ? t('form.legacyDenyAll') : t('form.legacyIgnored')}
                </span>
                <span className="break-all font-mono text-slate-700 dark:text-slate-200">
                  {row.directive} {row.address}
                </span>
                {row.description && <span className="text-slate-500 dark:text-slate-400">- {row.description}</span>}
                <span className="ml-auto flex items-center gap-1">
                  {canMoveToDomain(row) && (
                    <button
                      type="button"
                      onClick={() => onMove(row.key)}
                      className="rounded-md border border-sky-300 px-2 py-1 text-xs font-medium text-sky-700 transition-colors hover:bg-sky-50 dark:border-sky-700 dark:text-sky-300 dark:hover:bg-sky-900/30"
                    >
                      {t('form.moveToDomain')}
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => onRemove(row.key)}
                    aria-label={t('form.removeLegacy')}
                    title={t('form.removeLegacy')}
                    className="rounded-md p-1.5 text-slate-400 transition-colors hover:text-red-700 dark:hover:text-red-300"
                  >
                    <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </span>
              </div>
              {error && (
                <p className="mt-1 text-xs text-red-600 dark:text-red-400">
                  {key ? t(key, { detail: error.message ?? '' }) : error.message}
                </p>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
