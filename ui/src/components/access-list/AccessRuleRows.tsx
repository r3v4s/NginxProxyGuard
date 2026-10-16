import { useTranslation } from 'react-i18next';
import { HelpTip } from '../common/HelpTip';
import { classifyEntry, normalizeDnsName } from '../common/dns/dnsName';
import { errorTextKey, type AccessRuleRow, type RowError, type RuleField } from './accessListItems';

interface AccessRuleRowsProps {
  /** The editable rows (legacy rows excluded), in form order. */
  rows: AccessRuleRow[];
  errors: Record<string, RowError>;
  onAdd: () => void;
  onChange: (key: string, field: RuleField, value: string) => void;
  onRemove: (key: string) => void;
}

const FIELD =
  'rounded-lg border px-3 py-2.5 transition-colors focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400';
const FIELD_OK = 'border-slate-300 dark:border-slate-600';
const FIELD_BAD = 'border-red-400 dark:border-red-500';

/**
 * The rule rows of the access-list form. The address cell takes an IP, a CIDR,
 * `all` or a domain; a domain row is marked and can only allow.
 *
 * E2E (test/e2e/pages/access-list.page.ts) finds rows as `.flex.gap-2` holding a
 * select with the address as the first text input, and the add button as the
 * first type=button matching /add.*rule|\+|규칙/. Keep that shape.
 */
export function AccessRuleRows({ rows, errors, onAdd, onChange, onRemove }: AccessRuleRowsProps) {
  const { t } = useTranslation(['accessControl', 'dnsEntries']);
  const hasDomain = rows.some((row) => classifyEntry(row.address).kind === 'hostname');

  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50/60 p-4 dark:border-slate-700 dark:bg-slate-800/40">
      <div className="mb-3 flex items-center justify-between">
        <h4 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
          {t('form.accessRules')}
          <HelpTip contentKey="help.accessRules" ns="accessControl" />
        </h4>
        <button
          type="button"
          onClick={onAdd}
          className="rounded text-sm text-indigo-600 transition-colors hover:text-indigo-800 focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:text-indigo-400 dark:hover:text-indigo-300"
        >
          + {t('actions.addRule')}
        </button>
      </div>

      <div className="space-y-2">
        {rows.map((row) => {
          const entry = classifyEntry(row.address);
          const isDomain = entry.kind === 'hostname';
          const locked = isDomain && row.directive === 'allow';
          const error = errors[row.key];
          const key = error ? errorTextKey(error.code) : null;
          return (
            <div key={row.key}>
              <div className="flex flex-wrap gap-2 items-start sm:flex-nowrap">
                <select
                  value={row.directive}
                  disabled={locked}
                  title={locked ? t('form.domainAllowOnly') : undefined}
                  onChange={(e) => onChange(row.key, 'directive', e.target.value)}
                  className={`${FIELD} ${FIELD_OK} shrink-0 disabled:opacity-60`}
                >
                  <option value="allow">{t('form.allow')}</option>
                  <option value="deny">{t('form.deny')}</option>
                </select>
                <input
                  type="text"
                  value={row.address}
                  onChange={(e) => onChange(row.key, 'address', e.target.value)}
                  aria-invalid={error ? true : undefined}
                  className={`${FIELD} ${error ? FIELD_BAD : FIELD_OK} min-w-[10rem] flex-1`}
                  placeholder={t('form.ipPlaceholder')}
                />
                <input
                  type="text"
                  value={row.description}
                  onChange={(e) => onChange(row.key, 'description', e.target.value)}
                  className={`${FIELD} ${FIELD_OK} min-w-0 flex-1 sm:w-40 sm:flex-none`}
                  placeholder={t('form.ruleDescription')}
                />
                {rows.length > 1 && (
                  <button
                    type="button"
                    onClick={() => onRemove(row.key)}
                    aria-label={t('actions.removeRule')}
                    title={t('actions.removeRule')}
                    className="p-2 text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300"
                  >
                    <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                )}
              </div>
              {(isDomain || error) && (
                <div className="mt-1 flex flex-wrap items-center gap-2 text-xs">
                  {isDomain && (
                    <span className="rounded bg-sky-100 px-1.5 py-0.5 font-medium text-sky-800 dark:bg-sky-900/30 dark:text-sky-300">
                      {t('form.domainBadge')}
                    </span>
                  )}
                  {isDomain && entry.ascii !== normalizeDnsName(row.address) && (
                    <span className="break-all font-mono text-slate-500 dark:text-slate-400" title={row.address}>
                      {t('form.asciiName', { name: entry.ascii })}
                    </span>
                  )}
                  {error && (
                    <span className="text-red-600 dark:text-red-400">
                      {key ? t(key, { detail: error.message ?? '' }) : error.message}
                    </span>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {hasDomain && (
        <p className="mt-3 flex items-start gap-1.5 text-xs text-slate-500 dark:text-slate-400">
          <span>
            {t('form.domainsAfterIPs')} {t('dnsEntries:guide.common')}
          </span>
          <HelpTip contentKey="guide.ipv6" ns="dnsEntries" />
        </p>
      )}
    </div>
  );
}
