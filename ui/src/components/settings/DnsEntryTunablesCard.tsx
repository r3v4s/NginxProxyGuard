import { useState, type FormEvent } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { updateSystemSettings } from '../../api/settings';
import type { DNSEntrySettings } from '../../types/dnsEntries';
import { HelpTip } from '../common/HelpTip';
import {
  DNS_ENTRY_FIELD_GROUPS,
  DNS_ENTRY_LIMITS,
  dnsEntrySettingsPatch,
  invalidDnsEntryFields,
  type DnsEntryNumberField,
  type DnsEntrySettingsDraft,
} from './dnsEntryLimits';
import type { DnsNotice } from './dnsEntryOverview';

interface DnsEntryTunablesCardProps {
  /** The stored settings from GET /system-settings, never the ones in effect. */
  stored: DNSEntrySettings;
  /** NPG_DNS_ENTRIES_DISABLED is set (from the overview). */
  envDisabled?: boolean;
  /** NPG_DNS_ENTRIES_INTERVAL in seconds, null when it is unset (from the overview). */
  envIntervalSeconds?: number | null;
  /** Distinct domains in use, shown next to max_total. */
  totalNames?: number;
  canWrite: boolean;
  onMessage: (notice: DnsNotice) => void;
}

const inputClass =
  'w-full sm:w-40 rounded-lg border px-3 py-2 text-sm bg-white text-slate-900 focus:border-blue-500 focus:ring-2 focus:ring-blue-500 disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-500 dark:bg-slate-700 dark:text-white dark:disabled:bg-slate-800 dark:disabled:text-slate-400';

/**
 * The nine domain entry tunables. It shows and edits the stored
 * value; a save sends only the keys that changed and the server merges them
 * over what is stored. An environment switch locks the field it overrides.
 * Every input is named after its JSON key and sits in one form whose submit
 * button saves: the E2E spec finds them that way.
 */
export default function DnsEntryTunablesCard({
  stored,
  envDisabled = false,
  envIntervalSeconds = null,
  totalNames,
  canWrite,
  onMessage,
}: DnsEntryTunablesCardProps) {
  const { t } = useTranslation(['dnsEntries', 'common']);
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<DnsEntrySettingsDraft>({});

  const values: DNSEntrySettings = { ...stored, ...draft };
  const invalid = invalidDnsEntryFields(draft);
  const patch = dnsEntrySettingsPatch(stored, draft);
  const modified = Object.keys(patch).length > 0;
  const turningOff = stored.enabled && !values.enabled;
  const turningOn = !stored.enabled && values.enabled;

  const save = useMutation({
    mutationFn: (changes: DnsEntrySettingsDraft) => updateSystemSettings({ dns_entry_settings: changes }),
    onSuccess: () => {
      // Two query keys hold GET /system-settings, and the overview carries the
      // settings in effect.
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] });
      queryClient.invalidateQueries({ queryKey: ['system-settings'] });
      queryClient.invalidateQueries({ queryKey: ['dns-entries'] });
      setDraft({});
      onMessage({ tone: 'success', text: t('settings.saved') });
    },
    onError: (error: Error) => {
      // The server's sentence names the key and its range.
      onMessage({ tone: 'error', text: t('settings.saveFailed', { error: error.message }) });
    },
  });

  const canSave = canWrite && modified && invalid.length === 0 && !save.isPending;

  // Enter in a field submits too; the same checks as the button apply.
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (canSave) save.mutate(patch);
  };

  const setNumber = (field: DnsEntryNumberField, raw: string) =>
    setDraft((prev) => ({ ...prev, [field]: raw === '' ? Number.NaN : Number(raw) }));

  const numberField = (field: DnsEntryNumberField) => {
    const { min, max, def } = DNS_ENTRY_LIMITS[field];
    const id = `dns-entry-${field}`;
    const value = values[field];
    const isInvalid = invalid.includes(field);
    const envLocked = field === 'check_interval_seconds' && envIntervalSeconds !== null;
    const showUsage = field === 'max_total' && totalNames !== undefined;
    const overLimit = showUsage && totalNames > value;
    return (
      <div key={field}>
        <div className="mb-1 flex items-center">
          <label htmlFor={id} className="text-sm font-medium text-slate-700 dark:text-slate-300">
            {t(`settings.fields.${field}.label`)}
          </label>
          <HelpTip contentKey={`settings.fields.${field}.help`} ns="dnsEntries" />
        </div>
        <input
          id={id}
          name={field}
          type="number"
          inputMode="numeric"
          min={min}
          max={max}
          step={1}
          value={Number.isFinite(value) ? value : ''}
          disabled={!canWrite || envLocked}
          aria-invalid={isInvalid}
          onChange={(e) => setNumber(field, e.target.value)}
          className={`${inputClass} ${isInvalid ? 'border-red-500 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'}`}
        />
        {isInvalid && (
          <p className="mt-1 text-xs text-red-600 dark:text-red-400">{t('settings.rangeHint', { min, max })}</p>
        )}
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          {t(`settings.fields.${field}.desc`)} {t('settings.defaultValue', { value: def })}
        </p>
        {envLocked && (
          <p className="mt-1 text-xs font-medium text-amber-700 dark:text-amber-300">
            {t('settings.envInterval', { seconds: envIntervalSeconds })}
          </p>
        )}
        {showUsage && (
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('settings.inUse', { count: totalNames })}</p>
        )}
        {overLimit && (
          <p className="mt-1 text-xs font-medium text-amber-700 dark:text-amber-300">{t('settings.overLimit')}</p>
        )}
      </div>
    );
  };

  return (
    <form
      onSubmit={submit}
      noValidate
      className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition-colors dark:border-slate-700 dark:bg-slate-800"
    >
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t('settings.cardTitle')}</h3>
        {canWrite && (
          <div className="flex items-center gap-2">
            {modified && (
              <button
                type="button"
                onClick={() => setDraft({})}
                disabled={save.isPending}
                className="rounded-lg px-3 py-2 text-[13px] font-semibold text-slate-600 transition-colors hover:bg-slate-100 disabled:opacity-50 dark:text-slate-300 dark:hover:bg-slate-700"
              >
                {t('common:buttons.reset')}
              </button>
            )}
            <button
              type="submit"
              data-testid="dns-entry-settings-save"
              disabled={!canSave}
              className="rounded-lg bg-blue-600 px-4 py-2 text-[13px] font-semibold text-white transition-colors hover:bg-blue-700 disabled:bg-slate-300 disabled:opacity-50 dark:disabled:bg-slate-600"
            >
              {save.isPending ? t('common:status.saving') : t('common:buttons.save')}
            </button>
          </div>
        )}
      </div>

      <div className="space-y-5">
        <div className="flex items-start gap-3">
          <input
            id="dns-entry-enabled"
            name="enabled"
            type="checkbox"
            checked={values.enabled}
            disabled={!canWrite || envDisabled}
            onChange={(e) => setDraft((prev) => ({ ...prev, enabled: e.target.checked }))}
            className="mt-1 h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500 disabled:cursor-not-allowed dark:border-slate-600 dark:bg-slate-700"
          />
          <div className="min-w-0">
            <div className="flex items-center">
              <label htmlFor="dns-entry-enabled" className="text-sm font-medium text-slate-800 dark:text-slate-100">
                {t('settings.fields.enabled.label')}
              </label>
              <HelpTip contentKey="settings.fields.enabled.help" ns="dnsEntries" />
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">{t('settings.fields.enabled.desc')}</p>
            {envDisabled && (
              <p className="mt-1 text-xs font-medium text-amber-700 dark:text-amber-300">{t('settings.envDisabled')}</p>
            )}
            {turningOff && (
              <p className="mt-1 text-xs font-medium text-amber-700 dark:text-amber-300">{t('settings.turningOff')}</p>
            )}
            {turningOn && <p className="mt-1 text-xs text-blue-700 dark:text-blue-300">{t('settings.turningOn')}</p>}
          </div>
        </div>

        {DNS_ENTRY_FIELD_GROUPS.map((group) => (
          <div key={group.key} className="border-t border-slate-200 pt-4 dark:border-slate-700">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
              {t(`settings.groups.${group.key}`)}
            </h4>
            <div className="mt-3 grid grid-cols-1 gap-4 md:grid-cols-2">
              {group.fields.map((field) => numberField(field))}
            </div>
          </div>
        ))}
      </div>
    </form>
  );
}
