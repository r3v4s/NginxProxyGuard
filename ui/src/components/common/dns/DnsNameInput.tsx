import { useState, type KeyboardEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { isIPOrCIDR } from '../../proxy-host/tabs/security/priorityAllowEntries';
import { XIcon } from '../listui';
import { normalizeDnsName, toAsciiName } from './dnsName';
import { dnsErrorTextKey, type DnsNamesError } from './dnsListField';

interface DnsNameInputProps {
  /** The names as they are sent and stored: lower case, xn-- for a non-ASCII name. */
  names: string[];
  onChange: (names: string[]) => void;
  /**
   * A save's refusals. One with a name marks that chip (and goes away with
   * it); one without is about the list, such as the domain limit.
   */
  errors?: readonly DnsNamesError[];
  /** Holds adding and removing (a save on its way); the text box keeps its focus. */
  disabled?: boolean;
  /** Without the list's write permission: the chips only. */
  readOnly?: boolean;
}

const CHIP = 'inline-flex max-w-full items-center gap-1 rounded-md border px-2 py-0.5 text-xs';
const CHIP_OK = 'border-sky-200 bg-sky-50 text-sky-800 dark:border-sky-800/60 dark:bg-sky-900/20 dark:text-sky-200';
const CHIP_BAD = 'border-red-300 bg-red-50 text-red-800 dark:border-red-700 dark:bg-red-900/30 dark:text-red-200';
const FIELD =
  'min-w-0 flex-1 rounded-lg border px-3 py-2 text-sm transition-colors focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400';

/**
 * The chip input of a list's domains (#320, spec §15.1).
 *
 * What is typed is checked as typed first (toAsciiName): the URL parser that
 * makes the xn-- form drops a user part, a path or a port without a word, so
 * "ü@evil.example" would quietly become "evil.example". An IP address is sent
 * back to the IP field. A chip shows the name that is sent and trusted, with
 * what was typed as its tooltip. The server checks the same rules; a name it
 * refuses comes back through errors and marks its chip.
 *
 * Enter adds the name and never submits the form around the input.
 */
export function DnsNameInput({ names, onChange, errors = [], disabled = false, readOnly = false }: DnsNameInputProps) {
  const { t } = useTranslation('dnsEntries');
  const [draft, setDraft] = useState('');
  const [inputError, setInputError] = useState<string | null>(null);
  // What was typed for a name added here, shown as its chip's tooltip.
  const [typed, setTyped] = useState<Record<string, string>>({});

  const errorText = (e: DnsNamesError) => {
    const key = dnsErrorTextKey(e.code);
    return key ? t(key, { detail: e.message ?? '' }) : (e.message ?? '');
  };
  const chipErrors = new Map<string, DnsNamesError>();
  for (const e of errors) {
    if (e.name && names.includes(e.name) && !chipErrors.has(e.name)) chipErrors.set(e.name, e);
  }
  const listErrors = errors.filter((e) => !e.name);

  const add = () => {
    const raw = draft.trim();
    if (raw === '' || disabled) return;
    if (isIPOrCIDR(raw)) {
      setInputError(t('input.ipInNameField'));
      return;
    }
    const result = toAsciiName(raw);
    if ('code' in result) {
      setInputError(t(`nameErrors.${result.code}`));
      return;
    }
    if (names.includes(result.ascii)) {
      setInputError(t('input.duplicate'));
      return;
    }
    if (raw !== result.ascii) setTyped((prev) => ({ ...prev, [result.ascii]: raw }));
    onChange([...names, result.ascii]);
    setDraft('');
    setInputError(null);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      add();
    }
  };

  // A non-ASCII name is sent in its xn-- form: say so before it is added.
  const preview = draft.trim() === '' ? null : toAsciiName(draft);
  const savedAs = preview && 'ascii' in preview && preview.ascii !== normalizeDnsName(draft) ? preview.ascii : null;

  return (
    <div data-testid="dns-name-input" className="space-y-2">
      {names.length > 0 ? (
        <ul className="flex flex-wrap gap-1.5">
          {names.map((name) => {
            const raw = typed[name];
            return (
              <li
                key={name}
                data-testid="dns-name-chip"
                data-hostname={name}
                title={raw ? t('input.typed', { raw }) : name}
                className={`${CHIP} ${chipErrors.has(name) ? CHIP_BAD : CHIP_OK}`}
              >
                <span className="break-all font-mono">{name}</span>
                {!readOnly && (
                  <button
                    type="button"
                    disabled={disabled}
                    onClick={() => onChange(names.filter((n) => n !== name))}
                    aria-label={t('input.remove', { name })}
                    title={t('input.remove', { name })}
                    className="rounded p-0.5 opacity-70 transition-opacity hover:opacity-100 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <XIcon />
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      ) : (
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('input.empty')}</p>
      )}

      {[...chipErrors.entries()].map(([name, e]) => (
        <p key={name} role="alert" className="break-all text-xs text-red-600 dark:text-red-400">
          <span className="font-mono">{name}</span>: {errorText(e)}
        </p>
      ))}
      {listErrors.map((e, i) => (
        <p key={i} role="alert" className="break-all text-xs text-red-600 dark:text-red-400">
          {errorText(e)}
        </p>
      ))}

      {!readOnly && (
        <div>
          <div className="flex gap-2">
            <input
              type="text"
              value={draft}
              onChange={(e) => {
                setDraft(e.target.value);
                setInputError(null);
              }}
              onKeyDown={onKeyDown}
              placeholder={t('input.placeholder')}
              aria-label={t('field.title')}
              aria-invalid={inputError ? true : undefined}
              autoComplete="off"
              spellCheck={false}
              className={`${FIELD} ${inputError ? 'border-red-400 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'}`}
            />
            <button
              type="button"
              onClick={add}
              disabled={disabled || draft.trim() === ''}
              className="shrink-0 rounded-lg bg-sky-600 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-sky-700 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-sky-500 dark:hover:bg-sky-600"
            >
              {t('input.add')}
            </button>
          </div>
          {inputError ? (
            <p role="alert" className="mt-1 text-xs text-red-600 dark:text-red-400">
              {inputError}
            </p>
          ) : (
            savedAs && (
              <p className="mt-1 break-all font-mono text-xs text-slate-500 dark:text-slate-400">
                {t('input.savedAs', { name: savedAs })}
              </p>
            )
          )}
        </div>
      )}
    </div>
  );
}
