import { useTranslation } from 'react-i18next';
import type { DNSHostRef } from '../../../types/dnsEntries';

interface DnsLoginBypassWarningProps {
  /** Hosts with a login that use the list; null when the caller may not read hosts. */
  hosts?: DNSHostRef[] | null;
  /** How many such hosts there are. Nothing renders at 0 unless forThisHost. */
  count?: number;
  /** In the host form the host being edited is the one at risk, so no host list is shown. */
  forThisHost?: boolean;
}

const VISIBLE_HOSTS = 5;

/**
 * "These domains skip the login": a satisfy-any access list with domain entries
 * lets a client at a domain's address past a host's ForwardAuth or auth_basic
 * (#320). Shown in the list editor, the host form and the overview.
 */
export function DnsLoginBypassWarning({ hosts, count = 0, forThisHost = false }: DnsLoginBypassWarningProps) {
  const { t } = useTranslation('dnsEntries');
  if (!forThisHost && count <= 0) return null;
  const listed = hosts ?? [];
  const shown = listed.slice(0, VISIBLE_HOSTS);
  return (
    <div
      role="note"
      className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2.5 text-amber-800 dark:border-amber-800/60 dark:bg-amber-900/20 dark:text-amber-200"
    >
      <p className="text-sm font-medium">{t('loginBypass.title')}</p>
      <p className="mt-1 text-xs">{forThisHost ? t('loginBypass.host') : t('loginBypass.list')}</p>
      {!forThisHost &&
        (shown.length > 0 ? (
          <ul className="mt-1.5 flex flex-wrap gap-1.5">
            {shown.map((host) => (
              <li key={host.id} className="break-all rounded bg-amber-100 px-1.5 py-0.5 font-mono text-xs dark:bg-amber-800/40">
                {host.domain}
              </li>
            ))}
            {listed.length > shown.length && (
              <li className="text-xs">{t('loginBypass.more', { count: listed.length - shown.length })}</li>
            )}
          </ul>
        ) : (
          <p className="mt-1 text-xs">{t('loginBypass.count', { count })}</p>
        ))}
    </div>
  );
}
