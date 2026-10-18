import { useState, useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { confirmGlobalRateLimitDNS, getGlobalRateLimit, updateGlobalRateLimit } from '../api/global-rate-limit'
import type { GlobalRateLimit, UpdateGlobalRateLimitRequest } from '../types/security'
import { usePermissions } from '../hooks/usePermissions'
import { RateLimitFields } from './proxy-host/tabs/security/RateLimitFields'
import { dnsNeedsPolling } from './common/dns/dnsName'
import { DNS_POLL_MS, dnsConfigKey, dnsNamesErrorsOf, type DnsNamesError } from './common/dns/dnsListField'

type Draft = UpdateGlobalRateLimitRequest & { enabled: boolean }

const EMPTY: Draft = {
  enabled: false,
  requests_per_second: 50,
  burst_size: 100,
  zone_size: '10m',
  limit_by: 'ip',
  limit_response: 429,
  whitelist_ips: '',
}

function hydrate(g: GlobalRateLimit): Draft {
  return {
    enabled: g.enabled,
    requests_per_second: g.requests_per_second,
    burst_size: g.burst_size,
    zone_size: g.zone_size,
    limit_by: g.limit_by,
    limit_response: g.limit_response,
    whitelist_ips: g.whitelist_ips || '',
    whitelist_hostnames: g.whitelist_hostnames ?? [],
  }
}

export function GlobalRateLimitManager() {
  const { t } = useTranslation('waf')
  const queryClient = useQueryClient()
  // The global default's PUT and its confirm route need waf:write (#320).
  const { can } = usePermissions()

  const [data, setData] = useState<Draft>(EMPTY)
  const [dirty, setDirty] = useState(false)
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const [nameErrors, setNameErrors] = useState<DnsNamesError[]>([])

  const { data: global, isLoading } = useQuery({
    queryKey: ['global-rate-limit'],
    queryFn: getGlobalRateLimit,
    // Faster only while an exception domain waits for its answer or for nginx.
    refetchInterval: (query) =>
      dnsNeedsPolling(query.state.data?.whitelist_hostname_status ?? []) ? DNS_POLL_MS : 60000,
  })

  // Copy the record into the draft when it loads and when the default itself
  // changes; a refetch that only moves the domains' state leaves an unsaved
  // edit alone (#320).
  const hydratedKey = useRef<string | null>(null)
  useEffect(() => {
    if (!global) return
    const key = dnsConfigKey(global)
    if (key === hydratedKey.current) return
    hydratedKey.current = key
    setData(hydrate(global))
    setDirty(false)
  }, [global])

  const patch = (p: Partial<Draft>) => {
    setData((prev) => ({ ...prev, ...p }))
    setDirty(true)
  }

  const mutation = useMutation({
    mutationFn: (draft: Draft) => updateGlobalRateLimit(draft),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['global-rate-limit'] })
      setDirty(false)
      setNameErrors([])
      setSaveMessage({ type: 'success', message: t('globalRateLimit.saveSuccess') })
      setTimeout(() => setSaveMessage(null), 5000)
    },
    onError: (err, draft) => {
      // Keep the translated headline; append the server's reason (which names
      // the rejected whitelist entry) so a 400 is actionable, not mute (#263).
      // A refused domain is also marked on its chip (#320).
      setNameErrors(dnsNamesErrorsOf(err, 'whitelist_hostnames', draft.whitelist_hostnames))
      const detail = err instanceof Error && err.message ? `: ${err.message}` : ''
      setSaveMessage({ type: 'error', message: t('globalRateLimit.saveFailed') + detail })
      setTimeout(() => setSaveMessage(null), 8000)
    },
  })

  const handleDiscard = () => {
    setData(global ? hydrate(global) : EMPTY)
    setDirty(false)
    setNameErrors([])
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-32">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
          {t('globalRateLimit.title')}
        </h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
          {t('globalRateLimit.subtitle')}
        </p>
      </div>

      {/* Save Message */}
      {saveMessage && (
        <div className={`p-4 rounded-lg flex items-center gap-3 ${
          saveMessage.type === 'success'
            ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 text-green-800 dark:text-green-300'
            : 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-800 dark:text-red-300'
        }`}>
          <span>{saveMessage.message}</span>
        </div>
      )}

      {/* Pending Changes Banner */}
      {dirty && (
        <div className="p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg flex items-center justify-between">
          <div className="flex items-center gap-3 text-amber-800 dark:text-amber-300">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <span className="font-medium">{t('globalRateLimit.unsavedChanges')}</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleDiscard}
              className="px-3 py-1.5 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded transition-colors"
            >
              {t('common:buttons.discard')}
            </button>
            <button
              onClick={() => mutation.mutate(data)}
              disabled={mutation.isPending}
              className="px-4 py-1.5 text-sm bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded font-medium transition-colors flex items-center gap-2"
            >
              {mutation.isPending && (
                <svg className="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" strokeDasharray="50 20" />
                </svg>
              )}
              {t('common:buttons.save')}
            </button>
          </div>
        </div>
      )}

      {/* Enable Toggle Card */}
      <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
              {t('globalRateLimit.enableTitle')}
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
              {t('globalRateLimit.enableDescription')}
            </p>
          </div>
          <button
            onClick={() => patch({ enabled: !data.enabled })}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              data.enabled ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'
            }`}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${
              data.enabled ? 'translate-x-6' : 'translate-x-1'
            }`} />
          </button>
        </div>

        {data.enabled && (
          <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
            <RateLimitFields
              values={{
                requests_per_second: data.requests_per_second ?? 50,
                burst_size: data.burst_size ?? 100,
                limit_by: data.limit_by ?? 'ip',
                limit_response: data.limit_response ?? 429,
                whitelist_ips: data.whitelist_ips ?? '',
                whitelist_hostnames: data.whitelist_hostnames ?? [],
              }}
              onChange={patch}
              domains={{
                statuses: global?.whitelist_hostname_status,
                canWrite: can('waf:write'),
                onConfirm: confirmGlobalRateLimitDNS,
                onRefetch: () => queryClient.invalidateQueries({ queryKey: ['global-rate-limit'] }),
                errors: nameErrors,
              }}
            />
          </div>
        )}
      </div>

      {/* Info Box */}
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
        <div className="flex gap-3">
          <svg className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div className="text-sm text-blue-800 dark:text-blue-300">
            <p className="font-medium">{t('globalRateLimit.infoTitle')}</p>
            <p className="mt-1">{t('globalRateLimit.infoDesc')}</p>
          </div>
        </div>
      </div>
    </div>
  )
}
