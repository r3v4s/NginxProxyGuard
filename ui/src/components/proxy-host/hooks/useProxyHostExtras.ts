import { useQueryClient } from '@tanstack/react-query'
import { deleteGeoRestriction, getGeoRestriction, setGeoRestriction } from '../../../api/access'
import { updateBotFilter } from '../../../api/security'
import { api } from '../../../api/client'
import type { CreateBotFilterRequest } from '../../../types/security'
import type { BotFilterState, GeoDataState } from '../types'

/**
 * Maps the UI-only `disableGlobal` tri-state flag onto the API's
 * `disable_global` field and drops the UI-only key. Mirrors how the geo
 * restriction payload threads its own disable_global (#198).
 */
function botFilterPayload(data: BotFilterState): CreateBotFilterRequest {
  const { disableGlobal, ...rest } = data
  return { ...rest, disable_global: disableGlobal === true }
}

function asError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err))
}

/**
 * Why the geo restriction was not saved (#320): the domain limits answer 400,
 * so the form shows it rather than report success. Undefined when it was saved
 * or not sent.
 */
interface GeoSaveResult {
  geoError?: Error
}

/** Arguments required by {@link ProxyHostExtras.saveExtrasForCreate}. */
interface SaveExtrasCreateArgs {
  hostId: string
  botFilterData: BotFilterState
  geoData: GeoDataState
  blockedCloudProviders: string[]
  cloudProviderChallengeMode: boolean
  cloudProviderAllowSearchBots: boolean
  cloudDisableGlobal: boolean
}

/** Arguments required by {@link ProxyHostExtras.saveExtrasForUpdate}. */
interface SaveExtrasUpdateArgs extends SaveExtrasCreateArgs {
  /**
   * The pre-existing geo restriction for this host. We use this to
   * decide whether to DELETE the restriction when the user has cleared
   * all geo settings (vs. a host that never had one).
   */
  existingGeoRestriction: Awaited<ReturnType<typeof getGeoRestriction>> | null | undefined
}

/**
 * Hook that exposes two methods for saving the "extras" (bot filter,
 * geo restriction, cloud provider blocking). Each extra is saved with
 * `skip_reload=true` so the caller can issue a single nginx config
 * regenerate after all extras are applied.
 *
 * Behavior differs between create (only save what's enabled) and update
 * (always save all three, including delete-on-unset for geo).
 */
export function useProxyHostExtras() {
  const queryClient = useQueryClient()

  /**
   * For the CREATE flow: a freshly-created host has no prior settings,
   * so we only need to issue API calls for the extras that are actually
   * set. Errors do NOT abort the flow — the primary host is already
   * created, losing a bot filter write is recoverable. They are logged,
   * except the geo restriction's, which is returned (#320).
   *
   * Runs all applicable calls in parallel.
   *
   * @returns savedAny: at least one extra was sent (so the caller
   *          knows it needs to regenerate the nginx config afterwards).
   */
  async function saveExtrasForCreate({
    hostId,
    botFilterData,
    geoData,
    blockedCloudProviders,
    cloudProviderChallengeMode,
    cloudProviderAllowSearchBots,
    cloudDisableGlobal,
  }: SaveExtrasCreateArgs): Promise<GeoSaveResult & { savedAny: boolean }> {
    const promises: Promise<unknown>[] = []
    let geoError: Error | undefined

    if (
      botFilterData.enabled ||
      botFilterData.custom_blocked_agents ||
      botFilterData.custom_allowed_agents ||
      botFilterData.disableGlobal === true
    ) {
      promises.push(
        updateBotFilter(hostId, botFilterPayload(botFilterData), true).catch((err) =>
          console.error('Failed to save bot filter:', err),
        ),
      )
    }

    if (
      (geoData.enabled && geoData.countries.length > 0) ||
      (geoData.allowed_ips?.length ?? 0) > 0 ||
      (geoData.allowed_hostnames?.length ?? 0) > 0 ||
      geoData.disableGlobal === true
    ) {
      promises.push(
        setGeoRestriction(
          hostId,
          {
            mode: geoData.mode,
            countries: geoData.countries,
            allowed_ips: geoData.allowed_ips,
            allowed_hostnames: geoData.allowed_hostnames,
            allow_private_ips: geoData.allow_private_ips,
            allow_search_bots: geoData.allow_search_bots,
            enabled: geoData.enabled && geoData.countries.length > 0,
            challenge_mode: geoData.challenge_mode,
            disable_global: geoData.disableGlobal === true,
          },
          true,
        ).catch((err) => {
          geoError = asError(err)
        }),
      )
    }

    if (
      blockedCloudProviders.length > 0 ||
      cloudProviderChallengeMode ||
      cloudProviderAllowSearchBots ||
      cloudDisableGlobal
    ) {
      promises.push(
        api
          .put(`/api/v1/proxy-hosts/${hostId}/blocked-cloud-providers?skip_reload=true`, {
            blocked_providers: blockedCloudProviders,
            challenge_mode: cloudProviderChallengeMode,
            allow_search_bots: cloudProviderAllowSearchBots,
            cloud_disable_global: cloudDisableGlobal,
          })
          .catch((err) => console.error('Failed to save blocked cloud providers:', err)),
      )
    }

    if (promises.length === 0) return { savedAny: false }
    await Promise.all(promises)
    return { savedAny: true, geoError }
  }

  /**
   * For the UPDATE flow: always save all three extras in parallel. Geo
   * restriction DELETEs when the user has cleared both country blocking
   * and priority-allow IPs (but only if a record previously existed).
   *
   * Errors per-extra are not thrown — mirrors the original hook which
   * rejected only on nginx regenerate failure (handled by caller). The
   * bot filter's and the cloud providers' are logged; the geo
   * restriction's is returned (#320).
   */
  async function saveExtrasForUpdate({
    hostId,
    botFilterData,
    geoData,
    blockedCloudProviders,
    cloudProviderChallengeMode,
    cloudProviderAllowSearchBots,
    cloudDisableGlobal,
    existingGeoRestriction,
  }: SaveExtrasUpdateArgs): Promise<GeoSaveResult> {
    let geoError: Error | undefined
    const promises = [
      // Bot filter (skip reload)
      updateBotFilter(hostId, botFilterPayload(botFilterData), true)
        .then(() => queryClient.invalidateQueries({ queryKey: ['botFilter', hostId] }))
        .catch((err) => console.error('Failed to save bot filter:', err)),

      // Geo restriction (skip reload)
      (async () => {
        try {
          const hasGeoBlocking = geoData.enabled && geoData.countries.length > 0
          const hasPriorityAllowIPs = (geoData.allowed_ips?.length ?? 0) > 0
          // Domains alone keep the record too: deleting it deletes them (#320).
          const hasPriorityAllowDomains = (geoData.allowed_hostnames?.length ?? 0) > 0
          const isDisableGlobal = geoData.disableGlobal === true

          if (hasGeoBlocking || hasPriorityAllowIPs || hasPriorityAllowDomains || isDisableGlobal) {
            // Persist a record for override (hasGeoBlocking), priority-allow
            // IPs or domains, or an explicit "disable global" opt-out.
            // Deleting instead would fall back to inherit, so "disable" must
            // be stored.
            await setGeoRestriction(
              hostId,
              {
                mode: geoData.mode,
                countries: geoData.countries,
                allowed_ips: geoData.allowed_ips,
                // Left out until the record is read, which keeps the stored domains.
                allowed_hostnames: geoData.allowed_hostnames,
                allow_private_ips: geoData.allow_private_ips,
                allow_search_bots: geoData.allow_search_bots,
                enabled: hasGeoBlocking,
                challenge_mode: geoData.challenge_mode,
                disable_global: isDisableGlobal,
              },
              true,
            )
          } else if (existingGeoRestriction) {
            // Inherit: no local geo, no opt-out → drop the record so the host
            // falls back to the global default.
            await deleteGeoRestriction(hostId, true)
          }
          queryClient.invalidateQueries({ queryKey: ['geoRestriction', hostId] })
        } catch (err) {
          geoError = asError(err)
        }
      })(),

      // Blocked cloud providers (skip reload)
      api
        .put(`/api/v1/proxy-hosts/${hostId}/blocked-cloud-providers?skip_reload=true`, {
          blocked_providers: blockedCloudProviders,
          challenge_mode: cloudProviderChallengeMode,
          allow_search_bots: cloudProviderAllowSearchBots,
          cloud_disable_global: cloudDisableGlobal,
        })
        .then(() =>
          queryClient.invalidateQueries({ queryKey: ['blockedCloudProviders', hostId] }),
        )
        .catch((err) => console.error('Failed to save blocked cloud providers:', err)),
    ]

    await Promise.all(promises)
    return { geoError }
  }

  return {
    saveExtrasForCreate,
    saveExtrasForUpdate,
  }
}

/** Public return type, inferred. */
export type ProxyHostExtras = ReturnType<typeof useProxyHostExtras>
