import { getToken, clearToken } from './auth'

// A 401 means the session died. Reloading hands control to the login screen —
// but a dashboard fires dozens of parallel queries, so an expired session used
// to schedule dozens of reloads, and each reload re-issued the whole boot
// request set. During the #258 API-limiter lockout that loop kept re-spending
// the budget that caused it. Reload once, and only if we actually held a
// token: without one we are already on the login screen, where a stray 401
// must not reboot the page under the operator's hands.
let sessionExpiryHandled = false
export function handleSessionExpired(): void {
  const hadToken = !!getToken()
  clearToken()
  if (hadToken && !sessionExpiryHandled) {
    sessionExpiryHandled = true
    window.location.reload()
  }
}

export function getAuthHeaders(): HeadersInit {
  const token = getToken()
  const headers: HeadersInit = {
    'Content-Type': 'application/json'
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  return headers
}

// Custom error class to include details from server
export class ApiError extends Error {
  details?: string
  status: number
  /**
   * Stable machine-readable reason, when the server sends one. It exists so a
   * screen can show its own translated wording: the server's message names JSON
   * fields ("invalid chat_id") and is always English, which reads as a bug in an
   * otherwise Korean panel.
   */
  code?: string
  /**
   * The id of what a create saved although it answers with an error: a proxy
   * host created or cloned whose reload nginx refused (409
   * nginx_reload_rejected).
   */
  id?: string
  /**
   * The request field a 400 is about, such as "items[2].address" (#320). The
   * index counts the items of the request as sent, so a form maps it back to its
   * own row.
   */
  field?: string

  constructor(message: string, status: number, details?: string, code?: string, id?: string, field?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.details = details
    this.code = code
    this.id = id
    this.field = field
  }
}

/**
 * True for a 409 nginx_reload_rejected: the change is saved and its config
 * files are written, but the running nginx refused to load them. The message
 * says what to do, and details holds nginx's own line.
 */
export function isNginxReloadRefusal(err: unknown): err is ApiError {
  return err instanceof ApiError && err.status === 409 && err.code === 'nginx_reload_rejected'
}

/**
 * The error of a failed response, for a module that calls fetch itself: the
 * server's sentence (fallback when it sends none), with its code and the
 * request field a 400 names (#320), so a form can mark that entry. Unlike
 * handleResponse it changes nothing else about how the caller fails.
 */
export async function responseError(response: Response, fallback: string): Promise<ApiError> {
  const body = (await response.json().catch(() => null)) as
    | { error?: string; details?: string; code?: string; field?: string }
    | null
  return new ApiError(body?.error || fallback, response.status, body?.details, body?.code, undefined, body?.field)
}

export async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    if (response.status === 401) {
      handleSessionExpired()
    }
    // Gateway errors return HTML (nginx error page), not JSON
    if (response.status === 502 || response.status === 503 || response.status === 504) {
      throw new ApiError(
        response.status === 504
          ? 'Request timed out - the server is taking too long to respond'
          : 'Server temporarily unavailable - please try again',
        response.status
      )
    }
    const errorData = await response.json().catch(() => null)
    // Every 403 the API sends is JSON. One that is not came from something in
    // front of it — typically a WAF (NPG's own, when the UI is published through
    // a proxy host) rejecting the request body. Calling that a role problem sent
    // an administrator hunting through permissions they already had. (#307)
    if (response.status === 403 && errorData === null) {
      throw new ApiError(
        'The request was blocked before it reached the server (HTTP 403). A web application firewall or reverse proxy in front of this UI may have rejected it — check its logs.',
        403
      )
    }
    const message = errorData === null ? 'Unknown error' : errorData.error || `HTTP ${response.status}`
    const details = errorData?.details
    // 403 now means "your role does not allow this" far more often than anything
    // else, and the server's wording is aimed at API clients ("insufficient
    // permissions", "required: proxy:write"). Say it in terms an operator can act
    // on, keeping the raw requirement as details. (#222)
    if (response.status === 403) {
      const code = (errorData as { code?: string }).code
      if (code === 'must_change_password') {
        throw new ApiError('You must change your password before using the application.', 403, details)
      }
      if (code === 'initial_setup_required') {
        throw new ApiError(message, 403, details)
      }
      const required = (errorData as { required?: string }).required
      throw new ApiError(
        'Your role does not allow this action. Ask an administrator to grant it.',
        403,
        required ? `Required permission: ${required}` : details
      )
    }
    const body = errorData as { code?: string; id?: string; field?: string } | null
    throw new ApiError(message, response.status, details, body?.code, body?.id, body?.field)
  }
  // Handle empty responses (204 No Content)
  if (response.status === 204) {
    return {} as T
  }
  return response.json().catch(() => ({} as T))
}

export async function apiGet<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    headers: getAuthHeaders()
  })
  return handleResponse<T>(response)
}

export async function apiPost<T>(url: string, data?: unknown): Promise<T> {
  const response = await fetch(url, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: data ? JSON.stringify(data) : undefined
  })
  return handleResponse<T>(response)
}

export async function apiPut<T>(url: string, data: unknown): Promise<T> {
  const response = await fetch(url, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data)
  })
  return handleResponse<T>(response)
}

export async function apiDelete(url: string): Promise<void> {
  const response = await fetch(url, {
    method: 'DELETE',
    headers: getAuthHeaders()
  })
  if (!response.ok) {
    if (response.status === 401) {
      handleSessionExpired()
    }
    if (response.status === 502 || response.status === 503 || response.status === 504) {
      throw new ApiError(
        response.status === 504
          ? 'Request timed out - the server is taking too long to respond'
          : 'Server temporarily unavailable - please try again',
        response.status
      )
    }
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new ApiError(error.error || `HTTP ${response.status}`, response.status, error.details, error.code, undefined, error.field)
  }
}

// Convenience wrapper for api calls
export const api = {
  get: apiGet,
  post: apiPost,
  put: apiPut,
  delete: apiDelete,
}
