/**
 * Priority allow entries must be an IPv4 or IPv6 address or a CIDR range: the
 * API refuses a geo restriction holding anything else. The geo editors use
 * these helpers to point out other lines and to leave them out of what they
 * save, so one mistyped line does not stop the rest of the restriction from
 * being saved.
 */

const IPV4_OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
const IPV4_ADDRESS = new RegExp(`^${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3}$`)

function isIPv6Address(value: string): boolean {
  // Only the characters an IPv6 address is written with; the URL parser then
  // checks its form (at most eight groups, one "::", an IPv4 tail).
  if (!value.includes(':') || !/^[0-9A-Fa-f:.]+$/.test(value)) {
    return false
  }
  try {
    new URL(`http://[${value}]/`)
    return true
  } catch {
    return false
  }
}

/** Whether entry is an IP address or a CIDR range, with nothing around it. */
export function isIPOrCIDR(entry: string): boolean {
  const slash = entry.indexOf('/')
  const address = slash === -1 ? entry : entry.slice(0, slash)
  const isV4 = IPV4_ADDRESS.test(address)
  if (!isV4 && !isIPv6Address(address)) {
    return false
  }
  if (slash === -1) {
    return true
  }
  const prefix = entry.slice(slash + 1)
  return /^(0|[1-9]\d{0,2})$/.test(prefix) && Number(prefix) <= (isV4 ? 32 : 128)
}

/** Splits entries into the ones the API accepts and the rest. */
export function splitAllowedIPs(entries: string[]): { valid: string[]; invalid: string[] } {
  const valid: string[] = []
  const invalid: string[] = []
  for (const entry of entries) {
    if (isIPOrCIDR(entry)) {
      valid.push(entry)
    } else {
      invalid.push(entry)
    }
  }
  return { valid, invalid }
}

/** The non-empty, trimmed lines of the priority allow text area. */
export function allowedIPLines(text: string): string[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
}

/**
 * The entries of a saved list as the text area's onChange would pass them on:
 * the list is shown one entry per line, so it goes through the same steps.
 * kept are entries the server reports it leaves out of the configs (#320,
 * allowed_ips_ignored): a stored entry goes back as it is, which the API
 * takes, until the operator moves or removes it.
 */
export function savableAllowedIPs(saved: string[], kept: readonly string[] = []): string[] {
  const keep = new Set(kept)
  return allowedIPLines(saved.join('\n')).filter((entry) => isIPOrCIDR(entry) || keep.has(entry))
}
