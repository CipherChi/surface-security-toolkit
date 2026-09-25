import type {
  CheckStatus,
  CRTShResponse,
  DNSResponse,
  EmailResponse,
  TLSResponse,
  VirusTotalResponse,
  WhoisResponse,
} from './types'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000'

async function postDomain<T>(path: string, domain: string): Promise<T> {
  const response = await fetch(`${API_BASE_URL}/api/v1/${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
  })

  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as {
      detail?: string | Array<{ msg?: string }>
    } | null
    const detail = body?.detail
    const message = typeof detail === 'string'
      ? detail
      : Array.isArray(detail)
        ? detail.map((item) => item.msg).filter(Boolean).join(' ')
        : undefined
    throw new Error(message || `The check failed with HTTP ${response.status}.`)
  }

  return (await response.json()) as T
}

function statusMessage(status: CheckStatus, error?: string | null): string | undefined {
  if (status === 'not_found') return 'No published report was found for this domain.'
  if (status === 'unavailable') return error ?? 'This check is not configured.'
  if (status === 'error') return error ?? 'The data source could not complete this check.'
  return undefined
}

export const domainApi = {
  email: async (email: string) => {
    const response = await fetch(`${API_BASE_URL}/api/v1/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    })
    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as { detail?: string } | null
      throw new Error(body?.detail || `The check failed with HTTP ${response.status}.`)
    }
    return (await response.json()) as EmailResponse
  },
  dns: (domain: string) => postDomain<DNSResponse>('dns', domain),
  crtsh: (domain: string) => postDomain<CRTShResponse>('crtsh', domain),
  whois: async (domain: string) => {
    const result = await postDomain<WhoisResponse>('whois', domain)
    return { ...result, message: statusMessage(result.status, result.error) }
  },
  tls: async (domain: string) => {
    const result = await postDomain<TLSResponse>('tls', domain)
    return { ...result, message: statusMessage(result.status, result.error) }
  },
  virustotal: async (domain: string) => {
    const result = await postDomain<VirusTotalResponse>('virustotal', domain)
    return { ...result, message: statusMessage(result.status, result.error) }
  },
}
