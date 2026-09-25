export type CheckStatus = 'success' | 'not_found' | 'error' | 'unavailable'
export type ViewState = 'idle' | 'loading' | CheckStatus | 'partial'

export interface DNSResponse {
  domain: string
  records: Record<string, string[]>
  statuses: Record<string, string>
  errors: Record<string, string>
}

export interface CRTShResponse {
  domain: string
  subdomains: string[]
  status: CheckStatus
  error?: string | null
}

export interface WhoisResponse {
  domain: string
  data: Record<string, string | string[] | null>
  status: CheckStatus
  error?: string | null
}

export interface TLSCertificate {
  issuer: Record<string, string>
  subject: Record<string, string>
  valid_from: string | null
  valid_until: string | null
  days_until_expiry: number | null
  is_expired: boolean | null
  subject_alt_names: string[]
  serial_number: string | null
  version: number | null
}

export interface TLSResponse {
  domain: string
  certificate: TLSCertificate | null
  status: CheckStatus
  error?: string | null
}

export interface VirusTotalResponse {
  domain: string
  data: Record<string, unknown>
  status: CheckStatus
  error?: string | null
}

export interface CheckCardState<T = unknown> {
  status: ViewState
  data?: T
  message?: string
}

export interface EmailSignal {
  signal: string
  status: 'checked' | 'not_checked' | 'exposed' | 'clean' | 'loading'
  details: string
  source_url?: string | null
}

export interface EmailResponse {
  email: string
  domain: string
  signals: EmailSignal[]
}
