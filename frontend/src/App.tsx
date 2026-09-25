import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { domainApi } from './api'
import type {
  CheckCardState,
  CheckStatus,
  CRTShResponse,
  DNSResponse,
  EmailSignal,
  TLSResponse,
  VirusTotalResponse,
  ViewState,
  WhoisResponse,
} from './types'

type CheckId = 'crtsh' | 'dns' | 'whois' | 'tls' | 'virustotal'
type CheckStateMap = Record<CheckId, CheckCardState>
type LookupMode = 'domain' | 'email'

const initialChecks: CheckStateMap = {
  crtsh: { status: 'idle' },
  dns: { status: 'idle' },
  whois: { status: 'idle' },
  tls: { status: 'idle' },
  virustotal: { status: 'idle' },
}

const checkDetails: Record<CheckId, { title: string; eyebrow: string; description: string; icon: string }> = {
  crtsh: {
    title: 'Certificate transparency',
    eyebrow: 'SUBDOMAIN DISCOVERY',
    description: 'Names observed in public certificate logs',
    icon: 'CT',
  },
  dns: {
    title: 'DNS records',
    eyebrow: 'DOMAIN CONFIGURATION',
    description: 'Public A, MX, TXT and NS records',
    icon: 'DNS',
  },
  whois: {
    title: 'WHOIS registration',
    eyebrow: 'REGISTRATION DATA',
    description: 'Publicly available registrar details',
    icon: 'ID',
  },
  tls: {
    title: 'TLS certificate',
    eyebrow: 'CERTIFICATE HEALTH',
    description: 'Certificate presented on port 443',
    icon: 'TLS',
  },
  virustotal: {
    title: 'Threat reputation',
    eyebrow: 'COMMUNITY INTELLIGENCE',
    description: 'Existing VirusTotal domain report',
    icon: 'VT',
  },
}

function statusLabel(status: ViewState): string {
  const labels: Record<ViewState, string> = {
    idle: 'Not checked',
    loading: 'Checking',
    success: 'Complete',
    partial: 'Partial results',
    not_found: 'No data found',
    error: 'Check failed',
    unavailable: 'Not configured',
  }
  return labels[status]
}

function resultStatus(status: CheckStatus): ViewState {
  return status
}

function CheckCard({
  id,
  state,
  children,
}: {
  id: CheckId
  state: CheckCardState
  children: ReactNode
}) {
  const details = checkDetails[id]
  return (
    <section className={`check-card check-card--${state.status}`} aria-labelledby={`${id}-heading`}>
      <div className="check-card__topline">
        <div className="check-card__icon" aria-hidden="true">{details.icon}</div>
        <span className={`status-pill status-pill--${state.status}`}>
          {state.status === 'loading' && <span className="status-spinner" aria-hidden="true" />}
          {statusLabel(state.status)}
        </span>
      </div>
      <div className="check-card__heading">
        <p className="eyebrow">{details.eyebrow}</p>
        <h2 id={`${id}-heading`}>{details.title}</h2>
        <p className="check-card__description">{details.description}</p>
      </div>
      <div className="check-card__body">{children}</div>
    </section>
  )
}

function EmailSignalCard({ signal }: { signal: EmailSignal }) {
  const labels = { checked: 'Checked', not_checked: 'Not checked', exposed: 'Exposure found', clean: 'No signal', loading: 'Checking' }
  return (
    <section className="check-card email-signal-card" aria-label={signal.signal}>
      <div className="check-card__topline">
        <div className="check-card__icon" aria-hidden="true">{signal.signal === 'Email domain MX' ? 'MX' : signal.signal === 'Known breach exposure' ? 'HIBP' : 'AV'}</div>
        <span className={`status-pill status-pill--${signal.status}`}>
          {signal.status === 'loading' && <span className="status-spinner" aria-hidden="true" />}
          {labels[signal.status]}
        </span>
      </div>
      <div className="check-card__heading"><h2>{signal.signal}</h2></div>
      <div className="check-card__body">
        <p className="email-signal-details">{signal.details}</p>
        {signal.source_url && <a className="email-source-link" href={signal.source_url} target="_blank" rel="noreferrer">Source: {signal.source_url.includes('xposedornot') ? 'XposedOrNot' : 'Have I Been Pwned'} ↗</a>}
      </div>
    </section>
  )
}

function EmptyState({ children }: { children: ReactNode }) {
  return <div className="empty-state">{children}</div>
}

function DataRows({ data }: { data: Record<string, string | string[] | null> }) {
  const entries = Object.entries(data).filter(([, value]) => value !== null && value !== '')
  if (!entries.length) return <EmptyState>No registration fields were returned.</EmptyState>
  return (
    <dl className="data-rows">
      {entries.map(([label, value]) => (
        <div className="data-row" key={label}>
          <dt>{label.replace(/_/g, ' ')}</dt>
          <dd>{Array.isArray(value) ? value.join(', ') : value}</dd>
        </div>
      ))}
    </dl>
  )
}

function DNSResults({ result }: { result: DNSResponse }) {
  const types = ['A', 'MX', 'TXT', 'NS']
  return (
    <div className="dns-results">
      {types.map((type) => {
        const records = result.records[type] ?? []
        const status = result.statuses[type] ?? 'error'
        return (
          <div className="dns-row" key={type}>
            <div className="dns-row__label">
              <span className="mono-tag">{type}</span>
              <span className={`record-state record-state--${status}`}>
                {status === 'success' ? `${records.length} found` : status.replace('_', ' ')}
              </span>
            </div>
            {records.length ? (
              <ul className="record-list">
                {records.slice(0, 4).map((record, index) => <li key={`${record}-${index}`}>{record}</li>)}
                {records.length > 4 && <li className="muted">+{records.length - 4} more records</li>}
              </ul>
            ) : result.errors[type] ? (
              <p className="inline-error">{result.errors[type]}</p>
            ) : (
              <p className="muted small">No record published</p>
            )}
          </div>
        )
      })}
    </div>
  )
}

function ReputationResults({ result }: { result: VirusTotalResponse }) {
  const stats = result.data.last_analysis_stats as Record<string, number> | undefined
  const score = stats ? (stats.malicious ?? 0) + (stats.suspicious ?? 0) : null
  const votes = result.data.total_votes as Record<string, number> | undefined
  return (
    <>
      {score !== null && (
        <div className="reputation-score">
          <span className={`score-mark ${score > 0 ? 'score-mark--flagged' : ''}`}>{score}</span>
          <div>
            <strong>{score > 0 ? 'Flagged by vendors' : 'No vendors flagged this domain'}</strong>
            <span>{stats?.malicious ?? 0} malicious · {stats?.suspicious ?? 0} suspicious</span>
          </div>
        </div>
      )}
      {votes && (
        <div className="metric-strip">
          <span>Community votes</span>
          <strong>{votes.harmless ?? 0} harmless / {votes.malicious ?? 0} malicious</strong>
        </div>
      )}
      {result.data.reputation !== undefined && (
        <div className="metric-strip"><span>Reputation score</span><strong>{String(result.data.reputation)}</strong></div>
      )}
      {!stats && !votes && result.data.reputation === undefined && (
        <EmptyState>The report is available, but has no summary data yet.</EmptyState>
      )}
      <p className="disclaimer">Community verdicts are signals, not a guarantee of safety.</p>
    </>
  )
}

function TLSResults({ result }: { result: TLSResponse }) {
  const certificate = result.certificate
  if (!certificate) return <EmptyState>No certificate details were returned.</EmptyState>
  return (
    <>
      <div className={`certificate-banner ${certificate.is_expired ? 'certificate-banner--expired' : ''}`}>
        <span className="certificate-dot" />
        <div>
          <strong>{certificate.is_expired ? 'Certificate expired' : 'Certificate presented'}</strong>
          <span>
            {certificate.days_until_expiry === null
              ? 'Validity end date unavailable'
              : certificate.is_expired
                ? `Expired ${Math.abs(certificate.days_until_expiry)} days ago`
                : `Expires in ${certificate.days_until_expiry} days`}
          </span>
        </div>
      </div>
      <dl className="data-rows compact-rows">
        <div className="data-row"><dt>Issuer</dt><dd>{certificate.issuer.commonName ?? certificate.issuer.organizationName ?? 'Unknown'}</dd></div>
        <div className="data-row"><dt>Valid from</dt><dd>{certificate.valid_from ?? 'Unknown'}</dd></div>
        <div className="data-row"><dt>Valid until</dt><dd>{certificate.valid_until ?? 'Unknown'}</dd></div>
        <div className="data-row"><dt>Names covered</dt><dd>{certificate.subject_alt_names.length ? certificate.subject_alt_names.slice(0, 3).join(', ') : 'None listed'}</dd></div>
      </dl>
    </>
  )
}

function CardContent({ id, state, emptyPrompt = 'Enter a domain above to begin this check.' }: { id: CheckId; state: CheckCardState; emptyPrompt?: string }) {
  if (state.status === 'idle') {
    return <EmptyState>{emptyPrompt}</EmptyState>
  }
  if (state.status === 'loading') {
    return <div className="loading-lines" aria-label="Loading results"><span /><span /><span /></div>
  }
  if (state.status === 'error' || state.status === 'unavailable') {
    return (
      <div className={`message-box message-box--${state.status}`}>
        <strong>{state.status === 'unavailable' ? 'Setup needed' : 'Could not complete check'}</strong>
        <span>{state.message ?? 'The data source did not return a result. You can try again.'}</span>
      </div>
    )
  }
  if (state.status === 'not_found') {
    return <EmptyState>{state.message ?? 'No public data was found for this check.'}</EmptyState>
  }

  switch (id) {
    case 'crtsh': {
      const result = state.data as CRTShResponse
      return result.subdomains.length ? (
        <>
          <div className="result-count"><strong>{result.subdomains.length}</strong><span>names discovered</span></div>
          <ul className="chip-list">
            {result.subdomains.slice(0, 10).map((name) => <li key={name}>{name}</li>)}
            {result.subdomains.length > 10 && <li className="chip-more">+{result.subdomains.length - 10} more</li>}
          </ul>
        </>
      ) : <EmptyState>No certificate names found in the public log.</EmptyState>
    }
    case 'dns':
      return <DNSResults result={state.data as DNSResponse} />
    case 'whois': {
      const result = state.data as WhoisResponse
      return <DataRows data={result.data} />
    }
    case 'tls':
      return <TLSResults result={state.data as TLSResponse} />
    case 'virustotal':
      return <ReputationResults result={state.data as VirusTotalResponse} />
  }
}

function normalizeResult<T extends { status: CheckStatus; error?: string | null }>(
  data: T,
): CheckCardState<T> {
  return { status: resultStatus(data.status), data, message: data.error ?? undefined }
}

function normalizeDNS(data: DNSResponse): CheckCardState<DNSResponse> {
  const values = Object.values(data.statuses)
  const successes = values.filter((status) => status === 'success').length
  const errors = values.filter((status) => status === 'error').length
  const status: ViewState = successes === 0 && errors === values.length
    ? 'error'
    : errors > 0
      ? 'partial'
      : successes === 0
        ? 'not_found'
        : 'success'
  return {
    status,
    data,
    message: errors ? `${errors} record type${errors === 1 ? '' : 's'} could not be resolved.` : undefined,
  }
}

export default function App() {
  const [domain, setDomain] = useState('')
  const [activeDomain, setActiveDomain] = useState('')
  const [mode, setMode] = useState<LookupMode>('domain')
  const [emailSignals, setEmailSignals] = useState<EmailSignal[]>([])
  const [checks, setChecks] = useState<CheckStateMap>(initialChecks)
  const [submitted, setSubmitted] = useState(false)
  const [cooldown, setCooldown] = useState(false)
  const [lookupError, setLookupError] = useState('')
  const lastSubmitAt = useRef(0)

  useEffect(() => {
    let frame = 0
    const updateBackgroundDepth = () => {
      if (frame) return
      frame = window.requestAnimationFrame(() => {
        document.documentElement.style.setProperty('--scroll-depth', `${window.scrollY}px`)
        document.documentElement.style.setProperty('--planet-rotate', `${window.scrollY * 0.035}deg`)
        frame = 0
      })
    }
    updateBackgroundDepth()
    window.addEventListener('scroll', updateBackgroundDepth, { passive: true })
    return () => {
      window.removeEventListener('scroll', updateBackgroundDepth)
      if (frame) window.cancelAnimationFrame(frame)
    }
  }, [])

  useEffect(() => {
    if (!cooldown) return
    const timer = window.setTimeout(() => setCooldown(false), 2500)
    return () => window.clearTimeout(timer)
  }, [cooldown])

  async function runCheck<T>(id: CheckId, request: () => Promise<T>, normalize: (value: T) => CheckCardState) {
    try {
      const data = await request()
      setChecks((current) => ({ ...current, [id]: normalize(data) }))
    } catch (error) {
      setChecks((current) => ({
        ...current,
        [id]: {
          status: 'error',
          message: error instanceof Error ? error.message : 'An unexpected error occurred.',
        },
      }))
    }
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (Date.now() - lastSubmitAt.current < 2500) return
    const rawTarget = domain.trim()
    if (!rawTarget) return
    let target = rawTarget.toLowerCase()
    if (mode === 'domain') {
      if (rawTarget.includes('@')) {
        setLookupError('That looks like an email address. Switch to Email mode to check it.')
        return
      }
      try {
        const url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(rawTarget) ? rawTarget : `https://${rawTarget}`)
        target = url.hostname.toLowerCase().replace(/\.$/, '')
      } catch {
        setLookupError('Enter a domain such as example.com.')
        return
      }
      const labels = target.split('.')
      const isDomain = target.length <= 253 && labels.length >= 2 && !/^\d+$/.test(labels[labels.length - 1]) && labels.every((label) => label.length <= 63 && /^[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(label))
      if (!isDomain || target.includes(':')) {
        setLookupError('Enter a domain such as example.com, without an IP address.')
        return
      }
    }
    setLookupError('')
    lastSubmitAt.current = Date.now()
    setCooldown(true)
    setActiveDomain(target)
    setSubmitted(true)
    if (mode === 'email') {
      const emailDomain = target.split('@').slice(-1)[0] ?? ''
      setEmailSignals([
        { signal: 'Email domain MX', status: 'loading', details: 'Checking public mail routing records…' },
        { signal: 'Known breach exposure', status: 'loading', details: 'Checking public breach data…' },
        { signal: 'Public Gravatar avatar', status: 'loading', details: 'Checking for a public avatar association…' },
      ])
      setChecks({ ...initialChecks, crtsh: { status: 'loading' }, dns: { status: 'loading' }, whois: { status: 'loading' } })
      void domainApi.email(target).then((result) => setEmailSignals(result.signals)).catch((error: unknown) => {
        const details = error instanceof Error ? error.message : 'The email checks could not complete.'
        setEmailSignals([
          { signal: 'Email domain MX', status: 'not_checked', details },
            { signal: 'Known breach exposure', status: 'not_checked', details },
          { signal: 'Public Gravatar avatar', status: 'not_checked', details },
        ])
      })
      void runCheck('crtsh', () => domainApi.crtsh(emailDomain), normalizeResult<CRTShResponse>)
      void runCheck('dns', () => domainApi.dns(emailDomain), normalizeDNS)
      void runCheck('whois', () => domainApi.whois(emailDomain), (data) => normalizeResult(data))
      return
    }
    const requestedDomain = target
    setEmailSignals([])
    setChecks({
      crtsh: { status: 'loading' },
      dns: { status: 'loading' },
      whois: { status: 'loading' },
      tls: { status: 'loading' },
      virustotal: { status: 'loading' },
    })
    void runCheck('crtsh', () => domainApi.crtsh(requestedDomain), normalizeResult<CRTShResponse>)
    void runCheck('dns', () => domainApi.dns(requestedDomain), normalizeDNS)
    void runCheck('whois', () => domainApi.whois(requestedDomain), (data) => normalizeResult(data))
    void runCheck('tls', () => domainApi.tls(requestedDomain), (data) => normalizeResult(data))
    void runCheck('virustotal', () => domainApi.virustotal(requestedDomain), (data) => normalizeResult(data))
  }

  function handleReset() {
    setDomain('')
    setActiveDomain('')
    setChecks(initialChecks)
    setEmailSignals([])
    setSubmitted(false)
  }

  const orderedIds: CheckId[] = ['crtsh', 'dns', 'whois', 'tls', 'virustotal']
  const completedChecks = Object.values(checks).filter((check) => check.status !== 'idle' && check.status !== 'loading').length
  const loadingChecks = Object.values(checks).filter((check) => check.status === 'loading').length
  const emailChecksLoading = emailSignals.filter((signal) => signal.status === 'loading').length
  const checksFinished = completedChecks + (mode === 'email' ? emailSignals.length - emailChecksLoading : 0)
  const checksLoading = loadingChecks + (mode === 'email' ? emailChecksLoading : 0)
  const visibleEmailSignals = emailSignals.length ? emailSignals : [
    { signal: 'Email domain MX', status: 'not_checked' as const, details: 'Checks whether the email domain publishes mail routing records.' },
    { signal: 'Known breach exposure', status: 'not_checked' as const, details: 'Checks public breach records using XposedOrNot by default. If the source is temporarily unavailable, try again later.' },
    { signal: 'Public Gravatar avatar', status: 'not_checked' as const, details: 'Looks for an avatar associated with the email hash.' },
  ]

  return (
    <main className="app-shell">
      <div className="space-backdrop" aria-hidden="true">
        <div className="space-stars space-stars--far">{Array.from({ length: 8 }, (_, index) => <i key={index} style={{ left: `${(index * 37 + 9) % 100}%`, top: `${(index * 53 + 13) % 100}%`, animationDelay: `${(index * .83) % 6}s` }} />)}</div>
        <div className="space-stars space-stars--near">{Array.from({ length: 7 }, (_, index) => <i key={index} style={{ left: `${(index * 61 + 21) % 100}%`, top: `${(index * 29 + 31) % 100}%`, animationDelay: `${(index * 1.17) % 8}s` }} />)}</div>
        <div className="space-planet"><div className="space-planet__highlight" /></div>
      </div>
      <header className="topbar">
        <a className="brand" href="#top" aria-label="Surface home">
          <span className="brand-mark" aria-hidden="true"><span /><span /><span /></span>
          <span>surface<span className="brand-dot">.</span></span>
          <span className="brand-divider" />
          <span className="brand-caption">DOMAIN EXPOSURE</span>
        </a>
        <div className="topbar-meta"><span className="live-dot" /> PASSIVE INTELLIGENCE <span className="meta-separator">/</span> LOCAL WORKSPACE</div>
      </header>

      <section className="hero" id="top">
        <div className="hero-copy">
          <p className="eyebrow hero-eyebrow"><span className="eyebrow-rule" /> EXTERNAL ATTACK SURFACE</p>
          <h1>See what the<br /><span>internet sees.</span></h1>
          <p className="hero-description">A clear, passive view of the public data connected to a domain. No probes. No intrusion. Just the signals already out there.</p>
        </div>
        <div className="hero-note">
          <div className="note-icon" aria-hidden="true">◎</div>
          <div><strong>Read-only by design</strong><span>Checks use public records and existing reports.</span></div>
        </div>
      </section>

      <section className="search-panel" aria-label="Domain lookup">
        <div className="lookup-modes" role="tablist" aria-label="Lookup type">
          <button type="button" role="tab" aria-selected={mode === 'domain'} className={mode === 'domain' ? 'lookup-mode lookup-mode--active' : 'lookup-mode'} onClick={() => { setMode('domain'); setDomain(''); setActiveDomain(''); setSubmitted(false); setEmailSignals([]); setChecks(initialChecks) }}>Domain</button>
          <button type="button" role="tab" aria-selected={mode === 'email'} className={mode === 'email' ? 'lookup-mode lookup-mode--active' : 'lookup-mode'} onClick={() => { setMode('email'); setDomain(''); setActiveDomain(''); setSubmitted(false); setEmailSignals([]); setChecks(initialChecks) }}>Email</button>
        </div>
        <form onSubmit={handleSubmit}>
          <label htmlFor="domain-input">{mode === 'domain' ? 'DOMAIN OR HOSTNAME' : 'EMAIL ADDRESS'}</label>
          <div className="search-row">
            <div className="input-wrap">
              <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></svg>
              <input
                id="domain-input"
                value={domain}
                onChange={(event) => { setDomain(event.target.value); setLookupError('') }}
                type={mode === 'email' ? 'email' : 'text'}
                placeholder={mode === 'email' ? 'e.g. you@example.com' : 'e.g. example.com'}
                autoComplete={mode === 'email' ? 'email' : 'url'}
                required
              />
              {domain && <button className="clear-button" type="button" aria-label="Clear domain" onClick={() => setDomain('')}>×</button>}
            </div>
            <button className="submit-button" type="submit" disabled={cooldown || loadingChecks > 0 || emailSignals.some((signal) => signal.status === 'loading')}>
              {loadingChecks > 0 || emailSignals.some((signal) => signal.status === 'loading') ? 'Checking' : cooldown ? 'Wait a moment' : submitted ? 'Run again' : mode === 'email' ? 'Check email' : 'Check domain'}
              <span aria-hidden="true">↗</span>
            </button>
          </div>
        </form>
        {lookupError && <p className="inline-error lookup-error" role="alert">{lookupError}</p>}
        <div className="search-footnote"><span className="lock-icon" aria-hidden="true">▣</span> Only check {mode === 'email' ? 'email addresses' : 'domains'} you own or have permission to assess.</div>
        {mode === 'email' && <p className="email-privacy-note">The full address is sent to the breach source (XposedOrNot by default, or HIBP if configured). Public checks query the email domain; Gravatar receives only a SHA-256 hash.</p>}
      </section>

      <section className="results-section" aria-live="polite">
        <div className="section-heading">
          <div>
            <p className="eyebrow">INTELLIGENCE OVERVIEW</p>
            <h2>{activeDomain ? <>{mode === 'email' ? 'Exposure signals for ' : 'Results for '}<span className="domain-title">{activeDomain}</span></> : mode === 'email' ? 'Email signals with domain context.' : 'Five signals. One clear picture.'}</h2>
          </div>
          {submitted && (
            <div className="results-meta">
              <span className="results-progress">{checksLoading ? `${checksFinished} of ${mode === 'email' ? 6 : 5} checks complete` : 'All checks finished'}</span>
              <button type="button" className="text-button" onClick={handleReset}>Clear results</button>
            </div>
          )}
        </div>

        {!submitted && (
          <div className="intro-strip">
            <div className="intro-strip__symbol" aria-hidden="true">↳</div>
            <p>{mode === 'email' ? 'Check mail routing and public account signals, then review public records connected to the email domain.' : 'Enter a domain to gather its publicly visible records, certificate history, registration details and community reputation.'}</p>
            <span className="intro-count">{mode === 'email' ? '06 CHECKS' : '05 CHECKS'}</span>
          </div>
        )}

        {mode === 'email' && <div className="cards-grid email-cards-grid">{visibleEmailSignals.map((signal) => <EmailSignalCard key={signal.signal} signal={signal} />)}</div>}
        <div className="cards-grid">
          {(mode === 'email' ? (['crtsh', 'dns', 'whois'] as CheckId[]) : orderedIds).map((id) => (
            <CheckCard key={id} id={id} state={checks[id]}>
              <CardContent id={id} state={checks[id]} emptyPrompt="Enter an email address above to begin this domain check." />
            </CheckCard>
          ))}
        </div>
      </section>

      <footer className="footer">
        <div className="footer-brand"><span className="brand-mark small-mark"><span /><span /><span /></span> SURFACE <span className="footer-version">LOCAL · 0.1</span></div>
        <p>Public data only. Use responsibly and only with authorization.</p>
        <a href="https://docs.virustotal.com/reference/domain-info" target="_blank" rel="noreferrer">Data source details <span aria-hidden="true">↗</span></a>
      </footer>
    </main>
  )
}
