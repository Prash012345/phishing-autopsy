import { useMemo, useState } from 'react'
import axios from 'axios'
import './App.css'

const API_URL = 'http://127.0.0.1:5000/api/analyze'

function normalizeAnalysisResponse(data) {
  const ai = data.ai_analysis ?? data.ai ?? {}
  const score = data.score_breakdown ?? {
    model_probability: ai.threat_score ?? 0,
    heuristic_points: 0,
    final_score: ai.threat_score ?? 0,
    verdict: ai.is_phishing ? 'high_risk' : 'low_risk',
  }
  const linkAnalysis = data.link_analysis ?? {
    links: ai.links ?? [],
    details: [],
    unique_domains: [],
    total_links: ai.links?.length ?? 0,
    suspicious_count: ai.suspicious_links?.length ?? 0,
    suspicious_links: ai.suspicious_links ?? [],
  }

  return {
    ...data,
    ai,
    score_breakdown: score,
    link_analysis: linkAnalysis,
    risk_factors: data.risk_factors ?? [],
    language_analysis: data.language_analysis ?? {
      word_count: 0,
      keyword_hit_count: 0,
      keyword_hits: {},
    },
    header_analysis: data.header_analysis ?? {},
  }
}

function StatusPill({ label, good }) {
  return (
    <span className={`status-pill ${good ? 'pass' : 'fail'}`}>
      <span className="status-dot" />
      {label}
    </span>
  )
}

function Metric({ label, value, tone = 'neutral' }) {
  return (
    <div className={`metric ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

function EmptyState({ text }) {
  return <p className="empty-state">{text}</p>
}

function App() {
  const [emailText, setEmailText] = useState('')
  const [senderDomain, setSenderDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)
  const [file, setFile] = useState(null)

  const scoreTone = useMemo(() => {
    const finalScore = results?.score_breakdown?.final_score ?? results?.ai?.threat_score ?? 0
    if (finalScore >= 75) return 'critical'
    if (finalScore >= 51) return 'warning'
    return 'calm'
  }, [results])

  const handleAnalyze = async (e) => {
    e.preventDefault()
    setLoading(true)
    setResults(null)

    try {
      const formData = new FormData()

      if (file) {
        formData.append('file', file)
      } else {
        formData.append('email_text', emailText)
        formData.append('sender_domain', senderDomain)
      }

      const response = await axios.post(API_URL, formData)
      setResults(normalizeAnalysisResponse(response.data))
    } catch (error) {
      console.error('Error:', error)
      alert('Failed to analyze. Check backend.')
    } finally {
      setLoading(false)
    }
  }

  const dns = results?.dns_analysis
  const score = results?.score_breakdown
  const header = results?.header_analysis
  const links = results?.link_analysis
  const language = results?.language_analysis
  const riskFactors = results?.risk_factors ?? []

  return (
    <main className="app-shell">
      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Local email threat analysis</p>
            <h1>Phishing Autopsy</h1>
          </div>
          {results && (
            <div className={`score-ring ${scoreTone}`}>
              <span>{score?.final_score ?? results.ai?.threat_score ?? 0}</span>
              <small>/100</small>
            </div>
          )}
        </header>

        <section className="analysis-grid">
          <form className="input-panel" onSubmit={handleAnalyze}>
            <div className="panel-heading">
              <h2>Evidence Input</h2>
              <span>{file ? 'EML mode' : 'Manual mode'}</span>
            </div>

            <label className="drop-zone">
              <span className="drop-title">Upload raw .eml</span>
              <span className="drop-subtitle">{file ? file.name : 'No file selected'}</span>
              <input
                type="file"
                accept=".eml"
                onChange={(e) => setFile(e.target.files[0])}
              />
            </label>

            <div className="divider">or</div>

            <label className="field">
              <span>Claimed sender domain</span>
              <input
                type="text"
                value={senderDomain}
                onChange={(e) => setSenderDomain(e.target.value)}
                disabled={!!file}
                placeholder="example.com"
              />
            </label>

            <label className="field">
              <span>Email body</span>
              <textarea
                value={emailText}
                onChange={(e) => setEmailText(e.target.value)}
                disabled={!!file}
                rows="10"
                placeholder="Paste raw email text for direct analysis"
              />
            </label>

            {file && (
              <button className="ghost-button" type="button" onClick={() => setFile(null)}>
                Clear file
              </button>
            )}

            <button className="primary-button" type="submit" disabled={loading}>
              {loading ? 'Analyzing...' : 'Run Analysis'}
            </button>
          </form>

          <section className="dashboard">
            {!results && (
              <div className="placeholder">
                <h2>Analyst Console</h2>
                <p>Run an analysis to view model probability, authentication posture, link intelligence, language lures, and prioritized risk factors.</p>
              </div>
            )}

            {results && (
              <>
                <section className={`verdict-band ${scoreTone}`}>
                  <div>
                    <p className="eyebrow">Verdict</p>
                    <h2>{score?.verdict?.replace('_', ' ') ?? 'unknown'}</h2>
                    <p>{results.ai?.explanation ?? 'Analysis completed.'}</p>
                  </div>
                  <div className="score-breakdown">
                    <Metric label="Model probability" value={`${score?.model_probability ?? 0}%`} />
                    <Metric label="Heuristic points" value={score?.heuristic_points ?? 0} />
                    <Metric label="Risk factors" value={riskFactors.length} />
                  </div>
                </section>

                <section className="metrics-row">
                  <Metric label="Links" value={links?.total_links ?? 0} />
                  <Metric label="Suspicious links" value={links?.suspicious_count ?? 0} tone={(links?.suspicious_count ?? 0) ? 'critical' : 'calm'} />
                  <Metric label="Link domains" value={links?.unique_domains?.length ?? 0} />
                  <Metric label="Words analyzed" value={language?.word_count ?? 0} />
                </section>

                <section className="panel-grid">
                  <div className="panel">
                    <div className="panel-heading">
                      <h2>Authentication</h2>
                      <span>{results.extracted_domain || 'No domain'}</span>
                    </div>
                    {dns ? (
                      <div className="status-stack">
                        <StatusPill label="MX record" good={dns.mx_found} />
                        <StatusPill label="SPF record" good={dns.spf_found} />
                        <StatusPill label="DMARC record" good={dns.dmarc_found} />
                        <StatusPill label="Message-ID" good={header?.message_id_present} />
                      </div>
                    ) : (
                      <EmptyState text="No sender domain was available for DNS analysis." />
                    )}
                  </div>

                  <div className="panel">
                    <div className="panel-heading">
                      <h2>Header Signals</h2>
                      <span>{header?.received_count ?? 0} hops</span>
                    </div>
                    <dl className="kv-list">
                      <div><dt>From domain</dt><dd>{header?.from_domain || 'manual input'}</dd></div>
                      <div><dt>Reply-To</dt><dd>{header?.reply_to_domain || 'none'}</dd></div>
                      <div><dt>Return-Path</dt><dd>{header?.return_path_domain || 'none'}</dd></div>
                      <div><dt>Subject</dt><dd>{header?.subject || 'not available'}</dd></div>
                    </dl>
                  </div>
                </section>

                <section className="panel">
                  <div className="panel-heading">
                    <h2>Prioritized Risk Factors</h2>
                    <span>{riskFactors.length} findings</span>
                  </div>
                  {riskFactors.length ? (
                    <div className="finding-list">
                      {riskFactors.map((factor, index) => (
                        <article className={`finding ${factor.severity}`} key={`${factor.signal}-${index}`}>
                          <div>
                            <span className="finding-meta">{factor.category} / {factor.severity}</span>
                            <h3>{factor.signal}</h3>
                            <p>{factor.detail}</p>
                          </div>
                          <strong>+{factor.points}</strong>
                        </article>
                      ))}
                    </div>
                  ) : (
                    <EmptyState text="No heuristic risk factors were triggered." />
                  )}
                </section>

                <section className="panel-grid">
                  <div className="panel">
                    <div className="panel-heading">
                      <h2>URL Intelligence</h2>
                      <span>{links?.details?.length ?? 0} URLs</span>
                    </div>
                    {links?.details?.length ? (
                      <div className="url-list">
                        {links.details.map((link, index) => (
                          <article className={link.is_suspicious ? 'url-item flagged' : 'url-item'} key={`${link.url}-${index}`}>
                            <strong>{link.host || 'unknown host'}</strong>
                            <span>{link.url}</span>
                            <p>{link.reasons?.length ? link.reasons.join(', ') : 'No URL heuristic flags'}</p>
                          </article>
                        ))}
                      </div>
                    ) : (
                      <EmptyState text="No URLs were found in the message body." />
                    )}
                  </div>

                  <div className="panel">
                    <div className="panel-heading">
                      <h2>Language Signals</h2>
                      <span>{language?.keyword_hit_count ?? 0} hits</span>
                    </div>
                    {Object.keys(language?.keyword_hits ?? {}).length ? (
                      <div className="tag-cloud">
                        {Object.entries(language.keyword_hits).map(([category, hits]) => (
                          <div className="tag-group" key={category}>
                            <strong>{category}</strong>
                            <span>{hits.join(', ')}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <EmptyState text="No configured lure-language keywords were matched." />
                    )}
                  </div>
                </section>
              </>
            )}
          </section>
        </section>
      </section>
    </main>
  )
}

export default App
