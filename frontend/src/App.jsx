import { useState } from 'react'
import axios from 'axios'
import './App.css'

function App() {
  const [emailText, setEmailText] = useState('')
  const [senderDomain, setSenderDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)
  const [file, setFile] = useState(null)

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

      const response = await axios.post('http://127.0.0.1:5000/api/analyze', formData)

      setResults({
        dns: response.data.dns_analysis,
        domain: response.data.extracted_domain || senderDomain,
        ai: response.data.ai_analysis
      })
    } catch (error) {
      console.error('Error:', error)
      alert('Failed to analyze. Check backend.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto', padding: '20px', fontFamily: 'sans-serif' }}>
      <h1>Phishing Autopsy Sandbox</h1>
      <p>Paste a suspicious email below to analyze its threat level.</p>
      <p>Upload a raw <b>.eml</b> file, or paste text below.</p>

      <form onSubmit={handleAnalyze} style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
        <div style={{ padding: '20px', border: '2px dashed #666', borderRadius: '8px', textAlign: 'center', backgroundColor: '#222' }}>
          <label style={{ cursor: 'pointer', color: '#4da6ff', fontWeight: 'bold' }}>
            Click here to upload a .eml file
            <input
              type="file"
              accept=".eml"
              onChange={(e) => setFile(e.target.files[0])}
              style={{ display: 'none' }}
            />
          </label>
          {file && <p style={{ color: '#4caf50', marginTop: '10px' }}>Selected: {file.name}</p>}
        </div>

        <div style={{ textAlign: 'center' }}><strong>OR MANUAL ENTRY</strong></div>

        <div>
          <label>Claimed Sender Domain:</label><br />
          <input type="text" value={senderDomain} onChange={(e) => setSenderDomain(e.target.value)} disabled={!!file} placeholder="e.g., hdfcbank.com" style={{ width: '100%', padding: '10px' }} />
        </div>

        <div>
          <label>Raw Email Text:</label><br />
          <textarea value={emailText} onChange={(e) => setEmailText(e.target.value)} disabled={!!file} rows="5" placeholder="Paste email body..." style={{ width: '100%', padding: '10px' }} />
        </div>

        <button type="submit" disabled={loading} style={{ padding: '12px', backgroundColor: '#0056b3', color: 'white', cursor: 'pointer', fontSize: '16px', fontWeight: 'bold' }}>
          {loading ? 'Analyzing...' : 'Analyze Email'}
        </button>
      </form>

      {results && (
        <div style={{ marginTop: '30px', padding: '20px', border: '2px solid #ddd', borderRadius: '8px' }}>
          <h2>Analysis Results</h2>

          <div style={{
            padding: '15px',
            backgroundColor: results.ai.is_phishing ? '#ffebee' : '#e8f5e9',
            color: results.ai.is_phishing ? '#c62828' : '#2e7d32',
            borderRadius: '5px',
            marginBottom: '20px'
          }}>
            <h3 style={{ margin: 0 }}>Threat Score: {results.ai.threat_score}/100</h3>
            <p><strong>Verdict:</strong> {results.ai.is_phishing ? 'HIGH RISK - PHISHING DETECTED' : 'SAFE - NO THREAT DETECTED'}</p>
            <p><strong>AI Explanation:</strong> {results.ai.explanation}</p>
          </div>

          {results.ai.suspicious_links.length > 0 && (
            <div>
              <h3>Suspicious Links Found:</h3>
              <ul>
                {results.ai.suspicious_links.map((link, index) => (
                  <li key={index} style={{ color: 'red', wordBreak: 'break-all' }}>
                    {link.url}
                    {link.reasons?.length > 0 && (
                      <span style={{ color: '#6b0000' }}> ({link.reasons.join(', ')})</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {results.dns && (
            <div style={{ marginTop: '20px', padding: '15px', backgroundColor: '#f5f5f5', borderRadius: '5px' }}>
              <h3>Technical Header Verification ({results.domain || senderDomain}):</h3>
              <p>
                <strong>MX Records (Can receive mail?):</strong> {results.dns.mx_found ? 'Pass' : 'Fail (Suspicious)'}
              </p>
              <p>
                <strong>SPF Sender Policy:</strong> {results.dns.spf_found ? 'Pass' : 'Fail (No SPF record)'}
              </p>
              <p>
                <strong>DMARC Security Policy:</strong> {results.dns.dmarc_found ? 'Pass' : 'Fail (Unprotected Domain)'}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default App
