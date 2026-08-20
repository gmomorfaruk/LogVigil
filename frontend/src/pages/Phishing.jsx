import React, { useState } from 'react';

function Phishing({ addLog }) {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [phError, setPhError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleScan = async (e) => {
    e.preventDefault();
    setPhError('');
    setResult(null);
    setLoading(true);

    try {
      const res = await fetch('http://localhost:8000/api/phishing/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Analysis failed');
      }

      setResult(data);
      addLog(`Phishing scan completed on URL: ${url}. Rating: ${data.safety_score}% (${data.risk_level})`, data.risk_level === 'HIGH' ? 'error' : 'success');
    } catch (err) {
      setPhError(err.message);
      addLog(`Phishing check failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="phishing-container">
      <h2 className="section-title">🎣 URL Phishing & Squatting inspector</h2>
      <p className="section-description">
        Scan URLs to analyze typosquatting vectors, domain blacklists, SSL configuration, and phishing indicators before navigating.
      </p>

      {phError && <div className="auth-alert" style={{ marginBottom: '15px' }}>{phError}</div>}

      <div className="phishing-grid-layout">
        {/* Scanner Bar Widget */}
        <div className="cyber-widget scanner-input-card">
          <div className="widget-title">
            <span>INPUT URL TELEMETRY CHANNEL</span>
          </div>
          <form onSubmit={handleScan} className="scan-form">
            <div className="scan-input-group">
              <input
                type="text"
                className="cyber-input scan-input"
                placeholder="https://example-banking.com/login"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
              />
              <button type="submit" className="cyber-btn scan-submit-btn" disabled={loading}>
                {loading ? 'ANALYZING...' : 'RUN INSPECTOR'}
              </button>
            </div>
            <span className="input-hint">
              Test queries: <code>http://goog1e-login.com</code> or <code>https://google.com</code>
            </span>
          </form>
        </div>

        {/* Scan Results Panel */}
        {result && (
          <div className="cyber-widget scan-results-card">
            <div className="widget-title">
              <span>SCAN TARGET: {result.url}</span>
              <span className={`risk-badge ${result.risk_level.toLowerCase()}`}>
                {result.risk_level} RISK
              </span>
            </div>

            <div className="scan-results-flex">
              {/* Score panel */}
              <div className="scan-score-gauge">
                <span className={`large-score ${result.safety_score >= 80 ? 'green' : result.safety_score >= 50 ? 'amber' : 'red'}`}>
                  {result.safety_score}%
                </span>
                <span className="score-lbl">SAFETY INDEX SCORE</span>
              </div>

              {/* Checks checklist */}
              <div className="scan-checks-checklist">
                <h3>Heuristics Engine Checklist Output:</h3>
                <ul className="checklist">
                  <li className={result.details.https_enabled ? 'pass' : 'fail'}>
                    <span className="chk-icon">{result.details.https_enabled ? '✓' : '✗'}</span>
                    Secure SSL Connection (HTTPS)
                  </li>
                  <li className={!result.details.on_blacklist ? 'pass' : 'fail'}>
                    <span className="chk-icon">{!result.details.on_blacklist ? '✓' : '✗'}</span>
                    Domain Blacklist Absence check
                  </li>
                  <li className={!result.details.typosquatting_detected ? 'pass' : 'fail'}>
                    <span className="chk-icon">{!result.details.typosquatting_detected ? '✓' : '✗'}</span>
                    Domain Typosquatting / Spoofing check
                  </li>
                  <li className={!result.details.ip_address_url ? 'pass' : 'fail'}>
                    <span className="chk-icon">{!result.details.ip_address_url ? '✓' : '✗'}</span>
                    IP Address domain mask check
                  </li>
                  <li className={!result.details.suspicious_keywords ? 'pass' : 'fail'}>
                    <span className="chk-icon">{!result.details.suspicious_keywords ? '✓' : '✗'}</span>
                    Suspicious keyword scan (login, verify, banking)
                  </li>
                </ul>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Phishing;
