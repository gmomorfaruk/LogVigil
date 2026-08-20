import React, { useState, useEffect } from 'react';

function Threats({ addLog }) {
  const [summary, setSummary] = useState({ overall_risk: 'LOW', total_alerts: 0, active_threats: 0 });
  const [recommendations, setRecommendations] = useState([]);
  const [thError, setThError] = useState('');
  const [thSuccess, setThSuccess] = useState('');

  useEffect(() => {
    fetchSummary();
    fetchRecommendations();
  }, []);

  const fetchSummary = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/alerts/summary');
      const data = await res.json();
      setSummary(data);
    } catch (err) {}
  };

  const fetchRecommendations = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/alerts/recommendations');
      const data = await res.json();
      setRecommendations(data);
    } catch (err) {}
  };

  const handleApplyAction = async (recId, title) => {
    setThError('');
    setThSuccess('');
    try {
      const res = await fetch(`http://localhost:8000/api/alerts/recommendations/${recId}/apply`, {
        method: 'POST'
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Failed to apply recommendation');
      }
      setRecommendations((prev) =>
        prev.map((r) => (r.id === recId ? { ...r, status: 'RESOLVED' } : r))
      );
      setThSuccess(`Recommendation applied successfully: ${title}`);
      addLog(`Threat Engine remedy applied: ${title}`, 'success');
      fetchSummary();
    } catch (err) {
      setThError(err.message || 'Failed to apply recommendation');
      addLog(`Failed to apply remedy: ${err.message}`, 'error');
    }
  };

  const handleResolveAll = async () => {
    setThError('');
    setThSuccess('');
    try {
      const res = await fetch('http://localhost:8000/api/alerts/recommendations/resolve-all', {
        method: 'POST'
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Failed to resolve all recommendations');
      }
      setRecommendations((prev) =>
        prev.map((r) => ({ ...r, status: 'RESOLVED' }))
      );
      setThSuccess('All recommendations resolved successfully');
      addLog('Threat Engine: All pending remedies resolved in bulk', 'success');
      fetchSummary();
    } catch (err) {
      setThError(err.message || 'Failed to resolve all recommendations');
      addLog(`Failed to resolve all: ${err.message}`, 'error');
    }
  };

  return (
    <div className="threats-container">
      <h2 className="section-title">⚠️ Cyber Threat Decision Engine</h2>
      <p className="section-description">
        Analyze real-time events and packet telemetry. The engine correlates network alerts with local system states to generate recommendations.
      </p>

      {thError && <div className="auth-alert" style={{ marginBottom: '15px' }}>{thError}</div>}
      {thSuccess && <div className="auth-success" style={{ marginBottom: '15px' }}>{thSuccess}</div>}

      {/* Stats Summary Blocks */}
      <div className="threat-summary-row">
        <div className="cyber-widget threat-sum-card">
          <span className="card-lbl">OVERALL THREAT EVALUATION</span>
          <h2 className={`risk-glow-${summary.overall_risk.toLowerCase()}`}>
            {summary.overall_risk}
          </h2>
        </div>

        <div className="cyber-widget threat-sum-card">
          <span className="card-lbl">ACTIVE EVENT INCIDENTS</span>
          <h2 className="glow-cyan">{summary.total_alerts}</h2>
        </div>

        <div className="cyber-widget threat-sum-card">
          <span className="card-lbl">UNRESOLVED THREATS</span>
          <h2 className="glow-red">{summary.active_threats}</h2>
        </div>
      </div>

      {/* Recommendations Feed Section */}
      <div className="cyber-widget recommendations-card">
        <div className="widget-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <span>RECOMMENDED REMEDIATION ACTIONS DIRECTIVES</span>
            <span style={{ marginLeft: '15px' }} className="glow-cyan">{recommendations.filter(r => r.status === 'PENDING').length} PENDING</span>
          </div>
          {recommendations.some(r => r.status === 'PENDING') && (
            <button 
              className="cyber-btn" 
              onClick={handleResolveAll}
              style={{ fontSize: '11px', padding: '4px 10px', height: 'auto', minWidth: 'auto' }}
            >
              ⚡ RESOLVE ALL
            </button>
          )}
        </div>

        {recommendations.length === 0 ? (
          <div className="recs-empty-placeholder">
            <p>No active threats detected. System is clean and running within optimal bounds.</p>
          </div>
        ) : (
          <div className="recommendations-list">
            {recommendations.map((rec) => (
              <div key={rec.id} className={`recommendation-item ${rec.status === 'RESOLVED' ? 'resolved' : ''}`}>
                <div className="rec-header">
                  <div className="rec-title-block">
                    <h3>{rec.title}</h3>
                    <span className="rec-threat-link">Linked alert: <code>{rec.threat_id}</code></span>
                  </div>
                  <span className={`status-badge ${rec.status.toLowerCase()}`}>
                    {rec.status}
                  </span>
                </div>
                <p className="rec-description">{rec.description}</p>
                <div className="rec-payload-box">
                  <strong>ACTION POLICY SPECIFICATION:</strong>
                  <code>{JSON.stringify(rec.action_payload)}</code>
                </div>
                {rec.status === 'PENDING' && (
                  <button
                    className="cyber-btn rec-apply-btn"
                    onClick={() => handleApplyAction(rec.id, rec.title)}
                  >
                    ⚡ DEPLOY COUNTERMEASURE
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default Threats;
