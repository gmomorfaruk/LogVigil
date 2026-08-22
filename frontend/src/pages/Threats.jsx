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

  const renderActionDetails = (actionType, payload) => {
    if (actionType === 'FIREWALL_BLOCK') {
      return (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '8px' }}>
          <span style={{ backgroundColor: 'rgba(255, 85, 85, 0.15)', border: '1px solid rgba(255, 85, 85, 0.35)', color: '#ff7777', padding: '4px 10px', borderRadius: '4px', fontSize: '0.8rem', fontWeight: 'bold' }}>
            ⛔ ACTION: BLOCK TRAFFIC
          </span>
          {payload.ip && (
            <span style={{ backgroundColor: 'rgba(0, 240, 255, 0.1)', border: '1px solid rgba(0, 240, 255, 0.25)', color: '#00f0ff', padding: '4px 10px', borderRadius: '4px', fontSize: '0.8rem', fontFamily: 'monospace' }}>
              🎯 TARGET IP: {payload.ip}
            </span>
          )}
          <span style={{ backgroundColor: 'rgba(255, 255, 255, 0.05)', border: '1px solid rgba(255, 255, 255, 0.15)', color: '#cbd5e1', padding: '4px 10px', borderRadius: '4px', fontSize: '0.8rem' }}>
            🧭 DIRECTION: {payload.direction || 'OUTBOUND'}
          </span>
        </div>
      );
    }

    if (actionType === 'FIREWALL_ENABLE') {
      return (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '8px' }}>
          <span style={{ backgroundColor: 'rgba(0, 255, 136, 0.15)', border: '1px solid rgba(0, 255, 136, 0.35)', color: '#00ff88', padding: '4px 10px', borderRadius: '4px', fontSize: '0.8rem', fontWeight: 'bold' }}>
            🧱 ACTION: ACTIVATE FIREWALL SHIELD
          </span>
          <span style={{ backgroundColor: 'rgba(255, 255, 255, 0.05)', border: '1px solid rgba(255, 255, 255, 0.15)', color: '#cbd5e1', padding: '4px 10px', borderRadius: '4px', fontSize: '0.8rem' }}>
            🛡️ ENFORCEMENT: Enable packet filter & port monitoring
          </span>
        </div>
      );
    }

    // Generic fallback for any other action
    const keys = Object.keys(payload || {});
    if (keys.length === 0) {
      return (
        <div style={{ marginTop: '8px', color: '#94a3b8', fontSize: '0.8rem' }}>
          Action Type: <strong style={{ color: '#00f0ff' }}>{actionType}</strong>
        </div>
      );
    }

    return (
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '8px' }}>
        <span style={{ backgroundColor: 'rgba(0, 240, 255, 0.1)', border: '1px solid rgba(0, 240, 255, 0.25)', color: '#00f0ff', padding: '4px 10px', borderRadius: '4px', fontSize: '0.8rem' }}>
          {actionType}
        </span>
        {keys.map((k) => (
          <span key={k} style={{ backgroundColor: 'rgba(255, 255, 255, 0.05)', border: '1px solid rgba(255, 255, 255, 0.15)', color: '#cbd5e1', padding: '4px 10px', borderRadius: '4px', fontSize: '0.8rem', fontFamily: 'monospace' }}>
            {k}: {String(payload[k])}
          </span>
        ))}
      </div>
    );
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
              <div key={rec.id} className={`recommendation-item ${rec.status === 'RESOLVED' ? 'resolved' : ''}`} style={{ padding: '18px 20px', borderRadius: '8px' }}>
                <div className="rec-header" style={{ marginBottom: '10px' }}>
                  <div className="rec-title-block">
                    <h3 style={{ fontSize: '1.05rem', color: '#f8fafc', fontWeight: '700', marginBottom: '4px' }}>{rec.title}</h3>
                    <span className="rec-threat-link" style={{ fontSize: '0.82rem', color: '#94a3b8' }}>
                      Linked alert source: <code style={{ color: '#38bdf8', backgroundColor: 'rgba(0, 240, 255, 0.1)', padding: '2px 6px', borderRadius: '3px' }}>{rec.threat_id}</code>
                    </span>
                  </div>
                  <span className={`status-badge ${rec.status.toLowerCase()}`} style={{ fontSize: '0.75rem', fontWeight: 'bold', letterSpacing: '0.5px' }}>
                    {rec.status}
                  </span>
                </div>

                <p className="rec-description" style={{ fontSize: '0.92rem', color: '#cbd5e1', lineHeight: '1.5', marginBottom: '12px' }}>
                  {rec.description}
                </p>

                <div className="rec-payload-box" style={{ padding: '10px 14px', backgroundColor: 'rgba(0, 15, 30, 0.6)', border: '1px solid rgba(0, 240, 255, 0.15)', borderRadius: '6px', marginBottom: '14px' }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: 'bold', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    Remediation Policy Directive
                  </div>
                  {renderActionDetails(rec.action_type, rec.action_payload)}
                </div>

                {rec.status === 'PENDING' && (
                  <button
                    className="cyber-btn rec-apply-btn"
                    onClick={() => handleApplyAction(rec.id, rec.title)}
                    style={{ fontSize: '0.85rem', padding: '8px 16px' }}
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

