import React, { useState, useEffect } from 'react';

function Timeline({ addLog }) {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [tlError, setTlError] = useState('');

  const fetchTimeline = async () => {
    setLoading(true);
    setTlError('');
    try {
      const res = await fetch('http://localhost:8000/api/timeline');
      if (!res.ok) {
        throw new Error(`HTTP Error ${res.status}`);
      }
      const data = await res.json();
      setEvents(data);
    } catch (err) {
      setTlError(`Failed to fetch timeline: ${err.message}`);
      addLog(`Timeline fetch error: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTimeline();
  }, []);

  const getEventIcon = (type) => {
    switch (type) {
      case 'FIREWALL':
        return '🧱';
      case 'VAULT':
        return '🔒';
      case 'INTEGRITY':
        return '🔎';
      case 'NETWORK':
        return '📡';
      case 'SYSTEM':
      default:
        return '⚙️';
    }
  };

  const getSeverityClass = (sev) => {
    const s = sev.toUpperCase();
    if (s === 'HIGH' || s === 'ERROR' || s === 'CRITICAL') return 'risk-badge high';
    if (s === 'MEDIUM' || s === 'WARNING' || s === 'WARN') return 'risk-badge medium';
    return 'risk-badge low';
  };

  return (
    <div className="timeline-container">
      <div className="overview-header-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 className="section-title">🕒 Real-Time Security Incident Timeline</h2>
          <p className="section-description">
            Audit trailing of system, firewall, network, integrity, and vault actions in exact chronological sequence.
          </p>
        </div>
        <button className="cyber-btn" onClick={fetchTimeline} disabled={loading} style={{ height: 'fit-content' }}>
          {loading ? 'SYNCHRONIZING...' : '⚡ REFRESH EVENT STREAM'}
        </button>
      </div>

      {tlError && <div className="auth-alert" style={{ marginBottom: '15px' }}>{tlError}</div>}

      <div className="cyber-widget timeline-list-card" style={{ padding: '20px' }}>
        <div className="widget-title" style={{ marginBottom: '20px', display: 'flex', justifyContent: 'space-between' }}>
          <span>CHRONOLOGICAL ACTIVITY TRAIL</span>
          <span className="glow-cyan">{events.length} EVENTS REGISTERED</span>
        </div>

        {events.length === 0 ? (
          <div className="recs-empty-placeholder" style={{ padding: '40px', textAlign: 'center' }}>
            <p>No logged events found in system registers. Trigger actions to populate telemetry trail.</p>
          </div>
        ) : (
          <div className="timeline-trail" style={{ position: 'relative', paddingLeft: '20px', borderLeft: '2px solid var(--neon-cyan, #00f0ff)' }}>
            {events.map((event) => (
              <div 
                key={event.id} 
                className="timeline-event-item" 
                style={{ 
                  position: 'relative', 
                  marginBottom: '25px', 
                  backgroundColor: 'rgba(10, 25, 50, 0.4)', 
                  border: '1px solid rgba(0, 240, 255, 0.2)', 
                  borderRadius: '6px', 
                  padding: '15px',
                  boxShadow: '0 0 10px rgba(0, 240, 255, 0.05)'
                }}
              >
                {/* Visual marker dot on the timeline line */}
                <span 
                  className="timeline-marker" 
                  style={{ 
                    position: 'absolute', 
                    left: '-28px', 
                    top: '20px', 
                    width: '14px', 
                    height: '14px', 
                    borderRadius: '50%', 
                    backgroundColor: 'var(--dark-bg, #040814)', 
                    border: '3px solid var(--neon-cyan, #00f0ff)',
                    boxShadow: '0 0 8px var(--neon-cyan, #00f0ff)',
                    display: 'inline-block'
                  }}
                />

                <div className="event-meta" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap', gap: '10px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '1.2rem' }}>{getEventIcon(event.event_type)}</span>
                    <span className="protocol-badge" style={{ textTransform: 'uppercase', fontSize: '0.8rem', padding: '2px 8px', borderRadius: '4px', backgroundColor: 'rgba(0, 240, 255, 0.1)', color: 'var(--neon-cyan, #00f0ff)' }}>
                      {event.event_type}
                    </span>
                    <span className={getSeverityClass(event.severity)} style={{ fontSize: '0.75rem' }}>
                      {event.severity}
                    </span>
                  </div>
                  <code style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.6)' }}>
                    {new Date(event.timestamp).toLocaleString()}
                  </code>
                </div>

                <p className="event-message" style={{ margin: 0, fontSize: '0.95rem', color: '#e2e8f0', fontFamily: 'monospace' }}>
                  {event.message}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default Timeline;
