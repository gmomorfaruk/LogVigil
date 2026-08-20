import React, { useState, useEffect } from 'react';

function Network({ addLog }) {
  const [active, setActive] = useState(false);
  const [iface, setIface] = useState('eth0');
  const [alerts, setAlerts] = useState([]);
  const [netError, setNetError] = useState('');
  const [netSuccess, setNetSuccess] = useState('');

  useEffect(() => {
    fetchStatus();
    fetchAlerts();
  }, []);

  const fetchStatus = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/network/status');
      const data = await res.json();
      setActive(data.active);
      setIface(data.interface);
    } catch (err) {}
  };

  const fetchAlerts = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/network/alerts');
      const data = await res.json();
      setAlerts(data);
    } catch (err) {}
  };

  const handleToggle = async () => {
    setNetError('');
    setNetSuccess('');
    const targetState = !active;

    try {
      const res = await fetch('http://localhost:8000/api/network/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: targetState })
      });
      const data = await res.json();
      setActive(data.active);
      setNetSuccess(`Network parser ${data.active ? 'STARTED' : 'STOPPED'} successfully.`);
      addLog(`Suricata Network engine: ${data.active ? 'RUNNING' : 'STOPPED'} on interface ${data.interface}`, data.active ? 'success' : 'warn');
    } catch (err) {
      setNetError('Failed to toggle network parser state');
    }
  };

  return (
    <div className="network-container">
      <h2 className="section-title">📡 Live Network Packet telemetry</h2>
      <p className="section-description">
        Observe incoming and outgoing packet headers. LogVigil integrates Suricata intrusion detection logging to parse and flags SQL injections, scanning, and bad user agents.
      </p>

      {netError && <div className="auth-alert" style={{ marginBottom: '15px' }}>{netError}</div>}
      {netSuccess && <div className="auth-success" style={{ marginBottom: '15px' }}>{netSuccess}</div>}

      <div className="network-grid-layout">
        {/* Toggle Switch */}
        <div className="cyber-widget network-toggle-card">
          <div className="widget-title">
            <span>SURICATA DAEMON SYSTEM STATUS</span>
          </div>
          <div className="toggle-row">
            <div className="toggle-info">
              <h3>Live Packet Parser Daemon</h3>
              <p>Interface Listener: <code>{iface}</code> | Daemon status: {active ? 'MONITORING' : 'OFFLINE'}</p>
            </div>
            <button
              className={`cyber-btn toggle-btn ${active ? 'active-glow' : 'inactive-glow'}`}
              onClick={handleToggle}
            >
              {active ? 'SUSPEND CAPTURE' : 'LAUNCH CAPTURE'}
            </button>
          </div>
        </div>

        {/* Live Alerts list */}
        <div className="cyber-widget network-alerts-card">
          <div className="widget-title">
            <span>SURICATA PARSED ALERTS LOGS</span>
            <span className="glow-cyan">{alerts.length} ALERTS CACHED</span>
          </div>

          <div className="network-table-container">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>TIMESTAMP</th>
                  <th>IP ROUTE</th>
                  <th>CLASSIFICATION</th>
                  <th>THREAT MSG</th>
                  <th>SEVERITY</th>
                  <th>SNIPPET</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td><code>{new Date(alert.timestamp).toLocaleTimeString()}</code></td>
                    <td>
                      <div className="route-cell">
                        <span>{alert.source_ip}</span>
                        <span className="route-arrow">➔</span>
                        <span>{alert.dest_ip}</span>
                      </div>
                    </td>
                    <td>{alert.category}</td>
                    <td>{alert.message}</td>
                    <td>
                      <span className={`risk-badge ${alert.risk_level.toLowerCase()}`}>
                        {alert.risk_level}
                      </span>
                    </td>
                    <td>
                      <code className="payload-snippet">{alert.payload_snippet}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Network;
