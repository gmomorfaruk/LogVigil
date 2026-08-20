import React, { useState, useEffect } from 'react';

function Firewall({ addLog }) {
  const [enabled, setEnabled] = useState(false);
  const [rules, setRules] = useState([]);
  const [protocol, setProtocol] = useState('TCP');
  const [port, setPort] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [action, setAction] = useState('ALLOW');
  const [direction, setDirection] = useState('INBOUND');
  const [description, setDescription] = useState('');
  const [fwError, setFwError] = useState('');
  const [fwSuccess, setFwSuccess] = useState('');

  useEffect(() => {
    fetchStatus();
    fetchRules();
  }, []);

  const fetchStatus = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/firewall/status');
      const data = await res.json();
      setEnabled(data.enabled);
    } catch (err) {}
  };

  const fetchRules = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/firewall/rules');
      const data = await res.json();
      setRules(data);
    } catch (err) {}
  };

  const handleToggle = async () => {
    setFwError('');
    setFwSuccess('');
    const targetState = !enabled;

    try {
      const res = await fetch('http://localhost:8000/api/firewall/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enable: targetState })
      });
      const data = await res.json();
      setEnabled(data.enabled);
      const msg = data.message || `Firewall ${data.enabled ? 'ENABLED' : 'DISABLED'} successfully.`;
      setFwSuccess(msg);
      addLog(`Firewall interface toggled: ${data.enabled ? 'ACTIVE' : 'INACTIVE'}`, data.enabled ? 'success' : 'warn');
    } catch (err) {
      setFwError('Failed to toggle firewall state');
    }
  };

  const handleAddRule = async (e) => {
    e.preventDefault();
    setFwError('');
    setFwSuccess('');

    try {
      const res = await fetch('http://localhost:8000/api/firewall/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          protocol,
          port: parseInt(port),
          action,
          direction,
          description,
          ip_address: ipAddress.trim() || undefined
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Failed to create firewall rule');
      }

      setFwSuccess(data.applied_to_system ? 'Firewall rule applied to OS kernel successfully.' : 'Firewall rule saved to LogVigil database.');
      addLog(`New firewall rule appended: ${action} ${protocol}:${port}${ipAddress ? ' [' + ipAddress + ']' : ''} (${description})`, 'success');
      setPort('');
      setIpAddress('');
      setDescription('');
      fetchRules();
    } catch (err) {
      setFwError(err.message);
      addLog(`Failed to append rule: ${err.message}`, 'error');
    }
  };

  const handleDeleteRule = async (ruleId) => {
    setFwError('');
    setFwSuccess('');

    try {
      const res = await fetch(`http://localhost:8000/api/firewall/rules/${ruleId}`, {
        method: 'DELETE'
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Failed to delete rule');
      }

      setFwSuccess(data.message);
      addLog(`Firewall rule deleted: ${ruleId}`, 'warn');
      fetchRules();
    } catch (err) {
      setFwError(err.message);
      addLog(`Failed to delete rule: ${err.message}`, 'error');
    }
  };

  return (
    <div className="firewall-container">
      <h2 className="section-title">🧱 Core Firewall rules manager</h2>
      <p className="section-description">
        Manage active network filters, block malicious ports/IPs, and control incoming and outgoing network traffic routes.
      </p>

      {fwError && <div className="auth-alert" style={{ marginBottom: '15px' }}>{fwError}</div>}
      {fwSuccess && <div className="auth-success" style={{ marginBottom: '15px' }}>{fwSuccess}</div>}

      <div className="firewall-grid-layout">
        {/* Toggle switch panel */}
        <div className="cyber-widget firewall-toggle-card">
          <div className="widget-title">
            <span>INTERFACE CONTROLLERS</span>
          </div>
          <div className="toggle-row">
            <div className="toggle-info">
              <h3>Firewall Protection Shield</h3>
              <p>Active routing filters: {enabled ? 'ON' : 'OFF'}</p>
            </div>
            <button
              className={`cyber-btn toggle-btn ${enabled ? 'active-glow' : 'inactive-glow'}`}
              onClick={handleToggle}
            >
              {enabled ? 'SHUT DOWN FILTER' : 'BOOT FILTER'}
            </button>
          </div>
        </div>

        {/* Form and Rules List splits */}
        <div className="vault-grid">
          {/* Create Rule Form */}
          <div className="cyber-widget add-rule-card">
            <div className="widget-title">
              <span>APPEND FILTER RULE</span>
            </div>
            <form onSubmit={handleAddRule} className="rule-form">
              <div className="form-group">
                <label className="form-label">Protocol</label>
                <select className="cyber-input select-input" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="ICMP">ICMP</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Port</label>
                <input
                  type="number"
                  className="cyber-input"
                  placeholder="e.g. 443, 8080"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  min={1}
                  max={65535}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Target IP (Optional)</label>
                <input
                  type="text"
                  className="cyber-input"
                  placeholder="e.g. 192.168.1.50 or any"
                  value={ipAddress}
                  onChange={(e) => setIpAddress(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label className="form-label">Traffic Direction</label>
                <select className="cyber-input select-input" value={direction} onChange={(e) => setDirection(e.target.value)}>
                  <option value="INBOUND">INBOUND</option>
                  <option value="OUTBOUND">OUTBOUND</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Policy Action</label>
                <select className="cyber-input select-input" value={action} onChange={(e) => setAction(e.target.value)}>
                  <option value="ALLOW">ALLOW</option>
                  <option value="BLOCK">BLOCK</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Rule Description</label>
                <input
                  type="text"
                  className="cyber-input"
                  placeholder="Traffic profile identifier..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  maxLength={100}
                  required
                />
              </div>

              <button type="submit" className="cyber-btn rule-btn">
                ➕ APPEND POLICY RULE
              </button>
            </form>
          </div>

          {/* Active Rules List */}
          <div className="cyber-widget active-rules-card">
            <div className="widget-title">
              <span>ACTIVE POLICIES INDEX</span>
              <span>{rules.length} RULES LOADED</span>
            </div>

            <div className="rules-table-container">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>RULE PROFILE</th>
                    <th>TARGET IP</th>
                    <th>DIR</th>
                    <th>POLICY</th>
                    <th>DESCRIPTION</th>
                    <th>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((rule) => (
                    <tr key={rule.id}>
                      <td><code>{rule.id}</code></td>
                      <td>
                        <span className="protocol-badge">{rule.protocol}</span>
                        <span className="port-badge">:{rule.port}</span>
                      </td>
                      <td>
                        <span style={{ fontSize: '0.85rem', color: rule.ip_address ? 'var(--neon-cyan)' : 'var(--text-muted)' }}>
                          {rule.ip_address || 'ANY'}
                        </span>
                      </td>
                      <td>{rule.direction}</td>
                      <td>
                        <span className={`action-badge ${rule.action === 'ALLOW' ? 'allow' : 'block'}`}>
                          {rule.action}
                        </span>
                      </td>
                      <td>{rule.description}</td>
                      <td>
                        <button
                          className="cyber-table-btn delete-btn"
                          onClick={() => handleDeleteRule(rule.id)}
                        >
                          DELETE
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Firewall;
