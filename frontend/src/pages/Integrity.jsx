import React, { useState, useEffect } from 'react';

function Integrity({ addLog }) {
  const [folders, setFolders] = useState([]);
  const [newFolder, setNewFolder] = useState('');
  const [alerts, setAlerts] = useState([]);
  const [intError, setIntError] = useState('');
  const [intSuccess, setIntSuccess] = useState('');
  const [protectedCount, setProtectedCount] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  useEffect(() => {
    fetchStatus();
    fetchAlerts();
  }, []);

  const fetchStatus = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/integrity/status');
      const data = await res.json();
      setFolders(data.monitored_folders);
      setProtectedCount(data.protected_files_count);
    } catch (err) {}
  };

  const fetchAlerts = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/integrity/alerts');
      const data = await res.json();
      setAlerts(data);
    } catch (err) {}
  };

  const handleAddFolder = async (e) => {
    e.preventDefault();
    setIntError('');
    setIntSuccess('');
    setScanResult(null);

    try {
      const res = await fetch('http://localhost:8000/api/integrity/monitor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ folder_path: newFolder })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Failed to monitor path');
      }

      setIntSuccess(data.message);
      addLog(`Added folder path to file integrity monitor: ${newFolder}`, 'success');
      setNewFolder('');
      fetchStatus();
    } catch (err) {
      setIntError(err.message);
      addLog(`Integrity Monitor error: ${err.message}`, 'error');
    }
  };

  const handleRemoveFolder = async (folderPath) => {
    setIntError('');
    setIntSuccess('');

    try {
      const res = await fetch('http://localhost:8000/api/integrity/monitor', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ folder_path: folderPath })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Failed to remove folder');
      }

      setIntSuccess(data.message);
      addLog(`Removed folder from integrity monitor: ${folderPath}`, 'success');
      fetchStatus();
    } catch (err) {
      setIntError(err.message);
      addLog(`Integrity Monitor error: ${err.message}`, 'error');
    }
  };

  const handleScan = async () => {
    setScanning(true);
    setIntError('');
    setIntSuccess('');
    setScanResult(null);
    addLog('Initiating integrity scan across all monitored directories...', 'info');

    try {
      const res = await fetch('http://localhost:8000/api/integrity/scan', {
        method: 'POST'
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Scan failed');
      }

      setScanResult(data);
      setIntSuccess(data.message);
      addLog(`Integrity scan complete: ${data.scanned_files} files scanned, ${data.new_alerts} discrepancies found`, data.new_alerts > 0 ? 'warn' : 'success');
      fetchStatus();
      fetchAlerts();
    } catch (err) {
      setIntError(err.message);
      addLog(`Integrity scan error: ${err.message}`, 'error');
    } finally {
      setScanning(false);
    }
  };

  const handleClearAlerts = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/integrity/alerts', {
        method: 'DELETE'
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to clear alerts');

      setAlerts([]);
      setScanResult(null);
      addLog('Integrity alerts cleared', 'success');
    } catch (err) {
      addLog(`Error clearing alerts: ${err.message}`, 'error');
    }
  };

  const getAlertBadgeClass = (alertType) => {
    switch (alertType) {
      case 'MODIFIED': return 'red-badge';
      case 'DELETED': return 'orange-badge';
      case 'NEW': return 'blue-badge';
      default: return 'red-badge';
    }
  };

  return (
    <div className="integrity-container">
      <h2 className="section-title">🔎 File Integrity monitoring engine</h2>
      <p className="section-description">
        Observe local folders for unauthorized file edits, deletions, or new creations. LogVigil computes real-time SHA-256 hashes and compares them to check directory structures.
      </p>

      {intError && <div className="auth-alert" style={{ marginBottom: '15px' }}>{intError}</div>}
      {intSuccess && <div className="auth-success" style={{ marginBottom: '15px' }}>{intSuccess}</div>}

      <div className="integrity-grid">
        {/* Row 1, Col 1: Summary Status Widget */}
        <div className="cyber-widget integrity-summary-card">
          <div className="widget-title">
            <span>PROTECTION STATUS</span>
          </div>
          <div className="status-flex">
            <div className="score-flex-item cyan-metric">
              <span className="info-number glow-cyan">{protectedCount}</span>
              <span className="info-label">BASELINED FILES</span>
            </div>
            <div className={`score-flex-item ${alerts.length > 0 ? 'red-metric' : 'green-metric'}`}>
              <span className={`info-number ${alerts.length > 0 ? 'glow-red' : 'glow-green'}`}>
                {alerts.length}
              </span>
              <span className="info-label">INTEGRITY ALERTS</span>
            </div>
          </div>

          <button
            className={`cyber-btn integrity-btn ${scanning ? '' : 'scan-btn-pulse'}`}
            onClick={handleScan}
            disabled={scanning}
            style={{ width: '100%', marginTop: '15px' }}
          >
            {scanning ? '⏳ SCANNING...' : '🔍 SCAN ALL MONITORED DIRECTORIES'}
          </button>
        </div>

        {/* Row 1, Col 2: Last Scan Result Widget */}
        <div className="cyber-widget scan-result-card">
          <div className="widget-title">
            <span>LAST SCAN RESULT</span>
          </div>
          {scanResult ? (
            <div className="status-flex">
              <div className="score-flex-item cyan-metric">
                <span className="info-number glow-cyan">{scanResult.scanned_files}</span>
                <span className="info-label">FILES SCANNED</span>
              </div>
              <div className={`score-flex-item ${scanResult.new_alerts > 0 ? 'red-metric' : 'green-metric'}`}>
                <span className={`info-number ${scanResult.new_alerts > 0 ? 'glow-red' : 'glow-green'}`}>
                  {scanResult.new_alerts}
                </span>
                <span className="info-label">NEW DISCREPANCIES</span>
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', height: '100px', opacity: 0.5 }}>
              <span style={{ fontSize: '12px' }}>No scans executed in the current session.</span>
            </div>
          )}
        </div>

        {/* Row 2, Col 1: Add Folder Monitor form */}
        <div className="cyber-widget add-folder-card">
          <div className="widget-title">
            <span>OBSERVE DIRECTORY DIRECTIVE</span>
          </div>
          <form onSubmit={handleAddFolder} className="integrity-form">
            <div className="form-group" style={{ marginBottom: '15px' }}>
              <label className="form-label">Absolute Directory Path</label>
              <input
                type="text"
                className="cyber-input"
                placeholder="e.g. /home/user/workspace/source"
                value={newFolder}
                onChange={(e) => setNewFolder(e.target.value)}
                required
              />
            </div>
            <button type="submit" className="cyber-btn integrity-btn" style={{ width: '100%' }}>
              ➕ ADD MONITOR DIRECTIVE
            </button>
          </form>
        </div>

        {/* Row 2, Col 2: Current Monitored Folder Index */}
        <div className="cyber-widget monitored-folders-card">
          <div className="widget-title">
            <span>MONITORED DIRECTIVES REGISTER</span>
          </div>
          {folders.length === 0 ? (
            <p style={{ opacity: 0.5, padding: '10px 0', textAlign: 'center', fontSize: '12px' }}>
              No directories monitored. Add a folder to begin.
            </p>
          ) : (
            <ul className="folder-list">
              {folders.map((folder, index) => (
                <li key={index} className="folder-item" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', overflow: 'hidden' }}>
                    <span className="folder-icon">📂</span>
                    <span className="folder-path-text" style={{ textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>{folder}</span>
                  </div>
                  <button
                    className="cyber-btn"
                    onClick={() => handleRemoveFolder(folder)}
                    style={{ padding: '4px 10px', fontSize: '11px', background: 'rgba(255,50,50,0.15)', border: '1px solid rgba(255,50,50,0.3)', flexShrink: 0 }}
                  >
                    ✕ REMOVE
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Row 3, Full Width: Integrity Alerts Feed */}
        <div className="cyber-widget integrity-alerts-card-full">
          <div className="widget-title">
            <span>MODIFICATION ALERTS FEED</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className={alerts.length > 0 ? 'glow-red' : 'glow-green'}>
                {alerts.length} {alerts.length === 1 ? 'DISCREPANCY' : 'DISCREPANCIES'} DETECTED
              </span>
              {alerts.length > 0 && (
                <button
                  className="cyber-btn"
                  onClick={handleClearAlerts}
                  style={{ padding: '4px 10px', fontSize: '11px' }}
                >
                  CLEAR ALL
                </button>
              )}
            </span>
          </div>

          {alerts.length === 0 ? (
            <div className="alerts-empty-placeholder" style={{ height: '150px' }}>
              <span className="checkmark-icon">✓</span>
              <p>All file hashes match registered baselines. No modifications detected.</p>
            </div>
          ) : (
            <div className="alerts-feed-list-full">
              {alerts.map((alert) => (
                <div key={alert.id} className="integrity-alert-item">
                  <div className="alert-item-header">
                    <span className={`alert-badge ${getAlertBadgeClass(alert.alert_type)}`}>
                      {alert.alert_type}
                    </span>
                    <span className="alert-time">{new Date(alert.detected_at).toLocaleString()}</span>
                  </div>
                  <p className="alert-file-path">PATH: <code>{alert.file_path}</code></p>
                  <div className="hash-details">
                    {alert.hash_old && (
                      <div>
                        <strong>Baseline Hash:</strong>
                        <code>{alert.hash_old}</code>
                      </div>
                    )}
                    {alert.hash_new && (
                      <div style={{ marginTop: '5px' }}>
                        <strong>{alert.alert_type === 'NEW' ? 'File Hash:' : 'Detected Hash:'}</strong>
                        <code>{alert.hash_new}</code>
                      </div>
                    )}
                    {alert.alert_type === 'DELETED' && !alert.hash_new && (
                      <div style={{ marginTop: '5px', color: '#ff6b6b' }}>
                        <strong>Status:</strong> File no longer exists on disk
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default Integrity;
