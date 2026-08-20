import React, { useState, useEffect } from 'react';

function Settings({ addLog }) {
  const [darkMode, setDarkMode] = useState(true);
  const [notifications, setNotifications] = useState(true);
  const [autoUpdate, setAutoUpdate] = useState(false);
  const [backupFreq, setBackupFreq] = useState('WEEKLY');
  const [lastBackupTime, setLastBackupTime] = useState(null);
  const [backups, setBackups] = useState([]);

  const [seError, setSeError] = useState('');
  const [seSuccess, setSeSuccess] = useState('');

  const [backupLoading, setBackupLoading] = useState(false);
  const [restoreLoading, setRestoreLoading] = useState(false);

  useEffect(() => {
    fetchSettings();
    fetchBackups();
  }, []);

  const fetchSettings = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/settings');
      const data = await res.json();
      setDarkMode(data.dark_mode);
      setNotifications(data.notifications_enabled);
      setAutoUpdate(data.auto_update);
      setBackupFreq(data.backup_frequency);
      setLastBackupTime(data.last_backup_time);
    } catch (err) {}
  };

  const fetchBackups = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/settings/backups');
      const data = await res.json();
      setBackups(data);
    } catch (err) {}
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setSeError('');
    setSeSuccess('');

    try {
      const res = await fetch('http://localhost:8000/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dark_mode: darkMode,
          notifications_enabled: notifications,
          auto_update: autoUpdate,
          backup_frequency: backupFreq
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Failed to save settings');
      }

      setSeSuccess('System settings saved successfully.');
      addLog('LogVigil preference registers updated.', 'success');
      fetchSettings();
    } catch (err) {
      setSeError(err.message);
      addLog(`Failed to save settings: ${err.message}`, 'error');
    }
  };

  const handleBackup = async () => {
    setSeError('');
    setSeSuccess('');
    setBackupLoading(true);
    try {
      const res = await fetch('http://localhost:8000/api/settings/backup', {
        method: 'POST'
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Backup failed');
      }
      setSeSuccess(data.message || 'Database backup created successfully.');
      addLog(`LogVigil database snapshot '${data.filename || 'backup'}' created.`, 'success');
      fetchSettings();
      fetchBackups();
    } catch (err) {
      setSeError(err.message);
      addLog(`Backup failed: ${err.message}`, 'error');
    } finally {
      setBackupLoading(false);
    }
  };

  const handleRestore = async (filename = null) => {
    const targetMsg = filename ? `snapshot '${filename}'` : 'the latest backup file';
    if (!window.confirm(`WARNING: Restoring ${targetMsg} will overwrite active database records. Continue?`)) {
      return;
    }
    setSeError('');
    setSeSuccess('');
    setRestoreLoading(true);
    try {
      const url = filename
        ? `http://localhost:8000/api/settings/restore?filename=${encodeURIComponent(filename)}`
        : 'http://localhost:8000/api/settings/restore';

      const res = await fetch(url, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Restore failed');
      }
      setSeSuccess(data.message || 'Database restored successfully.');
      addLog(`LogVigil database restored from ${targetMsg}.`, 'success');
    } catch (err) {
      setSeError(err.message);
      addLog(`Restore failed: ${err.message}`, 'error');
    } finally {
      setRestoreLoading(false);
    }
  };

  return (
    <div className="settings-container">
      <h2 className="section-title">⚙️ Operator System Preferences</h2>
      <p className="section-description">
        Configure display filters, telemetry flags, background update intervals, and vault database operations.
      </p>

      {seError && <div className="auth-alert" style={{ marginBottom: '15px' }}>{seError}</div>}
      {seSuccess && <div className="auth-success" style={{ marginBottom: '15px' }}>{seSuccess}</div>}

      <div className="settings-grid-layout">
        <div className="cyber-widget settings-card">
          <div className="widget-title">
            <span>PREFERENCE DIRECTIVES MATRIX</span>
          </div>

          <form onSubmit={handleSave} className="settings-form">
            <div className="form-toggle-group">
              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={darkMode}
                  onChange={(e) => setDarkMode(e.target.checked)}
                />
                <span className="toggle-custom"></span>
                <span className="toggle-text">Enable Dark HUD theme overlay</span>
              </label>

              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={notifications}
                  onChange={(e) => setNotifications(e.target.checked)}
                />
                <span className="toggle-custom"></span>
                <span className="toggle-text">Enable high-priority alert banners</span>
              </label>

              <label className="toggle-label">
                <input
                  type="checkbox"
                  checked={autoUpdate}
                  onChange={(e) => setAutoUpdate(e.target.checked)}
                />
                <span className="toggle-custom"></span>
                <span className="toggle-text">Automatically execute background database backups</span>
              </label>
            </div>

            <div className="form-group" style={{ marginTop: '20px' }}>
              <label className="form-label">Database Auto-Backup Frequency</label>
              <select
                className="cyber-input select-input"
                value={backupFreq}
                onChange={(e) => setBackupFreq(e.target.value)}
              >
                <option value="DAILY">Daily syncs (Every 24h)</option>
                <option value="WEEKLY">Weekly archives (Every 7 days)</option>
                <option value="MONTHLY">Monthly backups (Every 30 days)</option>
              </select>
            </div>

            {lastBackupTime && (
              <div style={{ marginTop: '15px', fontSize: '0.85rem', color: '#00f0ff88' }}>
                LAST AUTOMATED BACKUP: <code style={{ color: '#00f0ff' }}>{new Date(lastBackupTime).toLocaleString()}</code>
              </div>
            )}

            <button type="submit" className="cyber-btn save-settings-btn" style={{ marginTop: '25px' }}>
              💾 WRITE CONFIG TO REGISTERS
            </button>
          </form>
        </div>

        {/* Backup & Restore console */}
        <div className="cyber-widget settings-card" style={{ marginTop: '20px' }}>
          <div className="widget-title">
            <span>DATABASE DISK OPERATIONS CONSOLE</span>
          </div>
          <p className="section-description" style={{ fontSize: '0.85rem', marginBottom: '20px' }}>
            Safeguard system integrity by creating snapshot backups of the SQLite database. Overwrite active records using standard restores.
          </p>

          <div className="backup-actions-flex" style={{ display: 'flex', gap: '15px', flexWrap: 'wrap', marginBottom: '20px' }}>
            <button 
              type="button" 
              className="cyber-btn" 
              onClick={handleBackup} 
              disabled={backupLoading}
              style={{ flex: 1, minWidth: '180px' }}
            >
              {backupLoading ? 'CREATING BACKUP...' : '📦 CREATE SNAPSHOT BACKUP'}
            </button>
            <button 
              type="button" 
              className="cyber-btn" 
              onClick={() => handleRestore(null)} 
              disabled={restoreLoading}
              style={{ flex: 1, minWidth: '180px', borderColor: 'rgba(239, 68, 68, 0.4)' }}
            >
              {restoreLoading ? 'RESTORING DATABASE...' : '🔄 RESTORE LATEST BACKUP'}
            </button>
          </div>

          {/* Backup Snapshots History Table */}
          {backups.length > 0 && (
            <div style={{ marginTop: '15px' }}>
              <h4 style={{ color: '#00f0ff', marginBottom: '10px', fontSize: '0.85rem', letterSpacing: '1px' }}>
                SNAPSHOT BACKUP ARCHIVE ({backups.length})
              </h4>
              <div className="vault-files-table-container" style={{ maxHeight: '200px', overflowY: 'auto' }}>
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>SNAPSHOT FILENAME</th>
                      <th>CREATED AT</th>
                      <th>SIZE</th>
                      <th>ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {backups.map((snap) => (
                      <tr key={snap.filename}>
                        <td style={{ fontFamily: 'monospace', fontSize: '11px', color: '#00f0ff' }}>{snap.filename}</td>
                        <td>{new Date(snap.created_at).toLocaleString()}</td>
                        <td>{(snap.size_bytes / 1024).toFixed(1)} KB</td>
                        <td>
                          <button
                            className="cyber-table-btn"
                            onClick={() => handleRestore(snap.filename)}
                            disabled={restoreLoading}
                            style={{ padding: '3px 8px', fontSize: '11px' }}
                          >
                            RESTORE
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default Settings;
