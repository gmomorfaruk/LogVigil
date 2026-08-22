import React, { useState, useEffect } from 'react';

function Integrity({ addLog, username }) {
  // ── existing FIM state ──────────────────────────────────────────────────
  const [folders, setFolders] = useState([]);
  const [newFolder, setNewFolder] = useState('');
  const [alerts, setAlerts] = useState([]);
  const [intError, setIntError] = useState('');
  const [intSuccess, setIntSuccess] = useState('');
  const [protectedCount, setProtectedCount] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  // ── Lock 3 state ─────────────────────────────────────────────────────────
  const [lock3Status, setLock3Status]             = useState(null);
  const [keypairPassphrase, setKeypairPassphrase] = useState('');
  const [keypairConfirm, setKeypairConfirm]       = useState('');
  const [generatingKey, setGeneratingKey]         = useState(false);
  const [lock3Error, setLock3Error]               = useState('');
  const [lock3Success, setLock3Success]           = useState('');
  const [enableFilePath, setEnableFilePath]       = useState('');
  const [enablingLock, setEnablingLock]           = useState(false);

  // Verify modal
  const [verifyModal, setVerifyModal]             = useState(null);
  const [verifyPassphrase, setVerifyPassphrase]   = useState('');
  const [verifyResult, setVerifyResult]           = useState(null);
  const [verifying, setVerifying]                 = useState(false);

  const currentUser = username || localStorage.getItem('username') || 'admin';

  useEffect(() => {
    fetchStatus();
    fetchAlerts();
    fetchLock3Status();
  }, []);

  // ── FIM helpers ──────────────────────────────────────────────────────────
  const fetchStatus = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/integrity/status');
      const data = await res.json();
      setFolders(data.monitored_folders);
      setProtectedCount(data.protected_files_count);
    } catch (_) {}
  };

  const fetchAlerts = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/integrity/alerts');
      setAlerts(await res.json());
    } catch (_) {}
  };

  const handleAddFolder = async (e) => {
    e.preventDefault();
    setIntError(''); setIntSuccess(''); setScanResult(null);
    try {
      const res = await fetch('http://localhost:8000/api/integrity/monitor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ folder_path: newFolder })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to monitor path');
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
    setIntError(''); setIntSuccess('');
    try {
      const res = await fetch('http://localhost:8000/api/integrity/monitor', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ folder_path: folderPath })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to remove folder');
      setIntSuccess(data.message);
      addLog(`Removed folder from integrity monitor: ${folderPath}`, 'success');
      fetchStatus();
    } catch (err) {
      setIntError(err.message);
      addLog(`Integrity Monitor error: ${err.message}`, 'error');
    }
  };

  const handleScan = async () => {
    setScanning(true); setIntError(''); setIntSuccess(''); setScanResult(null);
    addLog('Initiating integrity scan across all monitored directories...', 'info');
    try {
      const res = await fetch('http://localhost:8000/api/integrity/scan', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Scan failed');
      setScanResult(data);
      setIntSuccess(data.message);
      addLog(`Integrity scan complete: ${data.scanned_files} files scanned, ${data.new_alerts} discrepancies found`,
        data.new_alerts > 0 ? 'warn' : 'success');
      fetchStatus(); fetchAlerts();
    } catch (err) {
      setIntError(err.message);
      addLog(`Integrity scan error: ${err.message}`, 'error');
    } finally { setScanning(false); }
  };

  const handleClearAlerts = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/integrity/alerts', { method: 'DELETE' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to clear alerts');
      setAlerts([]); setScanResult(null);
      addLog('Integrity alerts cleared', 'success');
    } catch (err) { addLog(`Error clearing alerts: ${err.message}`, 'error'); }
  };

  const getAlertBadgeClass = (t) => ({ MODIFIED: 'red-badge', DELETED: 'orange-badge', NEW: 'blue-badge' }[t] || 'red-badge');

  // ── Lock 3 helpers ───────────────────────────────────────────────────────
  const fetchLock3Status = async () => {
    try {
      const res = await fetch(`http://localhost:8000/api/integrity/lock3/status?username=${encodeURIComponent(currentUser)}`);
      if (res.ok) setLock3Status(await res.json());
    } catch (_) {}
  };

  const handleGenerateKeypair = async (e) => {
    e.preventDefault();
    setLock3Error(''); setLock3Success('');
    if (keypairPassphrase !== keypairConfirm) { setLock3Error('Passphrases do not match.'); return; }
    if (keypairPassphrase.length < 8)         { setLock3Error('Passphrase must be at least 8 characters.'); return; }
    setGeneratingKey(true);
    try {
      const res = await fetch('http://localhost:8000/api/integrity/keypair/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: currentUser, passphrase: keypairPassphrase })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Key generation failed');
      setLock3Success(data.message);
      setKeypairPassphrase(''); setKeypairConfirm('');
      addLog('Lock 3 RSA-4096 key pair generated', 'success');
      fetchLock3Status();
    } catch (err) {
      setLock3Error(err.message);
      addLog(`Lock 3 keygen failed: ${err.message}`, 'error');
    } finally { setGeneratingKey(false); }
  };

  const handleEnableLock3 = async (e) => {
    e.preventDefault();
    setLock3Error(''); setLock3Success('');
    if (!enableFilePath.trim()) return;
    setEnablingLock(true);
    try {
      const res = await fetch('http://localhost:8000/api/integrity/lock3/enable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: currentUser, file_path: enableFilePath.trim() })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to enable Lock 3');
      setLock3Success(data.message);
      setEnableFilePath('');
      addLog(`Lock 3 enabled: ${enableFilePath}`, 'success');
      fetchLock3Status();
    } catch (err) {
      setLock3Error(err.message);
      addLog(`Lock 3 enable failed: ${err.message}`, 'error');
    } finally { setEnablingLock(false); }
  };

  const handleDisableLock3 = async (filePath) => {
    setLock3Error(''); setLock3Success('');
    try {
      const res = await fetch('http://localhost:8000/api/integrity/lock3/disable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: currentUser, file_path: filePath })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to disable Lock 3');
      setLock3Success(data.message);
      addLog(`Lock 3 removed from: ${filePath}`, 'success');
      fetchLock3Status();
    } catch (err) {
      setLock3Error(err.message);
      addLog(`Lock 3 disable failed: ${err.message}`, 'error');
    }
  };

  const openVerifyModal = (filePath) => {
    setVerifyModal({ file_path: filePath });
    setVerifyPassphrase(''); setVerifyResult(null);
  };

  const handleVerify = async (e) => {
    e.preventDefault();
    setVerifying(true); setVerifyResult(null);
    try {
      const res = await fetch('http://localhost:8000/api/integrity/lock3/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: currentUser, file_path: verifyModal.file_path, passphrase: verifyPassphrase })
      });
      const data = await res.json();
      setVerifyResult(data);
      addLog(`Lock 3 verify → ${data.status}: ${verifyModal.file_path}`, data.status === 'UNMODIFIED' ? 'success' : 'warn');
    } catch (err) {
      setVerifyResult({ status: 'ERROR', message: err.message });
    } finally { setVerifying(false); }
  };

  const verifyColor = (s) => ({ UNMODIFIED: '#34d399', TAMPERED: '#ff5c5c', DELETED: '#ffb020' }[s] || '#ff5c5c');
  const verifyIcon  = (s) => ({ UNMODIFIED: '✅', TAMPERED: '🚨', DELETED: '⚠️' }[s] || '❌');

  // ────────────────────────────────────────────────────────────────────────
  return (
    <div className="integrity-container">
      <h2 className="section-title">🔎 File Integrity monitoring engine</h2>
      <p className="section-description">
        Observe local folders for unauthorized file edits, deletions, or new creations.
        LogVigil computes real-time SHA-256 hashes and compares them to check directory structures.
      </p>

      {intError   && <div className="auth-alert"   style={{ marginBottom: '15px' }}>{intError}</div>}
      {intSuccess && <div className="auth-success" style={{ marginBottom: '15px' }}>{intSuccess}</div>}

      <div className="integrity-grid">

        {/* ── Protection Status ───────────────────────────────────────────── */}
        <div className="cyber-widget integrity-summary-card">
          <div className="widget-title"><span>PROTECTION STATUS</span></div>
          <div className="status-flex">
            <div className="score-flex-item cyan-metric">
              <span className="info-number glow-cyan">{protectedCount}</span>
              <span className="info-label">BASELINED FILES</span>
            </div>
            <div className={`score-flex-item ${alerts.length > 0 ? 'red-metric' : 'green-metric'}`}>
              <span className={`info-number ${alerts.length > 0 ? 'glow-red' : 'glow-green'}`}>{alerts.length}</span>
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

        {/* ── Last Scan Result ─────────────────────────────────────────────── */}
        <div className="cyber-widget scan-result-card">
          <div className="widget-title"><span>LAST SCAN RESULT</span></div>
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
            <div style={{ display:'flex', flexDirection:'column', justifyContent:'center', alignItems:'center', height:'100px', opacity:0.5 }}>
              <span style={{ fontSize:'12px' }}>No scans executed in the current session.</span>
            </div>
          )}
        </div>

        {/* ── Add Folder form ──────────────────────────────────────────────── */}
        <div className="cyber-widget add-folder-card">
          <div className="widget-title"><span>OBSERVE DIRECTORY DIRECTIVE</span></div>
          <form onSubmit={handleAddFolder} className="integrity-form">
            <div className="form-group" style={{ marginBottom:'15px' }}>
              <label className="form-label">Absolute Directory Path</label>
              <input type="text" className="cyber-input"
                placeholder="e.g. /home/user/workspace/source"
                value={newFolder} onChange={(e) => setNewFolder(e.target.value)} required />
            </div>
            <button type="submit" className="cyber-btn integrity-btn" style={{ width:'100%' }}>
              ➕ ADD MONITOR DIRECTIVE
            </button>
          </form>
        </div>

        {/* ── Monitored Folders List ───────────────────────────────────────── */}
        <div className="cyber-widget monitored-folders-card">
          <div className="widget-title"><span>MONITORED DIRECTIVES REGISTER</span></div>
          {folders.length === 0 ? (
            <p style={{ opacity:0.5, padding:'10px 0', textAlign:'center', fontSize:'12px' }}>
              No directories monitored. Add a folder to begin.
            </p>
          ) : (
            <ul className="folder-list">
              {folders.map((folder, i) => (
                <li key={i} className="folder-item" style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
                  <div style={{ display:'flex', alignItems:'center', gap:'8px', overflow:'hidden' }}>
                    <span className="folder-icon">📂</span>
                    <span className="folder-path-text" style={{ textOverflow:'ellipsis', overflow:'hidden', whiteSpace:'nowrap' }}>{folder}</span>
                  </div>
                  <button
                    className="cyber-btn"
                    onClick={() => handleRemoveFolder(folder)}
                    style={{ padding:'4px 10px', fontSize:'11px', background:'rgba(255,50,50,0.15)', border:'1px solid rgba(255,50,50,0.3)', flexShrink:0 }}
                  >✕ REMOVE</button>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* ── Alerts Feed ──────────────────────────────────────────────────── */}
        <div className="cyber-widget integrity-alerts-card-full">
          <div className="widget-title">
            <span>MODIFICATION ALERTS FEED</span>
            <span style={{ display:'flex', alignItems:'center', gap:'10px' }}>
              <span className={alerts.length > 0 ? 'glow-red' : 'glow-green'}>
                {alerts.length} {alerts.length === 1 ? 'DISCREPANCY' : 'DISCREPANCIES'} DETECTED
              </span>
              {alerts.length > 0 && (
                <button className="cyber-btn" onClick={handleClearAlerts} style={{ padding:'4px 10px', fontSize:'11px' }}>
                  CLEAR ALL
                </button>
              )}
            </span>
          </div>
          {alerts.length === 0 ? (
            <div className="alerts-empty-placeholder" style={{ height:'150px' }}>
              <span className="checkmark-icon">✓</span>
              <p>All file hashes match registered baselines. No modifications detected.</p>
            </div>
          ) : (
            <div className="alerts-feed-list-full">
              {alerts.map((alert) => (
                <div key={alert.id} className="integrity-alert-item">
                  <div className="alert-item-header">
                    <span className={`alert-badge ${getAlertBadgeClass(alert.alert_type)}`}>{alert.alert_type}</span>
                    <span className="alert-time">{new Date(alert.detected_at).toLocaleString()}</span>
                  </div>
                  <p className="alert-file-path">PATH: <code>{alert.file_path}</code></p>
                  <div className="hash-details">
                    {alert.hash_old && <div><strong>Baseline Hash:</strong><code>{alert.hash_old}</code></div>}
                    {alert.hash_new && (
                      <div style={{ marginTop:'5px' }}>
                        <strong>{alert.alert_type === 'NEW' ? 'File Hash:' : 'Detected Hash:'}</strong>
                        <code>{alert.hash_new}</code>
                      </div>
                    )}
                    {alert.alert_type === 'DELETED' && !alert.hash_new && (
                      <div style={{ marginTop:'5px', color:'#ff6b6b' }}><strong>Status:</strong> File no longer exists on disk</div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ══════════════════════════════════════════════════════════════════
            LOCK 3 — RSA-4096 + AES-256-GCM PRIVATE KEY PROTECTION
            ══════════════════════════════════════════════════════════════════ */}
        <div className="cyber-widget integrity-alerts-card-full" style={{ gridColumn:'1 / -1' }}>
          <div className="widget-title">
            <span>🔐 LOCK 3 — PRIVATE KEY FILE PROTECTION</span>
            <span style={{ fontSize:'11px', color: lock3Status?.has_keypair ? '#34d399' : '#ffb020' }}>
              {lock3Status?.has_keypair ? '● KEY PAIR ACTIVE' : '○ NO KEY PAIR'}
            </span>
          </div>

          {/* Concept banner */}
          <div style={{
            background:'linear-gradient(135deg, rgba(34,226,238,0.06), rgba(255,176,32,0.06))',
            border:'1px solid rgba(34,226,238,0.15)', borderRadius:'8px',
            padding:'14px 18px', marginBottom:'20px',
            fontSize:'12px', lineHeight:'1.7', color:'#7f97a1'
          }}>
            <strong style={{ color:'#22e2ee' }}>Three-layer defence:</strong>{' '}
            Lock&nbsp;1 (login password) → Lock&nbsp;2 (vault PIN) → Lock&nbsp;3 (RSA private key).{' '}
            Even if an attacker bypasses all authentication, protected files remain{' '}
            <strong style={{ color:'#ffb020' }}>unreadable without your Lock 3 passphrase</strong>.
            Files are encrypted with <strong style={{ color:'#22e2ee' }}>RSA-4096 + AES-256-GCM</strong> hybrid encryption.
            Your passphrase is <strong style={{ color:'#34d399' }}>never stored</strong> on this system.
          </div>

          {lock3Error   && <div className="auth-alert"   style={{ marginBottom:'14px' }}>{lock3Error}</div>}
          {lock3Success && <div className="auth-success" style={{ marginBottom:'14px' }}>{lock3Success}</div>}

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'18px' }}>

            {/* Key Pair Generation */}
            <div style={{ background:'rgba(34,226,238,0.04)', border:'1px solid rgba(34,226,238,0.18)', borderRadius:'8px', padding:'18px' }}>
              <div style={{ fontSize:'11px', fontWeight:700, color:'#22e2ee', letterSpacing:'1px', marginBottom:'14px' }}>
                🔑 {lock3Status?.has_keypair ? 'KEY PAIR STATUS' : 'GENERATE KEY PAIR'}
              </div>

              {lock3Status?.has_keypair ? (
                <div style={{ display:'flex', flexDirection:'column', gap:'10px', fontSize:'12px', color:'#7f97a1' }}>
                  <div><span style={{ color:'#34d399' }}>✓</span> RSA-4096 key pair active for <strong style={{ color:'#22e2ee' }}>{currentUser}</strong></div>
                  <div style={{ fontSize:'11px', opacity:0.7 }}>Private key stored encrypted — only your passphrase can unlock it.</div>
                  <div style={{ padding:'10px', background:'rgba(255,176,32,0.08)', borderRadius:'6px', border:'1px solid rgba(255,176,32,0.2)', fontSize:'11px', color:'#ffb020' }}>
                    ⚠ If you forget your Lock 3 passphrase, protected files cannot be recovered.
                  </div>
                </div>
              ) : (
                <form onSubmit={handleGenerateKeypair} style={{ display:'flex', flexDirection:'column', gap:'12px' }}>
                  <div className="form-group">
                    <label className="form-label">Lock 3 Passphrase</label>
                    <input type="password" className="cyber-input"
                      placeholder="Min. 8 characters — NOT your login password"
                      value={keypairPassphrase} onChange={(e) => setKeypairPassphrase(e.target.value)}
                      required minLength={8} />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Confirm Passphrase</label>
                    <input type="password" className="cyber-input"
                      placeholder="Repeat passphrase"
                      value={keypairConfirm} onChange={(e) => setKeypairConfirm(e.target.value)}
                      required />
                  </div>
                  <div style={{ fontSize:'11px', color:'#7f97a1', padding:'8px', background:'rgba(255,176,32,0.06)', borderRadius:'6px', border:'1px solid rgba(255,176,32,0.15)' }}>
                    ⚠ This passphrase is <strong>never stored</strong>. If you lose it, Lock 3 files cannot be recovered.
                  </div>
                  <button type="submit" className="cyber-btn integrity-btn" disabled={generatingKey} style={{ width:'100%' }}>
                    {generatingKey ? '⏳ GENERATING RSA-4096...' : '⚡ GENERATE KEY PAIR'}
                  </button>
                </form>
              )}
            </div>

            {/* Enable Lock 3 on a File */}
            <div style={{ background:'rgba(255,176,32,0.04)', border:'1px solid rgba(255,176,32,0.18)', borderRadius:'8px', padding:'18px' }}>
              <div style={{ fontSize:'11px', fontWeight:700, color:'#ffb020', letterSpacing:'1px', marginBottom:'14px' }}>
                🛡 ENABLE LOCK 3 ON A FILE
              </div>

              {!lock3Status?.has_keypair ? (
                <div style={{ fontSize:'12px', color:'#7f97a1', textAlign:'center', padding:'20px 0', opacity:0.7 }}>
                  Generate a key pair first to enable Lock 3 protection.
                </div>
              ) : (
                <form onSubmit={handleEnableLock3} style={{ display:'flex', flexDirection:'column', gap:'12px' }}>
                  <div className="form-group">
                    <label className="form-label">Full File Path (not a folder)</label>
                    <input type="text" className="cyber-input"
                      placeholder="e.g. /home/user/documents/secret.pdf"
                      value={enableFilePath} onChange={(e) => setEnableFilePath(e.target.value)}
                      required />
                  </div>
                  <div style={{ fontSize:'11px', color:'#7f97a1', padding:'8px', background:'rgba(34,226,238,0.05)', borderRadius:'6px' }}>
                    Enter the <strong style={{ color:'#22e2ee' }}>full path to a file</strong> (not a folder).
                    The file is auto-baselined automatically — no need to pre-add its folder.
                    An encrypted <code style={{ color:'#22e2ee' }}>.lv3</code> copy is created alongside it.
                  </div>

                  <button type="submit" className="cyber-btn" disabled={enablingLock}
                    style={{ width:'100%', background:'rgba(255,176,32,0.15)', border:'1px solid rgba(255,176,32,0.4)', color:'#ffb020' }}>
                    {enablingLock ? '⏳ ENCRYPTING...' : '🔒 ENABLE LOCK 3'}
                  </button>
                </form>
              )}
            </div>
          </div>

          {/* Lock 3 Protected Files List */}
          <div style={{ marginTop:'20px' }}>
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', fontSize:'11px', fontWeight:700, color:'#22e2ee', letterSpacing:'1px', marginBottom:'12px' }}>
              <span>📋 LOCK 3 PROTECTED FILES</span>
              <span style={{ color:'#7f97a1' }}>{lock3Status?.locked_count ?? 0} FILE{lock3Status?.locked_count !== 1 ? 'S' : ''} PROTECTED</span>
            </div>

            {(!lock3Status?.locked_files || lock3Status.locked_files.length === 0) ? (
              <div style={{ textAlign:'center', padding:'30px', opacity:0.5, fontSize:'12px', border:'1px dashed rgba(34,226,238,0.15)', borderRadius:'8px' }}>
                No files are currently under Lock 3 protection.
              </div>
            ) : (
              <div style={{ display:'flex', flexDirection:'column', gap:'8px' }}>
                {lock3Status.locked_files.map((f, i) => (
                  <div key={i} style={{
                    display:'flex', justifyContent:'space-between', alignItems:'center',
                    padding:'10px 14px',
                    background:'rgba(34,226,238,0.04)', border:'1px solid rgba(34,226,238,0.15)',
                    borderRadius:'6px', gap:'12px', flexWrap:'wrap'
                  }}>
                    <div style={{ flex:1, minWidth:0 }}>
                      <div style={{ display:'flex', alignItems:'center', gap:'8px' }}>
                        <span style={{ fontSize:'14px' }}>🔒</span>
                        <code style={{ fontSize:'11px', color:'#22e2ee', wordBreak:'break-all' }}>{f.file_path}</code>
                      </div>
                      {f.lv3_path && (
                        <div style={{ fontSize:'10px', color:'#7f97a1', marginTop:'3px', paddingLeft:'22px' }}>
                          → <code style={{ color:'#ffb020' }}>{f.lv3_path}</code>
                        </div>
                      )}
                    </div>
                    <div style={{ display:'flex', gap:'6px', flexShrink:0 }}>
                      <button
                        className="cyber-btn"
                        onClick={() => openVerifyModal(f.file_path)}
                        style={{ padding:'4px 10px', fontSize:'11px', background:'rgba(52,211,153,0.12)', border:'1px solid rgba(52,211,153,0.3)', color:'#34d399' }}
                      >🔍 VERIFY</button>
                      <button
                        className="cyber-btn"
                        onClick={() => handleDisableLock3(f.file_path)}
                        style={{ padding:'4px 10px', fontSize:'11px', background:'rgba(255,50,50,0.12)', border:'1px solid rgba(255,50,50,0.3)', color:'#ff5c5c' }}
                      >✕ REMOVE</button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Verify Modal ──────────────────────────────────────────────────── */}
      {verifyModal && (
        <div style={{
          position:'fixed', inset:0, zIndex:9999,
          background:'rgba(0,0,0,0.75)', backdropFilter:'blur(6px)',
          display:'flex', alignItems:'center', justifyContent:'center'
        }}>
          <div style={{
            background:'#07151a', border:'1px solid rgba(34,226,238,0.3)',
            borderRadius:'12px', padding:'30px', width:'100%', maxWidth:'480px',
            boxShadow:'0 0 40px rgba(34,226,238,0.15)'
          }}>
            <div style={{ fontSize:'13px', fontWeight:700, color:'#22e2ee', letterSpacing:'1px', marginBottom:'6px' }}>
              🔍 LOCK 3 INTEGRITY VERIFICATION
            </div>
            <code style={{ fontSize:'11px', color:'#7f97a1', wordBreak:'break-all', display:'block', marginBottom:'20px' }}>
              {verifyModal.file_path}
            </code>

            {!verifyResult ? (
              <form onSubmit={handleVerify} style={{ display:'flex', flexDirection:'column', gap:'14px' }}>
                <div className="form-group">
                  <label className="form-label">Lock 3 Passphrase</label>
                  <input type="password" className="cyber-input"
                    placeholder="Enter your Lock 3 passphrase"
                    value={verifyPassphrase} onChange={(e) => setVerifyPassphrase(e.target.value)}
                    required autoFocus />
                </div>
                <div style={{ fontSize:'11px', color:'#7f97a1' }}>
                  Decryption happens in memory only — nothing is written to disk. Your passphrase is discarded immediately after.
                </div>
                <div style={{ display:'flex', gap:'10px' }}>
                  <button type="submit" className="cyber-btn integrity-btn" disabled={verifying} style={{ flex:1 }}>
                    {verifying ? '⏳ DECRYPTING & VERIFYING...' : '🔐 VERIFY INTEGRITY'}
                  </button>
                  <button type="button" className="cyber-btn" onClick={() => setVerifyModal(null)}
                    style={{ padding:'0 16px', background:'rgba(255,50,50,0.1)', border:'1px solid rgba(255,50,50,0.3)' }}>
                    CANCEL
                  </button>
                </div>
              </form>
            ) : (
              <div style={{ display:'flex', flexDirection:'column', gap:'14px' }}>
                <div style={{
                  padding:'18px',
                  background:`rgba(${verifyResult.status === 'UNMODIFIED' ? '52,211,153' : '255,92,92'}, 0.08)`,
                  border:`1px solid rgba(${verifyResult.status === 'UNMODIFIED' ? '52,211,153' : '255,92,92'}, 0.3)`,
                  borderRadius:'8px', textAlign:'center'
                }}>
                  <div style={{ fontSize:'28px', marginBottom:'8px' }}>{verifyIcon(verifyResult.status)}</div>
                  <div style={{ fontSize:'14px', fontWeight:700, color:verifyColor(verifyResult.status), marginBottom:'6px' }}>
                    {verifyResult.status}
                  </div>
                  <div style={{ fontSize:'12px', color:'#7f97a1' }}>{verifyResult.message}</div>
                </div>
                <button className="cyber-btn" onClick={() => setVerifyModal(null)} style={{ width:'100%' }}>CLOSE</button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default Integrity;
