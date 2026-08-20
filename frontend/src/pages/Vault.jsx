import React, { useState, useEffect, useCallback } from 'react';

function Vault({ addLog }) {
  const [locked, setLocked] = useState(true);

  // --- Unlock stage state machine ---
  // 'pin' | 'master_key' | 'cooldown' | 'unlocked'
  const [unlockStage, setUnlockStage] = useState('pin');
  const [cooldownSeconds, setCooldownSeconds] = useState(0);
  const [cooldownInterval, setCooldownInterval] = useState(null);

  // Form inputs
  const [pinInput, setPinInput] = useState('');
  const [masterKeyInput, setMasterKeyInput] = useState('');

  // Files & passwords
  const [filePath, setFilePath] = useState('');
  const [files, setFiles] = useState([]);
  const [vaultError, setVaultError] = useState('');
  const [vaultSuccess, setVaultSuccess] = useState('');
  const [hasPin, setHasPin] = useState(true);
  const [hasMasterKey, setHasMasterKey] = useState(false);
  const [setupPin, setSetupPin] = useState('');
  const [setupPinConfirm, setSetupPinConfirm] = useState('');
  const [setupMasterKey, setSetupMasterKey] = useState('');

  // Master Key management (post-setup)
  const [showMasterKeyPanel, setShowMasterKeyPanel] = useState(false);
  const [mkCurrentPin, setMkCurrentPin] = useState('');
  const [mkNewKey, setMkNewKey] = useState('');
  const [mkError, setMkError] = useState('');
  const [mkSuccess, setMkSuccess] = useState('');

  // Password Vault
  const [activeSubTab, setActiveSubTab] = useState('files');
  const [passwords, setPasswords] = useState([]);
  const [websiteInput, setWebsiteInput] = useState('');
  const [usernameInput, setUsernameInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [visiblePasswords, setVisiblePasswords] = useState({});

  const getToken = () => localStorage.getItem('logvigil_token');
  const authHeaders = () => {
    const token = getToken();
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  };

  // -------------------------------------------------------------------------
  // Countdown timer for lockout display
  // -------------------------------------------------------------------------
  const startCooldownTimer = useCallback((seconds) => {
    if (cooldownInterval) clearInterval(cooldownInterval);
    setCooldownSeconds(seconds);
    const interval = setInterval(() => {
      setCooldownSeconds(prev => {
        if (prev <= 1) {
          clearInterval(interval);
          setUnlockStage('pin');
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    setCooldownInterval(interval);
  }, []);

  useEffect(() => {
    return () => { if (cooldownInterval) clearInterval(cooldownInterval); };
  }, [cooldownInterval]);

  const formatCooldown = (secs) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}m ${s.toString().padStart(2, '0')}s`;
  };

  // -------------------------------------------------------------------------
  // Auto-lock on vault session expiry (backend is authority)
  // -------------------------------------------------------------------------
  // Centralised function to fully reset vault UI to locked state
  const performAutoLock = useCallback((reason = 'inactivity') => {
    setLocked(true);
    setUnlockStage('pin');
    setFiles([]);
    setPasswords([]);
    setMasterKeyInput('');
    setPinInput('');
    setVisiblePasswords({});
    // Always close and clear the master key panel on any lock
    setShowMasterKeyPanel(false);
    setMkCurrentPin('');
    setMkNewKey('');
    setMkError('');
    setMkSuccess('');
    addLog(`🔒 Vault auto-locked: ${reason}`, 'warn');
  }, [addLog]);

  // -------------------------------------------------------------------------
  // Inactivity ping — keeps DB session alive while vault is open and idle.
  // Backend validates session; if expired → 401 → enforce lock in UI.
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (locked) return;

    const pingInterval = setInterval(async () => {
      try {
        const res = await fetch('http://localhost:8000/api/vault/inactivity-ping', {
          headers: authHeaders()
        });
        if (res.status === 401 || res.status === 403) {
          // Backend session expired — backend wins, lock the UI
          performAutoLock('inactivity timeout');
        }
      } catch (_) {
        // Network error — don't lock, just retry next tick
      }
    }, 60000); // every 60 seconds

    return () => clearInterval(pingInterval);
  }, [locked, performAutoLock]);

  // -------------------------------------------------------------------------
  // Fetch initial vault status
  // -------------------------------------------------------------------------
  useEffect(() => {
    fetchStatus();
    // Re-sync stage from backend whenever window regains focus
    // (catches the case where server-side state changed while tab was inactive)
    const onFocus = () => fetchStatus();
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, []);

  const fetchStatus = async () => {
    try {
      const token = getToken();
      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
      const res = await fetch('http://localhost:8000/api/vault/status', { headers });
      const data = await res.json();

      setLocked(data.locked);
      setHasPin(data.has_pin !== undefined ? data.has_pin : true);
      setHasMasterKey(data.has_master_key || false);

      // Apply stage from backend status
      if (data.lockout_seconds && data.lockout_seconds > 0) {
        setUnlockStage('cooldown');
        startCooldownTimer(data.lockout_seconds);
      } else if (data.unlock_stage) {
        setUnlockStage(data.unlock_stage);
      }

      if (!data.locked) {
        fetchFiles();
        fetchPasswords();
      }
    } catch (err) {
      setVaultError('Failed to contact vault API');
    }
  };

  const fetchFiles = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/vault/files', { headers: authHeaders() });
      if (res.ok) {
        const data = await res.json();
        setFiles(data);
      } else if (res.status === 401) {
        performAutoLock('session expired');
      }
    } catch (_) {}
  };

  const fetchPasswords = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/vault/passwords', { headers: authHeaders() });
      if (res.ok) {
        const data = await res.json();
        setPasswords(data);
      } else if (res.status === 401) {
        performAutoLock('session expired');
      }
    } catch (_) {}
  };

  // -------------------------------------------------------------------------
  // First-time PIN + Master Key setup
  // -------------------------------------------------------------------------
  const handleSetupPin = async (e) => {
    e.preventDefault();
    setVaultError('');
    setVaultSuccess('');

    if (setupPin !== setupPinConfirm) {
      setVaultError('PINs do not match. Please re-enter.');
      return;
    }
    if (setupPin.length < 4) {
      setVaultError('PIN must be at least 4 characters.');
      return;
    }

    try {
      const body = { pin: setupPin };
      if (setupMasterKey.trim()) body.master_key = setupMasterKey;

      const res = await fetch('http://localhost:8000/api/vault/setup-pin', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'PIN setup failed');

      setVaultSuccess(data.message || 'Vault PIN configured successfully!');
      addLog('Vault PIN configured for current operator.', 'success');
      setHasPin(true);
      setHasMasterKey(!!setupMasterKey.trim());
      setSetupPin('');
      setSetupPinConfirm('');
      setSetupMasterKey('');
    } catch (err) {
      setVaultError(err.message);
      addLog(`Vault PIN setup error: ${err.message}`, 'error');
    }
  };

  // -------------------------------------------------------------------------
  // Vault Toggle — handles both PIN stage and Master Key stage
  // -------------------------------------------------------------------------
  const handleToggle = async (e) => {
    e.preventDefault();
    setVaultError('');
    setVaultSuccess('');

    // Build request body based on current stage
    const body = {};
    if (unlockStage === 'pin' || unlockStage === 'master_key' && pinInput) {
      if (pinInput) body.pin = pinInput;
    }
    if (unlockStage === 'master_key' && masterKeyInput) {
      body.master_key = masterKeyInput;
    }
    // Lock request doesn't need a body
    if (!locked && !body.pin && !body.master_key) {
      body.pin = null; // trigger lock path
    }

    try {
      const res = await fetch('http://localhost:8000/api/vault/toggle', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify(body)
      });

      const data = await res.json();

      if (res.status === 429) {
        // Lockout — switch to cooldown stage
        const lockoutSecs = parseInt(res.headers.get('X-Lockout-Seconds') || data.detail?.match(/\d+/)?.[0] || '1800');
        setUnlockStage('cooldown');
        startCooldownTimer(lockoutSecs);
        setVaultError('');
        addLog('Vault access restricted: progressive lockout active.', 'error');
        return;
      }

      if (res.status === 401) {
        const stage = res.headers.get('X-Vault-Stage');
        if (stage === 'master_key') {
          // Escalate to master key stage — vague message, no threshold revealed
          setUnlockStage('master_key');
          setVaultError('⚠️ Additional verification required.');
          setPinInput('');
          addLog('Vault: additional verification required.', 'warn');
        } else {
          setVaultError(data.detail || 'Access denied');
          addLog(`Vault Access Failure: ${data.detail}`, 'error');
        }
        return;
      }

      if (!res.ok) {
        throw new Error(data.detail || 'Access denied');
      }

      // SUCCESS — 200 response
      // Backend may redirect back to 'pin' stage (e.g. no master key configured — counter was auto-reset)
      if (res.ok && data.unlock_stage === 'pin' && data.locked) {
        setUnlockStage('pin');
        setPinInput('');
        setMasterKeyInput('');
        setHasMasterKey(data.has_master_key || false);
        setVaultError('');
        setVaultSuccess('Enter your vault PIN to unlock.');
        addLog('Vault: PIN required. Configure a master key after unlocking for extra protection.', 'warn');
        return;
      }

      setLocked(data.locked);
      setPinInput('');
      setMasterKeyInput('');

      if (!data.locked) {
        // Vault just unlocked — refresh full status to get fresh hasMasterKey
        setUnlockStage('unlocked');
        setVaultSuccess('Vault unlocked successfully.');
        addLog('AES-256 Cryptographic Vault unlocked.', 'success');
        fetchStatus();
        fetchFiles();
        fetchPasswords();
      } else {
        // Vault just locked — update hasMasterKey from backend response, clear panel
        setUnlockStage('pin');
        setVaultSuccess('');
        setHasMasterKey(data.has_master_key || false);
        setShowMasterKeyPanel(false);
        setMkCurrentPin('');
        setMkNewKey('');
        setMkError('');
        addLog('Vault access terminated. Storage locked.', 'warn');
        setFiles([]);
        setPasswords([]);
        setVisiblePasswords({});
      }
    } catch (err) {
      setVaultError(err.message);
      addLog(`Vault Access Failure: ${err.message}`, 'error');
    }
  };

  // Master Key setup/update (requires vault to be unlocked + PIN re-confirmation)
  const handleSetupMasterKey = async (e) => {
    e.preventDefault();
    setMkError('');
    setMkSuccess('');

    if (!mkCurrentPin) { setMkError('Current PIN is required to confirm your identity.'); return; }
    if (!mkNewKey || mkNewKey.length < 4) { setMkError('Master key must be at least 4 characters.'); return; }

    try {
      const res = await fetch('http://localhost:8000/api/vault/setup-master-key', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ current_pin: mkCurrentPin, master_key: mkNewKey })
      });
      const data = await res.json();

      // If vault session expired mid-form, lock the UI gracefully
      if (res.status === 401 || res.status === 403) {
        performAutoLock('session expired during master key setup');
        return;
      }

      if (!res.ok) throw new Error(data.detail || 'Master key setup failed');

      setMkSuccess(data.message || 'Master key configured successfully!');
      setHasMasterKey(true);
      setMkCurrentPin('');
      setMkNewKey('');
      addLog('Vault master key configured successfully.', 'success');
      // Refresh full status to confirm backend state
      fetchStatus();
      setTimeout(() => { setShowMasterKeyPanel(false); setMkSuccess(''); }, 2500);
    } catch (err) {
      setMkError(err.message);
      addLog(`Master key setup error: ${err.message}`, 'error');
    }
  };


  // -------------------------------------------------------------------------
  const handleEncrypt = async (e) => {
    e.preventDefault();
    setVaultError('');
    setVaultSuccess('');

    try {
      const res = await fetch('http://localhost:8000/api/vault/encrypt', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ file_path: filePath })
      });
      const data = await res.json();
      if (res.status === 401) { performAutoLock('session expired'); return; }
      if (!res.ok) throw new Error(data.detail || 'Encryption failed');

      setVaultSuccess(`Encrypted file saved at: ${data.encrypted_path}`);
      addLog(`File successfully encrypted: ${data.file_name}`, 'success');
      setFilePath('');
      fetchFiles();
    } catch (err) {
      setVaultError(err.message);
      addLog(`Encryption Failure: ${err.message}`, 'error');
    }
  };

  const handleDecrypt = async (fileId) => {
    setVaultError('');
    setVaultSuccess('');

    try {
      const res = await fetch('http://localhost:8000/api/vault/decrypt', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ file_id: fileId })
      });
      const data = await res.json();
      if (res.status === 401) { performAutoLock('session expired'); return; }
      if (!res.ok) throw new Error(data.detail || 'Decryption failed');

      setVaultSuccess(`Decrypted file restored at: ${data.decrypted_path}`);
      addLog(`File successfully decrypted: ${data.file_name}`, 'success');
      fetchFiles();
    } catch (err) {
      setVaultError(err.message);
      addLog(`Decryption Failure: ${err.message}`, 'error');
    }
  };

  // -------------------------------------------------------------------------
  // Password vault
  // -------------------------------------------------------------------------
  const handleAddPassword = async (e) => {
    e.preventDefault();
    setVaultError('');
    setVaultSuccess('');

    try {
      const res = await fetch('http://localhost:8000/api/vault/passwords', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ website: websiteInput, username: usernameInput, password: passwordInput })
      });
      const data = await res.json();
      if (res.status === 401) { performAutoLock('session expired'); return; }
      if (!res.ok) throw new Error(data.detail || 'Failed to store credential');

      setVaultSuccess(`Credentials for '${data.website}' saved successfully.`);
      addLog(`Credentials stored: website='${data.website}' user='${data.username}'`, 'success');
      setWebsiteInput('');
      setUsernameInput('');
      setPasswordInput('');
      fetchPasswords();
    } catch (err) {
      setVaultError(err.message);
      addLog(`Credentials Storage Failure: ${err.message}`, 'error');
    }
  };

  const handleDeletePassword = async (pwdId) => {
    setVaultError('');
    setVaultSuccess('');

    try {
      const res = await fetch(`http://localhost:8000/api/vault/passwords/${pwdId}`, {
        method: 'DELETE',
        headers: authHeaders()
      });
      const data = await res.json();
      if (res.status === 401) { performAutoLock('session expired'); return; }
      if (!res.ok) throw new Error(data.detail || 'Failed to delete credential');

      setVaultSuccess('Credential deleted successfully.');
      addLog(`Credential entry deleted: ID ${pwdId}`, 'warn');
      fetchPasswords();
    } catch (err) {
      setVaultError(err.message);
      addLog(`Credential deletion error: ${err.message}`, 'error');
    }
  };

  const togglePasswordVisibility = (id) => {
    setVisiblePasswords(prev => ({ ...prev, [id]: !prev[id] }));
  };

  // -------------------------------------------------------------------------
  // Render unlock panel based on stage
  // -------------------------------------------------------------------------
  const renderUnlockPanel = () => {
    if (!hasPin) {
      // First-time setup
      return (
        <form onSubmit={handleSetupPin} className="vault-pin-form">
          <label className="form-label">CONFIGURE VAULT PIN (First Time Setup)</label>
          <div className="form-group" style={{ marginBottom: '10px' }}>
            <input type="password" className="cyber-input pin-input"
              placeholder="Create your vault PIN (min 4 chars)..."
              value={setupPin} onChange={e => setSetupPin(e.target.value)}
              maxLength={8} minLength={4} required />
          </div>
          <div className="form-group" style={{ marginBottom: '10px' }}>
            <input type="password" className="cyber-input pin-input"
              placeholder="Confirm your vault PIN..."
              value={setupPinConfirm} onChange={e => setSetupPinConfirm(e.target.value)}
              maxLength={8} minLength={4} required />
          </div>
          <div className="form-group" style={{ marginBottom: '10px' }}>
            <input type="password" className="cyber-input pin-input"
              placeholder="Master Key (optional — for extra security)..."
              value={setupMasterKey} onChange={e => setSetupMasterKey(e.target.value)}
              minLength={4} />
          </div>
          <button type="submit" className="cyber-btn pin-submit-btn" style={{ width: '100%' }}>
            🔐 CONFIGURE VAULT PIN
          </button>
          <span className="input-hint">
            Optional: Set a master key for a second layer of security if PIN entry fails.
          </span>
        </form>
      );
    }

    if (unlockStage === 'cooldown') {
      return (
        <div className="vault-lockout-panel">
          <div className="lockout-icon">🔴</div>
          <div className="lockout-title">ACCESS TEMPORARILY RESTRICTED</div>
          <div className="lockout-timer">{formatCooldown(cooldownSeconds)}</div>
          <div className="lockout-hint">Security protocols active. Please wait before retrying.</div>
        </div>
      );
    }

    if (unlockStage === 'master_key') {
      return (
        <form onSubmit={handleToggle} className="vault-pin-form">
          <div className="master-key-warning">
            <span className="warning-icon">⚠️</span>
            <span className="warning-text">ADDITIONAL VERIFICATION REQUIRED</span>
          </div>
          <label className="form-label">SECURITY MASTER KEY</label>
          <div className="pin-input-row">
            <input type="password" className="cyber-input pin-input master-key-input"
              placeholder="Enter master security key..."
              value={masterKeyInput} onChange={e => setMasterKeyInput(e.target.value)}
              minLength={4} required autoFocus />
            <button type="submit" className="cyber-btn pin-submit-btn danger-btn">
              VERIFY
            </button>
          </div>
          <span className="input-hint">Enter the master key configured during vault setup.</span>
        </form>
      );
    }

    // Default: PIN stage
    return (
      <form onSubmit={handleToggle} className="vault-pin-form">
        <label className="form-label">OPERATOR MASTER PIN</label>
        <div className="pin-input-row">
          <input type="password" className="cyber-input pin-input"
            placeholder="Enter your security PIN..."
            value={pinInput} onChange={e => setPinInput(e.target.value)}
            maxLength={8} required />
          <button type="submit" className="cyber-btn pin-submit-btn">
            {locked ? 'UNLOCK' : 'LOCK'}
          </button>
        </div>
        <span className="input-hint">Enter the PIN you configured during vault setup</span>
      </form>
    );
  };

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------
  // Calculate total size
  const totalFileSize = files.reduce((acc, f) => acc + (f.size || 0), 0);
  const formattedSize = totalFileSize > 1024 * 1024
    ? (totalFileSize / (1024 * 1024)).toFixed(2) + ' MB'
    : (totalFileSize / 1024).toFixed(2) + ' KB';

  if (locked) {
    return (
      <div className="vault-container vault-locked-view">
        <style>{`
          .vault-locked-view {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 70vh;
            padding: 20px;
          }
          .vault-lock-card {
            max-width: 480px;
            width: 100%;
            background: rgba(6, 10, 20, 0.75) !important;
            border: 1px solid #ff005544 !important;
            box-shadow: 0 0 40px rgba(255, 0, 85, 0.15), inset 0 0 20px rgba(255, 0, 85, 0.05) !important;
            backdrop-filter: blur(16px) !important;
            padding: 40px 30px !important;
            border-radius: 12px !important;
            text-align: center;
            position: relative;
            overflow: hidden;
            border-top: 3px solid #ff0055 !important;
          }
          .lock-shield-wrapper {
            width: 80px;
            height: 80px;
            margin: 0 auto 24px;
            background: rgba(255, 0, 85, 0.05);
            border: 1px solid rgba(255, 0, 85, 0.2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.8rem;
            box-shadow: 0 0 25px rgba(255, 0, 85, 0.1);
            animation: pulse-red-glow 2s infinite ease-in-out;
          }
          @keyframes pulse-red-glow {
            0%, 100% { box-shadow: 0 0 15px rgba(255, 0, 85, 0.1); border-color: rgba(255, 0, 85, 0.2); }
            50% { box-shadow: 0 0 30px rgba(255, 0, 85, 0.3); border-color: rgba(255, 0, 85, 0.5); background: rgba(255, 0, 85, 0.1); }
          }
          .lock-card-header h3 {
            font-family: var(--font-cyber);
            font-size: 1.25rem;
            letter-spacing: 2px;
            color: #ff0055;
            margin-bottom: 8px;
            text-shadow: 0 0 10px rgba(255, 0, 85, 0.3);
            text-transform: uppercase;
          }
          .lock-card-header p {
            color: #8ab4b4;
            font-size: 0.85rem;
            margin-bottom: 25px;
            line-height: 1.5;
          }
          .vault-pin-form {
            display: flex;
            flex-direction: column;
            gap: 15px;
            text-align: left;
          }
          .pin-input-container {
            display: flex;
            flex-direction: column;
            gap: 6px;
          }
          .pin-input-row {
            display: flex;
            gap: 10px;
          }
          .pin-input-row input {
            flex: 1;
          }
          .pin-submit-btn {
            background: linear-gradient(135deg, #ff0055, #cc0044) !important;
            border: 1px solid #ff0055bb !important;
            color: #fff !important;
            font-family: var(--font-cyber) !important;
            letter-spacing: 1.5px !important;
            font-weight: bold !important;
            padding: 12px 20px !important;
            font-size: 0.88rem !important;
            transition: all 0.3s !important;
            box-shadow: 0 4px 15px rgba(255, 0, 85, 0.3) !important;
            cursor: pointer;
          }
          .pin-submit-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(255, 0, 85, 0.5) !important;
          }
          .cooldown-indicator {
            color: #ff3366;
            font-family: var(--font-mono);
            font-size: 2.2rem;
            font-weight: bold;
            letter-spacing: 4px;
            text-shadow: 0 0 15px rgba(255, 0, 85, 0.4);
            margin: 15px 0;
            text-align: center;
          }
          .cooldown-text {
            color: #888;
            font-size: 0.8rem;
            text-align: center;
            margin-top: 10px;
          }
          .auth-alert {
            background: rgba(255, 0, 85, 0.1) !important;
            border: 1px solid rgba(255, 0, 85, 0.3) !important;
            color: #ff3366 !important;
            padding: 12px !important;
            font-size: 0.85rem !important;
            border-radius: 6px !important;
            margin-bottom: 20px !important;
            text-shadow: 0 0 5px rgba(255, 0, 85, 0.2);
            text-align: center;
          }
          .auth-success {
            background: rgba(0, 255, 136, 0.1) !important;
            border: 1px solid rgba(0, 255, 136, 0.3) !important;
            color: #00ff88 !important;
            padding: 12px !important;
            font-size: 0.85rem !important;
            border-radius: 6px !important;
            margin-bottom: 20px !important;
            text-align: center;
          }
          .master-key-warning {
            display: flex;
            align-items: center;
            gap: 10px;
            background: #2a1a00;
            border: 1px solid #ff990044;
            padding: 12px 16px;
            margin-bottom: 10px;
            border-radius: 4px;
          }
          .warning-icon { font-size: 1.4rem; }
          .warning-text { color: #ffaa00; font-weight: bold; letter-spacing: 1px; font-size: 0.8rem; }
          .master-key-input { border-color: #ff990066 !important; }
          .master-key-input:focus { border-color: #ffaa00 !important; box-shadow: 0 0 8px #ffaa0033 !important; }
          .danger-btn { background: #2a0a0a !important; border-color: #ff4444 !important; color: #ff6666 !important; }
          .danger-btn:hover { background: #3a0a0a !important; color: #ff4444 !important; box-shadow: 0 0 10px #ff444433 !important; }
        `}</style>

        <div className="vault-lock-card">
          <div className="lock-shield-wrapper">
            {unlockStage === 'cooldown' ? '⏳' : '🔒'}
          </div>

          <div className="lock-card-header">
            <h3>{unlockStage === 'cooldown' ? 'SYSTEM LOCKOUT' : 'VAULT SESSION CLOSED'}</h3>
            <p>
              {unlockStage === 'cooldown'
                ? 'Security protocols active. PIN entry blocked due to authentication failures.'
                : 'Vault partition is encrypted. Please authenticate with local PIN code to mount directories.'}
            </p>
          </div>

          {vaultError && <div className="auth-alert">{vaultError}</div>}
          {vaultSuccess && <div className="auth-success">{vaultSuccess}</div>}

          {renderUnlockPanel()}
        </div>
      </div>
    );
  }

  return (
    <div className="vault-container">
      <style>{`
        /* Metrics row */
        .vault-stats-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 20px;
          margin-bottom: 25px;
        }
        @media (max-width: 1100px) {
          .vault-stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
        @media (max-width: 600px) {
          .vault-stats-grid { grid-template-columns: 1fr; }
        }
        .vault-stat-card {
          background: rgba(6, 12, 24, 0.45) !important;
          border: 1px solid rgba(0, 240, 255, 0.1) !important;
          box-shadow: inset 0 0 15px rgba(0, 240, 255, 0.02) !important;
          border-radius: 8px !important;
          padding: 18px !important;
          display: flex;
          align-items: center;
          gap: 15px;
          transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
        }
        .vault-stat-card:hover {
          border-color: rgba(0, 240, 255, 0.25) !important;
          box-shadow: 0 0 20px rgba(0, 240, 255, 0.08), inset 0 0 15px rgba(0, 240, 255, 0.04) !important;
          transform: translateY(-2px);
        }
        .vault-stat-icon {
          font-size: 2rem;
          background: rgba(0, 240, 255, 0.03);
          border: 1px solid rgba(0, 240, 255, 0.08);
          border-radius: 6px;
          width: 48px;
          height: 48px;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .vault-stat-details {
          display: flex;
          flex-direction: column;
          gap: 2px;
        }
        .vault-stat-value {
          font-size: 1.25rem;
          font-weight: bold;
          font-family: var(--font-mono);
          color: #fff;
        }
        .vault-stat-label {
          font-size: 0.72rem;
          letter-spacing: 1px;
          color: #8ab4b4;
          text-transform: uppercase;
          font-weight: bold;
        }
        .vault-stat-subtext {
          font-size: 0.72rem;
          color: #4a6a6a;
        }
        .secure-level-high { color: #00ff88 !important; text-shadow: 0 0 8px rgba(0, 255, 136, 0.2); }
        .secure-level-low { color: #ffaa00 !important; text-shadow: 0 0 8px rgba(255, 170, 0, 0.2); }

        /* Tabs styling */
        .vault-subtabs {
          display: flex;
          gap: 10px;
          margin-bottom: 25px;
          border-bottom: 1px solid rgba(0, 240, 255, 0.1);
          padding-bottom: 12px;
        }
        .subtab-btn {
          background: transparent;
          border: 1px solid transparent;
          color: #8ab4b4;
          padding: 10px 24px;
          cursor: pointer;
          font-family: var(--font-cyber);
          font-size: 0.85rem;
          font-weight: bold;
          text-transform: uppercase;
          letter-spacing: 1.5px;
          transition: all 0.3s ease;
          border-radius: 4px;
        }
        .subtab-btn:hover {
          color: #00f0ff;
          background: rgba(0, 240, 255, 0.03);
        }
        .subtab-btn.active {
          background: rgba(0, 240, 255, 0.08);
          border: 1px solid rgba(0, 240, 255, 0.3);
          color: #00f0ff;
          box-shadow: 0 0 15px rgba(0, 240, 255, 0.15);
        }

        /* Forms and Widgets UI polishing */
        .cyber-widget {
          border: 1px solid rgba(0, 240, 255, 0.1) !important;
          background: rgba(6, 12, 24, 0.5) !important;
          border-radius: 8px !important;
          padding: 20px !important;
        }
        .widget-title {
          border-bottom: 1px solid rgba(0, 240, 255, 0.15) !important;
          padding-bottom: 12px !important;
          font-family: var(--font-cyber) !important;
          font-weight: bold !important;
          letter-spacing: 1.5px !important;
          color: #00f0ff !important;
          text-shadow: 0 0 8px rgba(0, 240, 255, 0.2) !important;
          font-size: 0.85rem !important;
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 15px !important;
        }
        
        .encrypt-form-card {
          margin-bottom: 20px;
        }
        
        .encrypt-form {
          display: flex;
          flex-direction: column;
          gap: 15px;
        }
        
        .cyber-input {
          background: rgba(0, 0, 0, 0.4) !important;
          border: 1px solid rgba(0, 240, 255, 0.15) !important;
          border-radius: 4px !important;
          padding: 10px 12px !important;
          color: #fff !important;
          font-family: var(--font-mono) !important;
          font-size: 0.85rem !important;
          transition: all 0.2s !important;
        }
        .cyber-input:focus {
          border-color: #00f0ff !important;
          box-shadow: 0 0 8px rgba(0, 240, 255, 0.2) !important;
          background: rgba(0, 0, 0, 0.6) !important;
        }
        
        .encrypt-btn {
          background: linear-gradient(135deg, rgba(0, 240, 255, 0.2), rgba(0, 240, 255, 0.05)) !important;
          border: 1px solid rgba(0, 240, 255, 0.4) !important;
          color: #00f0ff !important;
          font-weight: bold !important;
          letter-spacing: 1px !important;
          font-family: var(--font-cyber) !important;
          padding: 12px !important;
          cursor: pointer;
          transition: all 0.3s !important;
        }
        .encrypt-btn:hover {
          background: rgba(0, 240, 255, 0.25) !important;
          box-shadow: 0 0 15px rgba(0, 240, 255, 0.3) !important;
          border-color: #00f0ff !important;
        }

        /* Config forms info display */
        .info-panel-sec {
          display: flex;
          flex-direction: column;
          gap: 12px;
          padding: 4px 0;
        }
        
        .divider {
          height: 1px;
          background: rgba(0, 240, 255, 0.1);
          margin: 12px 0;
        }

        /* Table custom styling */
        .vault-files-table-container {
          overflow-x: auto;
        }
        .file-cell {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .file-icon {
          font-size: 1.4rem;
        }
        .file-info {
          display: flex;
          flex-direction: column;
          gap: 2px;
        }
        .file-name {
          font-weight: bold;
          color: #fff;
          font-size: 0.85rem;
        }
        .file-path {
          font-size: 0.72rem;
          color: #4a6a6a;
          max-width: 320px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        
        .visibility-btn {
          background: rgba(0, 240, 255, 0.05);
          border: 1px solid rgba(0, 240, 255, 0.15);
          color: #00f0ff;
          cursor: pointer;
          font-size: 0.75rem;
          padding: 2px 8px;
          border-radius: 3px;
          font-weight: bold;
          font-family: var(--font-mono);
          transition: all 0.2s;
        }
        .visibility-btn:hover {
          background: rgba(0, 240, 255, 0.2);
          border-color: #00f0ff;
          color: #fff;
        }
        
        .cyber-table-btn {
          background: rgba(0, 240, 255, 0.05) !important;
          border: 1px solid rgba(0, 240, 255, 0.2) !important;
          color: #00f0ff !important;
          padding: 6px 12px !important;
          font-size: 0.75rem !important;
          font-family: var(--font-mono) !important;
          font-weight: bold !important;
          border-radius: 4px !important;
          cursor: pointer !important;
          transition: all 0.2s !important;
        }
        .cyber-table-btn:hover {
          background: rgba(0, 240, 255, 0.2) !important;
          border-color: #00f0ff !important;
          box-shadow: 0 0 10px rgba(0, 240, 255, 0.3) !important;
        }
        .cyber-table-btn.delete-btn {
          background: rgba(255, 0, 85, 0.05) !important;
          border: 1px solid rgba(255, 0, 85, 0.2) !important;
          color: #ff3366 !important;
        }
        .cyber-table-btn.delete-btn:hover {
          background: rgba(255, 0, 85, 0.2) !important;
          border-color: #ff0055 !important;
          box-shadow: 0 0 10px rgba(255, 0, 85, 0.3) !important;
        }
        .pulse-cyan-dot {
          display: inline-block;
          width: 8px;
          height: 8px;
          background: #00ff88;
          border-radius: 50%;
          box-shadow: 0 0 8px #00ff88;
          animation: pulse-dot 1.5s infinite;
        }
      `}</style>

      <h2 className="section-title">🔒 Cryptographic AES-256 Vault</h2>
      <p className="section-description">
        Securely encrypt sensitive local files or manage website logins using military-grade AES-256 authenticated encryption.
      </p>

      {/* Metrics Dashboard Row */}
      <div className="vault-stats-grid">
        <div className="vault-stat-card">
          <div className="vault-stat-icon">📁</div>
          <div className="vault-stat-details">
            <span className="vault-stat-label">Secured Files</span>
            <span className="vault-stat-value">{files.length}</span>
            <span className="vault-stat-subtext">Total weight: {formattedSize}</span>
          </div>
        </div>

        <div className="vault-stat-card">
          <div className="vault-stat-icon">🔑</div>
          <div className="vault-stat-details">
            <span className="vault-stat-label">Isolated Credentials</span>
            <span className="vault-stat-value">{passwords.length}</span>
            <span className="vault-stat-subtext">Credentials isolated</span>
          </div>
        </div>

        <div className="vault-stat-card">
          <div className="vault-stat-icon">🛡️</div>
          <div className="vault-stat-details">
            <span className="vault-stat-label">Vault Shield</span>
            <span className={`vault-stat-value ${hasMasterKey ? 'secure-level-high' : 'secure-level-low'}`}>
              {hasMasterKey ? 'SECURE' : 'VULNERABLE'}
            </span>
            <span className="vault-stat-subtext">
              {hasMasterKey ? 'Master key active' : 'Master key unconfigured'}
            </span>
          </div>
        </div>

        <div className="vault-stat-card">
          <div className="vault-stat-icon">⚡</div>
          <div className="vault-stat-details">
            <span className="vault-stat-label">Session Status</span>
            <span className="vault-stat-value">
              <span className="pulse-cyan-dot" style={{ marginRight: '6px' }}></span>
              ACTIVE
            </span>
            <span className="vault-stat-subtext">Idle-monitoring active</span>
          </div>
        </div>
      </div>

      {/* Sub tabs selector */}
      <div className="vault-subtabs">
        <button className={`subtab-btn ${activeSubTab === 'files' ? 'active' : ''}`} onClick={() => setActiveSubTab('files')}>
          📁 File Encryption
        </button>
        <button className={`subtab-btn ${activeSubTab === 'passwords' ? 'active' : ''}`} onClick={() => setActiveSubTab('passwords')}>
          🔑 Password Vault
        </button>
      </div>

      {vaultError && <div className="auth-alert" style={{ marginBottom: '20px' }}>{vaultError}</div>}
      {vaultSuccess && <div className="auth-success" style={{ marginBottom: '20px' }}>{vaultSuccess}</div>}

      <div className="vault-grid">
        {/* Left Column: Form actions & settings */}
        <div className="vault-panel-left">
          {/* Active form based on subtab selection */}
          {activeSubTab === 'files' ? (
            <div className="cyber-widget encrypt-form-card">
              <div className="widget-title"><span>ENCRYPT SOURCE PATH</span></div>
              <form onSubmit={handleEncrypt} className="encrypt-form">
                <div className="form-group">
                  <label className="form-label">Absolute Source File Path</label>
                  <input type="text" className="cyber-input"
                    placeholder="/home/user/documents/tax.pdf"
                    value={filePath} onChange={e => setFilePath(e.target.value)} required />
                </div>
                <button type="submit" className="cyber-btn encrypt-btn">🔑 RUN AES-256 ENCRYPTION</button>
              </form>
            </div>
          ) : (
            <div className="cyber-widget encrypt-form-card">
              <div className="widget-title"><span>STORE LOGIN CREDENTIALS</span></div>
              <form onSubmit={handleAddPassword} className="encrypt-form">
                <div className="form-group">
                  <label className="form-label">Website / Service Domain</label>
                  <input type="text" className="cyber-input" placeholder="e.g. google.com"
                    value={websiteInput} onChange={e => setWebsiteInput(e.target.value)} required />
                </div>
                <div className="form-group">
                  <label className="form-label">Username / Email</label>
                  <input type="text" className="cyber-input" placeholder="Enter username..."
                    value={usernameInput} onChange={e => setUsernameInput(e.target.value)} required />
                </div>
                <div className="form-group">
                  <label className="form-label">Password</label>
                  <input type="password" className="cyber-input" placeholder="Enter credential password..."
                    value={passwordInput} onChange={e => setPasswordInput(e.target.value)} required />
                </div>
                <button type="submit" className="cyber-btn encrypt-btn">🔑 SECURELY ENCRYPT & STORE</button>
              </form>
            </div>
          )}

          {/* Combined Operations settings card */}
          <div className="cyber-widget">
            <div className="widget-title">
              <span>SYSTEM SECURITY CONTROLS</span>
            </div>
            
            <div className="info-panel-sec">
              <button
                className="cyber-btn"
                style={{
                  width: '100%',
                  background: '#1a0a0a',
                  borderColor: '#ff444466',
                  color: '#ff6666',
                  fontWeight: 'bold',
                  fontFamily: 'var(--font-cyber)',
                  letterSpacing: '1px',
                  padding: '10px'
                }}
                onClick={handleToggle}
              >
                🔒 LOCK VAULT OVERRIDE
              </button>

              <div className="divider"></div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span className="form-label" style={{ margin: 0, fontSize: '0.78rem' }}>MASTER KEY:</span>
                <span style={{
                  fontSize: '0.72rem', fontWeight: 'bold', letterSpacing: '1px',
                  color: hasMasterKey ? '#00ff88' : '#ffaa00',
                  background: hasMasterKey ? '#00ff8811' : '#ffaa0011',
                  border: `1px solid ${hasMasterKey ? '#00ff8822' : '#ffaa0022'}`,
                  padding: '2px 8px',
                  borderRadius: '3px'
                }}>
                  {hasMasterKey ? 'ACTIVE' : 'VULNERABLE'}
                </span>
              </div>

              {!showMasterKeyPanel ? (
                <div>
                  <p style={{ color: '#888', fontSize: '0.8rem', marginBottom: '10px', lineHeight: '1.4' }}>
                    {hasMasterKey
                      ? 'Recovery key is active. It will allow you to bypass PIN block in an emergency.'
                      : 'Emergency recovery is disabled. Set master key to prevent permanent PIN lockout.'}
                  </p>
                  <button
                    className="cyber-btn"
                    style={{ width: '100%', fontSize: '0.8rem', padding: '8px' }}
                    onClick={() => { setShowMasterKeyPanel(true); setMkError(''); setMkSuccess(''); }}
                  >
                    🔑 {hasMasterKey ? 'MANAGE MASTER KEY' : 'CONFIGURE MASTER KEY'}
                  </button>
                </div>
              ) : (
                <form onSubmit={handleSetupMasterKey} style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '5px' }}>
                  {mkError && <div className="auth-alert" style={{ marginBottom: '5px', fontSize: '0.78rem', padding: '8px' }}>{mkError}</div>}
                  {mkSuccess && <div className="auth-success" style={{ marginBottom: '5px', fontSize: '0.78rem', padding: '8px' }}>{mkSuccess}</div>}

                  <div className="form-group" style={{ marginBottom: '2px' }}>
                    <label className="form-label" style={{ fontSize: '0.75rem' }}>CURRENT VAULT PIN</label>
                    <input
                      type="password"
                      className="cyber-input pin-input"
                      placeholder="Enter PIN to verify..."
                      value={mkCurrentPin}
                      onChange={e => setMkCurrentPin(e.target.value)}
                      maxLength={8}
                      required
                    />
                  </div>
                  <div className="form-group" style={{ marginBottom: '4px' }}>
                    <label className="form-label" style={{ fontSize: '0.75rem' }}>
                      {hasMasterKey ? 'NEW MASTER KEY' : 'SET MASTER KEY'}
                    </label>
                    <input
                      type="password"
                      className="cyber-input pin-input"
                      placeholder="Min 4 characters..."
                      value={mkNewKey}
                      onChange={e => setMkNewKey(e.target.value)}
                      minLength={4}
                      required
                    />
                  </div>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button type="submit" className="cyber-btn" style={{ flex: 1, fontSize: '0.78rem', padding: '8px' }}>
                      💾 SAVE
                    </button>
                    <button
                      type="button"
                      className="cyber-btn"
                      style={{ fontSize: '0.78rem', padding: '8px 12px', background: 'transparent', color: '#888', borderColor: '#333' }}
                      onClick={() => { setShowMasterKeyPanel(false); setMkCurrentPin(''); setMkNewKey(''); setMkError(''); }}
                    >
                      CANCEL
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Table of secured entries */}
        <div className="vault-panel-right">
          <div className="cyber-widget vault-files-card" style={{ height: '100%' }}>
            <div className="widget-title">
              <span>SECURED ARCHIVE INDEX</span>
              <span style={{ fontSize: '0.72rem', color: '#00f0ffb8', background: 'rgba(0, 240, 255, 0.05)', padding: '2px 8px', border: '1px solid rgba(0, 240, 255, 0.1)', borderRadius: '3px' }}>
                {activeSubTab === 'files' ? `${files.length} FILES` : `${passwords.length} CREDENTIALS`}
              </span>
            </div>

            {activeSubTab === 'files' ? (
              files.length === 0 ? (
                <div className="vault-empty-placeholder" style={{ padding: '60px 20px', textAlign: 'center', color: '#4a6a6a' }}>
                  <p style={{ fontSize: '1.2rem', marginBottom: '10px' }}>📁</p>
                  <p style={{ fontSize: '0.85rem' }}>No files encrypted yet. Enter a source file path in the control panel to encrypt.</p>
                </div>
              ) : (
                <div className="vault-files-table-container">
                  <table className="cyber-table">
                    <thead>
                      <tr>
                        <th>FILE NAME</th>
                        <th>DATE ENCRYPTED</th>
                        <th>SIZE</th>
                        <th>ACTION</th>
                      </tr>
                    </thead>
                    <tbody>
                      {files.map(file => (
                        <tr key={file.file_id}>
                          <td>
                            <div className="file-cell">
                              <span className="file-icon">📄</span>
                              <div className="file-info">
                                <span className="file-name">{file.file_name}</span>
                                <span className="file-path">{file.path}</span>
                              </div>
                            </div>
                          </td>
                          <td>{new Date(file.encrypted_at).toLocaleString()}</td>
                          <td>{(file.size / 1024).toFixed(2)} KB</td>
                          <td>
                            <button className="cyber-table-btn" onClick={() => handleDecrypt(file.file_id)}>
                              DECRYPT
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )
            ) : (
              passwords.length === 0 ? (
                <div className="vault-empty-placeholder" style={{ padding: '60px 20px', textAlign: 'center', color: '#4a6a6a' }}>
                  <p style={{ fontSize: '1.2rem', marginBottom: '10px' }}>🔑</p>
                  <p style={{ fontSize: '0.85rem' }}>No credentials saved yet. Submit domain accounts to secure them in password partition.</p>
                </div>
              ) : (
                <div className="vault-files-table-container">
                  <table className="cyber-table">
                    <thead>
                      <tr>
                        <th>WEBSITE</th>
                        <th>USERNAME</th>
                        <th>PASSWORD</th>
                        <th>ACTION</th>
                      </tr>
                    </thead>
                    <tbody>
                      {passwords.map(pwd => (
                        <tr key={pwd.id}>
                          <td>
                            <div className="file-cell">
                              <span className="file-icon">🌐</span>
                              <div className="file-info">
                                <span className="file-name">{pwd.website}</span>
                              </div>
                            </div>
                          </td>
                          <td><code>{pwd.username}</code></td>
                          <td>
                            <span style={{ marginRight: '8px', fontFamily: 'monospace' }}>
                              {visiblePasswords[pwd.id] ? pwd.password : '••••••••••••'}
                            </span>
                            <button className="visibility-btn" onClick={() => togglePasswordVisibility(pwd.id)}>
                              {visiblePasswords[pwd.id] ? 'HIDE' : 'REVEAL'}
                            </button>
                          </td>
                          <td>
                            <button className="cyber-table-btn delete-btn" onClick={() => handleDeletePassword(pwd.id)}>
                              DELETE
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default Vault;
