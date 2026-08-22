import { useState, useEffect, useRef } from 'react';
import toast, { Toaster } from 'react-hot-toast';
import logoImg from './assets/logvigil_logo.png';
import './App.css';

// Import components
import Sidebar from './components/Sidebar';
import Overview from './pages/Overview';
import Vault from './pages/Vault';
import Firewall from './pages/Firewall';
import Integrity from './pages/Integrity';
import Network from './pages/Network';
import Threats from './pages/Threats';
import Timeline from './pages/Timeline';
import Phishing from './pages/Phishing';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import Activity from './pages/Activity';

function App() {
  const [backendConnected, setBackendConnected] = useState(null); // null = testing, true = ok, false = offline
  const [backendMessage, setBackendMessage] = useState('FETCHING STATUS...');
  const [logs, setLogs] = useState([]);
  const [pingCount, setPingCount] = useState(0);
  const [currentTime, setCurrentTime] = useState('');
  
  // Navigation active tab
  const [activeTab, setActiveTab] = useState('overview');

  // Auth state
  const [user, setUser] = useState(localStorage.getItem('logvigil_user') || null);
  const [token, setToken] = useState(localStorage.getItem('logvigil_token') || null);
  const [isRegisterMode, setIsRegisterMode] = useState(false);
  const [usernameInput, setUsernameInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [authError, setAuthError] = useState('');
  const [authSuccess, setAuthSuccess] = useState('');
  // Login brute-force UX state
  const [loginFailCount, setLoginFailCount] = useState(0);
  const [loginLockoutSeconds, setLoginLockoutSeconds] = useState(0);
  const loginLockoutRef = useRef(null);

  const terminalEndRef = useRef(null);
  const logfeedRef = useRef(null);

  // ── Animated log feed background for login page ──
  useEffect(() => {
    if (user) return; // Only run on login screen
    const el = logfeedRef.current;
    if (!el) return;

    const templates = [
      { cls: 'lv-lg-ok',   text: h => `${h} logvigil sshd[1122]: Accepted publickey for root from 10.0.4.12 port 51422` },
      { cls: 'lv-lg-info', text: h => `${h} logvigil kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.4 DPT=22` },
      { cls: 'lv-lg-warn', text: h => `${h} logvigil sudo: pam_unix(sudo:auth): authentication failure; user=deploy` },
      { cls: 'lv-lg-crit', text: h => `${h} logvigil iptables: DROP TCP 203.0.113.7:443 -> 10.0.4.12:8080` },
      { cls: 'lv-lg-info', text: h => `${h} logvigil systemd[1]: Started Session 4821 of user analyst` },
      { cls: 'lv-lg-ok',   text: h => `${h} logvigil cron[882]: (root) CMD (logvigil-scan --level=deep)` },
      { cls: 'lv-lg-warn', text: h => `${h} logvigil auditd: PAM: authentication acct="root" exe="/usr/bin/su"` },
      { cls: 'lv-lg-info', text: h => `${h} logvigil networkd: eth0: link is up, 1000Mbps, full-duplex` },
      { cls: 'lv-lg-crit', text: h => `${h} logvigil fail2ban: [sshd] Ban 91.240.118.22 (5 attempts)` },
      { cls: 'lv-lg-info', text: h => `${h} logvigil logvigil-core: checksum verified for /var/log/auth.log` },
      { cls: 'lv-lg-ok',   text: h => `${h} logvigil dockerd: container 4f2a9c health=passing` },
      { cls: 'lv-lg-warn', text: h => `${h} logvigil kernel: TCP: request_sock_TCP: Possible SYN flooding` },
    ];

    const pad = n => n.toString().padStart(2, '0');
    const stamp = () => { const d = new Date(); return `[${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}]`; };

    const colCount = window.innerWidth < 700 ? 1 : window.innerWidth < 1100 ? 2 : 3;
    const cols = [];
    for (let i = 0; i < colCount; i++) {
      const c = document.createElement('div');
      c.className = 'lv-logfeed-col';
      el.appendChild(c);
      cols.push(c);
    }

    const spawn = () => {
      const tpl = templates[Math.floor(Math.random() * templates.length)];
      const line = document.createElement('div');
      line.className = tpl.cls;
      line.textContent = tpl.text(stamp());
      const col = cols[Math.floor(Math.random() * cols.length)];
      col.appendChild(line);
      if (col.childNodes.length > 40) col.removeChild(col.firstChild);
    };

    for (let i = 0; i < 60; i++) spawn();
    const interval = setInterval(spawn, 550);
    return () => { clearInterval(interval); el.innerHTML = ''; };
  }, [user]);

  // Clock tick effect
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toLocaleString());
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  // Auto-scroll terminal logs
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Custom log writer & toast triggers
  const addLog = (text, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, { text: `[${timestamp}] ${text}`, type }]);

    if (type === 'success') {
      toast.success(text, { id: text });
    } else if (type === 'error') {
      toast.error(text, { id: text });
    } else if (type === 'warn') {
      toast(text, { icon: '⚠️', id: text });
    }
  };

  // Connect to backend API
  const pingBackend = async () => {
    addLog('Querying Security Gateway API: GET http://localhost:8000/...', 'info');
    
    try {
      const controller = new AbortController();
      const id = setTimeout(() => controller.abort(), 3000); // 3s timeout
      
      const response = await fetch('http://localhost:8000/', { signal: controller.signal });
      clearTimeout(id);
      
      if (!response.ok) {
        throw new Error(`HTTP Error ${response.status}`);
      }
      
      const data = await response.json();
      setBackendConnected(true);
      setBackendMessage(data.message || 'HELLO LOGVIGIL');
      addLog(`Success payload established: "${data.message || 'Hello LogVigil'}"`, 'success');
    } catch (error) {
      setBackendConnected(false);
      setBackendMessage('CONNECTION OFFLINE');
      addLog(`Handshake Failed: ${error.message}. LogVigil daemon unresponsive.`, 'error');
      addLog(`Tip: Ensure the FastAPI server is running with 'uvicorn main:app --reload' in '/backend/' directory.`, 'warn');
    }
    setPingCount((prev) => prev + 1);
  };

  // Initial boot and token validation sequence
  useEffect(() => {
    const bootSequence = [
      { text: 'Loading LogVigil Core Cryptographic Kernel...', type: 'info', delay: 100 },
      { text: 'Setting up client port listener: 5173', type: 'info', delay: 300 },
      { text: 'SQLite database module initialized successfully.', type: 'success', delay: 600 },
      { text: 'Memory profiles verified: Core execution mode enabled.', type: 'info', delay: 900 },
      { text: 'Pre-flight integrity self-test: PASS', type: 'success', delay: 1200 },
    ];

    bootSequence.forEach((item) => {
      setTimeout(() => {
        addLog(item.text, item.type);
      }, item.delay);
    });

    // Execute first handshake attempt after boot sequence
    setTimeout(() => {
      pingBackend();
    }, 1500);

    // Verify token with backend if exists
    const savedToken = localStorage.getItem('logvigil_token');
    const savedUser = localStorage.getItem('logvigil_user');
    if (savedToken && savedUser) {
      setTimeout(() => {
        addLog(`Verifying stored session token for operator: ${savedUser}...`, 'info');
        fetch('http://localhost:8000/api/auth/me', {
          headers: {
            'Authorization': `Bearer ${savedToken}`
          }
        })
        .then(res => {
          if (res.ok) return res.json();
          throw new Error('Session expired');
        })
        .then(data => {
          setUser(data.username);
          setToken(savedToken);
          addLog(`Session token verified. Active operator session restored.`, 'success');
        })
        .catch(err => {
          localStorage.removeItem('logvigil_token');
          localStorage.removeItem('logvigil_user');
          setUser(null);
          setToken(null);
          addLog(`Stored session invalid or expired: ${err.message}`, 'warn');
        });
      }, 1600);
    }
  }, []);

  const handleRegister = async (e) => {
    e.preventDefault();
    setAuthError('');
    setAuthSuccess('');
    addLog(`Initiating registration sequence for operator: ${usernameInput}`, 'info');

    try {
      const response = await fetch('http://localhost:8000/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: usernameInput, password: passwordInput })
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || 'Registration failed');
      }

      setAuthSuccess('Registration successful. Access gateway using credentials.');
      addLog(`Registration complete. Operator database updated for: ${usernameInput}`, 'success');
      setIsRegisterMode(false);
      setPasswordInput('');
    } catch (err) {
      setAuthError(err.message);
      addLog(`Registration failed: ${err.message}`, 'error');
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setAuthError('');
    setAuthSuccess('');

    // Don't allow submit if locally tracking a lockout
    if (loginLockoutSeconds > 0) return;

    addLog(`Validating credentials with core API: ${usernameInput}`, 'info');

    try {
      const response = await fetch('http://localhost:8000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: usernameInput, password: passwordInput })
      });

      const data = await response.json();

      if (response.status === 429) {
        // Backend-enforced lockout
        const secs = parseInt(response.headers.get('X-Lockout-Seconds') || '900');
        setLoginLockoutSeconds(secs);
        setAuthError(`Access temporarily restricted. Try again in ${Math.ceil(secs / 60)} minute(s).`);
        addLog('Login locked out by security policy.', 'error');
        // Start countdown
        if (loginLockoutRef.current) clearInterval(loginLockoutRef.current);
        loginLockoutRef.current = setInterval(() => {
          setLoginLockoutSeconds(prev => {
            if (prev <= 1) { clearInterval(loginLockoutRef.current); return 0; }
            return prev - 1;
          });
        }, 1000);
        return;
      }

      if (!response.ok) {
        const newCount = loginFailCount + 1;
        setLoginFailCount(newCount);
        // Vague hint after multiple local failures — doesn't reveal server threshold
        if (newCount >= 3) {
          setAuthError('Multiple failed attempts detected. Verify your credentials carefully.');
        } else {
          setAuthError(data.detail || 'Invalid username or password');
        }
        addLog(`Credentials rejected: ${data.detail}`, 'error');
        return;
      }

      // Success — reset counters
      setLoginFailCount(0);
      setLoginLockoutSeconds(0);
      if (loginLockoutRef.current) clearInterval(loginLockoutRef.current);

      localStorage.setItem('logvigil_token', data.token);
      localStorage.setItem('logvigil_user', data.username);
      setUser(data.username);
      setToken(data.token);
      setAuthError('');

      addLog(`Credentials accepted. SecureLink established with operator: ${data.username}`, 'success');
    } catch (err) {
      setAuthError(err.message);
      addLog(`Credentials rejected: ${err.message}`, 'error');
    }
  };

  const handleLogout = async () => {
    addLog('Initiating secure logout sequence...', 'info');
    if (token) {
      try {
        await fetch('http://localhost:8000/api/auth/logout', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` }
        });
      } catch (err) {
        // Local logout proceeds regardless of API response
      }
    }
    localStorage.removeItem('logvigil_token');
    localStorage.removeItem('logvigil_user');
    setUser(null);
    setToken(null);
    setUsernameInput('');
    setPasswordInput('');
    setActiveTab('overview');
    addLog('Operator session terminated. Interface locked.', 'warn');
  };

  // Render the selected view tab content
  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return (
          <Overview
            logs={logs}
            pingBackend={pingBackend}
            pingCount={pingCount}
            backendConnected={backendConnected}
            backendMessage={backendMessage}
            terminalEndRef={terminalEndRef}
          />
        );
      case 'vault':
        return <Vault addLog={addLog} />;
      case 'firewall':
        return <Firewall addLog={addLog} />;
      case 'integrity':
        return <Integrity addLog={addLog} username={user} />;
      case 'network':
        return <Network addLog={addLog} />;
      case 'threats':
        return <Threats addLog={addLog} />;
      case 'timeline':
        return <Timeline addLog={addLog} />;
      case 'phishing':
        return <Phishing addLog={addLog} />;
      case 'reports':
        return <Reports addLog={addLog} />;
      case 'settings':
        return <Settings addLog={addLog} />;
      case 'activity':
        return <Activity addLog={addLog} />;
      default:
        return <div className="page-error">Invalid active partition selector</div>;
    }
  };

  return (
    <div className="cyber-main-layout">
      {!user ? (
        <div className="lv-login-scene">
          {/* ── Animated log feed background ── */}
          <div id="lv-logfeed" ref={logfeedRef}></div>

          {/* ── Decorative layers ── */}
          <div className="lv-grid-overlay"></div>
          <div className="lv-radar"></div>
          <div className="lv-radar-sweep"></div>
          <div className="lv-vignette"></div>
          <div className="lv-scanlines"></div>

          {/* ── Stage content ── */}
          <div className="lv-stage">
            <header className="lv-topbar">
              <div className="lv-badge">🔒</div>
              <div className="lv-brandtext">
                <img src={logoImg} alt="LogVigil" className="login-logo-img lv-logo-img" />
                <div className="lv-brand-info">
                  <div className="lv-brand-name">LOGVIGIL</div>
                  <div className="lv-brand-sub">System Monitor // Encrypted Gateway Console</div>
                </div>
              </div>
            </header>

            <h1 className="lv-masthead" data-text="LOGVIGIL // LINUX SECURITY MONITOR &amp; LOG ANALYZER">
              LOGVIGIL // LINUX SECURITY MONITOR &amp; LOG ANALYZER
            </h1>

            <div className="lv-tagline">
              <span className="lv-dot"></span>
              LINK STATUS: LISTENING &nbsp;|&nbsp; NODES ONLINE: 214 &nbsp;|&nbsp; THREAT LEVEL: NOMINAL
            </div>

            <div className="lv-content">
              <div className="lv-cardwrap">
                <div className="lv-corner lv-tl"></div>
                <div className="lv-corner lv-tr"></div>
                <div className="lv-corner lv-bl"></div>
                <div className="lv-corner lv-br"></div>

                <div className="lv-card">
                  <div className="lv-protocol">
                    {isRegisterMode ? 'REGISTER OPERATOR' : 'LOGVIGIL LOGIN PROTOCOL'}
                  </div>
                  <div className="lv-protocol-sub">
                    {isRegisterMode ? 'Create your secure operator credentials' : 'Authenticate to continue monitoring'}
                  </div>

                  <form onSubmit={isRegisterMode ? handleRegister : handleLogin}>
                    <div className="lv-field">
                      <label className="lv-fieldlabel">Username</label>
                      <div className="lv-input-wrap">
                        <span className="lv-icon">●</span>
                        <input
                          type="text"
                          className="lv-input"
                          placeholder="operator_id"
                          value={usernameInput}
                          onChange={(e) => setUsernameInput(e.target.value)}
                          required
                        />
                      </div>
                    </div>

                    <div className="lv-field">
                      <label className="lv-fieldlabel">Master Password</label>
                      <div className="lv-input-wrap">
                        <span className="lv-icon">🔑</span>
                        <input
                          type="password"
                          className="lv-input"
                          placeholder="••••••••••••"
                          value={passwordInput}
                          onChange={(e) => setPasswordInput(e.target.value)}
                          required
                        />
                      </div>
                    </div>

                    {!isRegisterMode && (
                      <div className="lv-metarow">
                        <span>AES-256 SESSION</span>
                        <span className="lv-meta-link">Forgot key?</span>
                      </div>
                    )}

                    {authError && <div className="auth-alert" style={{ marginBottom: '14px' }}>{authError}</div>}
                    {authSuccess && <div className="auth-success" style={{ marginBottom: '14px' }}>{authSuccess}</div>}

                    <button
                      type="submit"
                      className="lv-establish-btn"
                      disabled={loginLockoutSeconds > 0}
                      style={{ opacity: loginLockoutSeconds > 0 ? 0.5 : 1 }}
                    >
                      {loginLockoutSeconds > 0
                        ? `⏳ ${Math.floor(loginLockoutSeconds / 60)}m ${(loginLockoutSeconds % 60).toString().padStart(2, '0')}s`
                        : isRegisterMode ? 'Register Operator' : 'Establish Link'
                      }
                    </button>
                  </form>

                  <div className="lv-registerline">
                    {isRegisterMode ? (
                      <>
                        Already registered?{' '}
                        <span className="lv-reg-link" onClick={() => { setIsRegisterMode(false); setAuthError(''); setAuthSuccess(''); }}>
                          Access Gateway
                        </span>
                      </>
                    ) : (
                      <>
                        First time operator?{' '}
                        <span className="lv-reg-link" onClick={() => { setIsRegisterMode(true); setAuthError(''); setAuthSuccess(''); }}>
                          Register key
                        </span>
                      </>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* ── Status ticker ── */}
          <div className="lv-ticker">
            <span className="lv-ticker-track">
              <span className="lv-ticker-seg lv-cy">[GW-04]</span> handshake stable
              <span className="lv-ticker-seg">tls_version=1.3</span>
              <span className="lv-ticker-seg lv-ok">[OK]</span> integrity check passed
              <span className="lv-ticker-seg">watchdog: 00:14:22 uptime</span>
              <span className="lv-ticker-seg lv-warn">[WARN]</span> 3 failed auth attempts blocked from 41.222.x.x
              <span className="lv-ticker-seg">journald sync complete</span>
              <span className="lv-ticker-seg lv-cy">[GW-04]</span> handshake stable
              <span className="lv-ticker-seg">tls_version=1.3</span>
              <span className="lv-ticker-seg lv-ok">[OK]</span> integrity check passed
              <span className="lv-ticker-seg">watchdog: 00:14:22 uptime</span>
              <span className="lv-ticker-seg lv-warn">[WARN]</span> 3 failed auth attempts blocked from 41.222.x.x
              <span className="lv-ticker-seg">journald sync complete</span>
            </span>
          </div>
        </div>
      ) : (
        <div className="cyber-dashboard-layout">
          {/* Left Side: Navigation Panel */}
          <Sidebar
            activeTab={activeTab}
            setActiveTab={setActiveTab}
            user={user}
            onLogout={handleLogout}
          />

          {/* Right Side: Working Pane Content */}
          <main className="cyber-content-pane">
            <header className="pane-header">
              <span className="system-indicator">LOGVIGIL // LIVE DAEMON CONTROLS</span>
              <div className="pane-header-right">
                <span className="cyber-clock">SYS_TIME: <span className="glow-cyan">{currentTime}</span></span>
                <span className="gateway-badge">
                  <span className={`badge-dot ${backendConnected ? 'active' : ''}`}></span>
                  GATEWAY: {backendConnected ? 'CONNECTED' : 'OFFLINE'}
                </span>
              </div>
            </header>
            
            <div className="pane-view-viewport">
              {renderTabContent()}
            </div>
          </main>
        </div>
      )}
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#0c1620',
            color: '#00f0ff',
            border: '1px solid #00f0ff44',
            fontFamily: 'monospace',
            fontSize: '13px',
            boxShadow: '0 0 10px rgba(0, 240, 255, 0.2)'
          },
          success: {
            iconTheme: {
              primary: '#00f0ff',
              secondary: '#0c1620',
            },
          },
          error: {
            style: {
              background: '#1a0c0c',
              color: '#ff4444',
              border: '1px solid #ff444444',
            },
            iconTheme: {
              primary: '#ff4444',
              secondary: '#1a0c0c',
            },
          },
        }}
      />
    </div>
  );
}

export default App;
