import { useState, useEffect, useRef } from 'react';
import toast, { Toaster } from 'react-hot-toast';
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
        return <Integrity addLog={addLog} />;
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
      default:
        return <div className="page-error">Invalid active partition selector</div>;
    }
  };

  return (
    <div className="cyber-main-layout">
      {!user ? (
        <div className="app-container">
          <header className="cyber-header" style={{ justifyContent: 'center' }}>
            <div className="logo-container">
              <span className="logo-icon glow-cyan">🛡️</span>
              <div className="system-title">
                <h1>LogVigil // Linux Security Monitor & Log Analyzer</h1>
                <p>System Monitor | Encrypted Gateway Console</p>
              </div>
            </div>
          </header>

          <div className="auth-wrapper">
            <div className="auth-card">
              <h2 className="auth-title">
                {isRegisterMode ? "REGISTER OPERATOR CREDENTIALS" : "LOGVIGIL LOGIN PROTOCOL"}
              </h2>
              
              <form className="auth-form" onSubmit={isRegisterMode ? handleRegister : handleLogin}>
                <div className="form-group">
                  <label className="form-label">Username</label>
                  <div className="input-container">
                    <span className="input-icon">👤</span>
                    <input
                      type="text"
                      className="cyber-input"
                      placeholder="Enter operator code..."
                      value={usernameInput}
                      onChange={(e) => setUsernameInput(e.target.value)}
                      required
                    />
                  </div>
                </div>
                
                <div className="form-group">
                  <label className="form-label">Master Password</label>
                  <div className="input-container">
                    <span className="input-icon">🔑</span>
                    <input
                      type="password"
                      className="cyber-input"
                      placeholder="Enter security key..."
                      value={passwordInput}
                      onChange={(e) => setPasswordInput(e.target.value)}
                      required
                    />
                  </div>
                </div>
                
                {authError && <div className="auth-alert">{authError}</div>}
                {authSuccess && <div className="auth-success">{authSuccess}</div>}
                
                <button
                  type="submit"
                  className="cyber-btn"
                  style={{ width: '100%', marginTop: '10px', opacity: loginLockoutSeconds > 0 ? 0.5 : 1 }}
                  disabled={loginLockoutSeconds > 0}
                >
                  {loginLockoutSeconds > 0
                    ? `⏳ ${Math.floor(loginLockoutSeconds / 60)}m ${(loginLockoutSeconds % 60).toString().padStart(2, '0')}s`
                    : isRegisterMode ? 'Register Operator' : 'Establish Link'
                  }
                </button>
              </form>
              
              <div className="auth-footer">
                {isRegisterMode ? (
                  <>
                    Already registered?
                    <span className="auth-link" onClick={() => { setIsRegisterMode(false); setAuthError(''); setAuthSuccess(''); }}>
                      Access Gateway
                    </span>
                  </>
                ) : (
                  <>
                    First time operator?
                    <span className="auth-link" onClick={() => { setIsRegisterMode(true); setAuthError(''); setAuthSuccess(''); }}>
                      Register Key
                    </span>
                  </>
                )}
              </div>
            </div>
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
