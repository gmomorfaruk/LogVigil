import React, { useState, useEffect } from 'react';
import { Radar, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  RadialLinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';
import LiveMonitor from '../components/LiveMonitor';

ChartJS.register(
  RadialLinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
  Legend,
  ArcElement
);

function Overview({ logs, pingBackend, pingCount, backendConnected, backendMessage, terminalEndRef }) {
  const [scoreData, setScoreData] = useState({ overall_score: 0, breakdown: {} });
  const [recommendations, setRecommendations] = useState([]);
  const [firewallStatus, setFirewallStatus] = useState({ enabled: false });
  const [vaultStatus, setVaultStatus] = useState({ locked: true });
  const [networkStatus, setNetworkStatus] = useState({ active: false });
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    // Fetch stats to show real status
    fetch('http://localhost:8000/api/security-score')
      .then((res) => res.json())
      .then((data) => setScoreData(data))
      .catch(() => {});

    fetch('http://localhost:8000/api/firewall/status')
      .then((res) => res.json())
      .then((data) => setFirewallStatus(data))
      .catch(() => {});

    fetch('http://localhost:8000/api/vault/status')
      .then((res) => res.json())
      .then((data) => setVaultStatus(data))
      .catch(() => {});

    fetch('http://localhost:8000/api/network/status')
      .then((res) => res.json())
      .then((data) => setNetworkStatus(data))
      .catch(() => {});
  }, [backendConnected]);

  // Fetch active alerts dynamically for live monitor
  useEffect(() => {
    const fetchAlerts = () => {
      fetch('http://localhost:8000/api/alerts/recommendations')
        .then((res) => res.json())
        .then((data) => setRecommendations(data))
        .catch(() => {});
    };
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, [backendConnected]);

  // Animate score number on change
  useEffect(() => {
    const target = scoreData.overall_score;
    if (animatedScore === target) return;

    const step = target > animatedScore ? 1 : -1;
    const timer = setInterval(() => {
      setAnimatedScore((prev) => {
        if (prev === target) {
          clearInterval(timer);
          return prev;
        }
        return prev + step;
      });
    }, 15);
    return () => clearInterval(timer);
  }, [scoreData.overall_score]);

  const getScoreColor = (score) => {
    if (score >= 80) return '#00f0ff';
    if (score >= 50) return '#ffc107';
    return '#ff4444';
  };

  // Radar chart configuration
  const bd = scoreData.breakdown || {};
  const radarData = {
    labels: ['Firewall', 'Vault', 'Integrity', 'Network', 'Credentials'],
    datasets: [
      {
        label: 'Security Score',
        data: [
          bd.firewall_score || 0,
          bd.vault_score || 0,
          bd.integrity_score || 0,
          bd.network_score || 0,
          bd.password_score || 0,
        ],
        backgroundColor: 'rgba(0, 240, 255, 0.12)',
        borderColor: '#00f0ff',
        borderWidth: 2,
        pointBackgroundColor: '#00f0ff',
        pointBorderColor: '#00f0ff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: '#00f0ff',
        pointRadius: 5,
        pointHoverRadius: 7,
      },
    ],
  };

  const radarOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      r: {
        beginAtZero: true,
        max: 100,
        ticks: {
          stepSize: 20,
          color: '#4a6a6a',
          backdropColor: 'transparent',
          font: { size: 10 },
        },
        grid: {
          color: 'rgba(0, 240, 255, 0.08)',
        },
        angleLines: {
          color: 'rgba(0, 240, 255, 0.12)',
        },
        pointLabels: {
          color: '#8ab4b4',
          font: { size: 11, weight: 'bold', family: "'Courier New', monospace" },
        },
      },
    },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: 'rgba(10, 20, 30, 0.95)',
        titleColor: '#00f0ff',
        bodyColor: '#c0d0d0',
        borderColor: '#00f0ff33',
        borderWidth: 1,
        callbacks: {
          label: (ctx) => `${ctx.label}: ${ctx.raw}%`,
        },
      },
    },
  };

  // Doughnut chart configuration for overall score
  const doughnutData = {
    datasets: [
      {
        data: [scoreData.overall_score, 100 - scoreData.overall_score],
        backgroundColor: [getScoreColor(scoreData.overall_score), 'rgba(30, 50, 60, 0.5)'],
        borderWidth: 0,
        cutout: '78%',
      },
    ],
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: { enabled: false },
    },
  };

  return (
    <div className="overview-container">
      <div className="overview-header-row">
        <h2 className="section-title">📊 System Command overview</h2>
        <span className="api-link-status">SYSTEM SECURE_LINK STATUS</span>
      </div>

      <div className="overview-grid">
        {/* Left Column: Security Score Gauge & Quick Widget Modules */}
        <div className="overview-widgets">
          {/* Security Score Widget with Charts */}
          <div className="cyber-widget score-widget">
            <div className="widget-title">
              <span>🛡️ COMPOSITE SECURITY SCORE</span>
              <span className="glow-green">ONLINE</span>
            </div>
            <div className="score-flex">
              {/* Doughnut Score Gauge */}
              <div className="radial-score" style={{ position: 'relative', width: '140px', height: '140px' }}>
                <Doughnut data={doughnutData} options={doughnutOptions} />
                <div style={{
                  position: 'absolute',
                  top: '50%',
                  left: '50%',
                  transform: 'translate(-50%, -50%)',
                  textAlign: 'center',
                }}>
                  <span className="score-num" style={{ color: getScoreColor(scoreData.overall_score), fontSize: '28px' }}>
                    {animatedScore}%
                  </span>
                  <br />
                  <span className="score-label" style={{ fontSize: '10px' }}>RATING</span>
                </div>
              </div>
              <div className="score-breakdown">
                <h4>Metric Weights:</h4>
                <ul>
                  <li>🧱 Firewall Protection: <span className="glow-cyan">{bd.firewall_score || 0}%</span></li>
                  <li>🔒 AES-256 Vault: <span className="glow-cyan">{bd.vault_score || 0}%</span></li>
                  <li>🔎 File Integrity: <span className="glow-cyan">{bd.integrity_score || 0}%</span></li>
                  <li>📡 Network Monitor: <span className="glow-cyan">{bd.network_score || 0}%</span></li>
                  <li>🔑 User Credentials: <span className="glow-cyan">{bd.password_score || 0}%</span></li>
                </ul>
              </div>
            </div>

            {/* Radar Chart */}
            <div style={{ width: '100%', height: '250px', marginTop: '15px' }}>
              <Radar data={radarData} options={radarOptions} />
            </div>
          </div>

          {/* Quick Info Grid */}
          <div className="quick-info-grid">
            <div className={`status-card ${firewallStatus.enabled ? 'active-green' : 'inactive-red'}`}>
              <span className="card-icon">🧱</span>
              <div className="card-details">
                <h3>FIREWALL</h3>
                <span className="card-value">{firewallStatus.enabled ? 'ENABLED' : 'DISABLED'}</span>
              </div>
            </div>

            <div className={`status-card ${vaultStatus.locked ? 'inactive-red' : 'active-green'}`}>
              <span className="card-icon">🔒</span>
              <div className="card-details">
                <h3>VAULT ACCESS</h3>
                <span className="card-value">{vaultStatus.locked ? 'LOCKED' : 'UNLOCKED'}</span>
              </div>
            </div>

            <div className={`status-card ${networkStatus.active ? 'active-green' : 'inactive-red'}`}>
              <span className="card-icon">📡</span>
              <div className="card-details">
                <h3>SURICATA PARSER</h3>
                <span className="card-value">{networkStatus.active ? 'MONITORING' : 'OFFLINE'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Live Monitor & API Gateway Status */}
        <div className="overview-gateway-card">
          <LiveMonitor 
            alerts={recommendations.filter(r => r.status === 'PENDING').map(r => ({
              id: r.id,
              severity: r.action_type === 'FIREWALL_BLOCK' ? 'critical' : 'warning'
            }))}
            status={recommendations.some(r => r.status === 'PENDING') ? 'alert' : 'secure'}
          />

          <div className="cyber-widget gateway-widget" style={{ marginTop: '20px' }}>
            <div className="widget-title">
              <span>🌐 API GATEWAY SHIELD</span>
            </div>
            <div className={`gateway-status-panel ${backendConnected ? 'connected' : 'offline'}`}>
              <div className="status-large">{backendConnected ? 'ESTABLISHED' : 'UNRESPONSIVE'}</div>
              <div className="status-msg">{backendMessage}</div>
            </div>
            <div className="gateway-meta">
              <p>ENDPOINT: <code>http://localhost:8000/</code></p>
              <p>RESPONSE FORMAT: <code>application/json</code></p>
            </div>
          </div>
        </div>
      </div>

      {/* Diagnostics Terminal Log (Full Width) */}
      <div className="terminal-card full-width-terminal">
        <div className="terminal-header">
          <span>💻</span> Cryptographic Core Diagnostics Log
        </div>
        <div className="terminal-logs">
          {logs.map((log, index) => (
            <div key={index} className={log.type}>
              {log.text}
            </div>
          ))}
          <div ref={terminalEndRef} />
        </div>
        
        <div className="terminal-actions">
          <button className="cyber-btn" onClick={pingBackend}>
            ⚡ Handshake Security Gateway
          </button>
          <div className="handshake-count">
            Handshakes attempted: <span className="glow-cyan">{pingCount}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Overview;
