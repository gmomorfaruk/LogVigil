import React, { useState, useEffect, useCallback } from 'react';
import {
  Eye, EyeOff, RefreshCw, Trash2, Monitor, Clock, AppWindow, 
  Search, Filter, Activity, BarChart3, Zap
} from 'lucide-react';

function ActivityMonitor({ addLog }) {
  const [status, setStatus] = useState({ enabled: false, running: false, poll_interval: 5, total_logs: 0 });
  const [logs, setLogs] = useState([]);
  const [totalLogs, setTotalLogs] = useState(0);
  const [summary, setSummary] = useState({ total_events: 0, unique_apps: 0, top_apps: [], events_by_hour: [], monitoring_since: null });
  const [loading, setLoading] = useState(false);
  const [toggling, setToggling] = useState(false);
  const [error, setError] = useState('');

  // Filters
  const [eventFilter, setEventFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  // Clear confirmation
  const [showClearConfirm, setShowClearConfirm] = useState(false);

  const API = 'http://localhost:8000/api/activity';

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API}/status`);
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch (err) {
      // Silent fail for status polling
    }
  }, []);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = new URLSearchParams();
      if (eventFilter) params.append('event_type', eventFilter);
      if (searchQuery) params.append('search', searchQuery);
      if (dateFrom) params.append('date_from', dateFrom);
      if (dateTo) params.append('date_to', dateTo);
      params.append('limit', '200');

      const res = await fetch(`${API}/logs?${params}`);
      if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
      const data = await res.json();
      setLogs(data.logs);
      setTotalLogs(data.total);
    } catch (err) {
      setError(`Failed to fetch activity logs: ${err.message}`);
      addLog(`Activity log fetch error: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [eventFilter, searchQuery, dateFrom, dateTo, addLog]);

  const fetchSummary = useCallback(async () => {
    try {
      const res = await fetch(`${API}/logs/summary`);
      if (res.ok) {
        const data = await res.json();
        setSummary(data);
      }
    } catch (err) {
      // Silent fail
    }
  }, []);

  const handleToggle = async () => {
    setToggling(true);
    try {
      const res = await fetch(`${API}/toggle`, { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
      const data = await res.json();
      setStatus(prev => ({ ...prev, enabled: data.enabled, running: data.running }));
      addLog(data.message, 'success');
    } catch (err) {
      addLog(`Failed to toggle monitor: ${err.message}`, 'error');
    } finally {
      setToggling(false);
    }
  };

  const handleClearLogs = async () => {
    try {
      const res = await fetch(`${API}/logs`, { method: 'DELETE' });
      if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
      const data = await res.json();
      setShowClearConfirm(false);
      addLog(data.message, 'success');
      fetchLogs();
      fetchSummary();
      fetchStatus();
    } catch (err) {
      addLog(`Failed to clear logs: ${err.message}`, 'error');
    }
  };

  const refreshAll = () => {
    fetchStatus();
    fetchLogs();
    fetchSummary();
  };

  useEffect(() => {
    refreshAll();
  }, []);

  useEffect(() => {
    fetchLogs();
  }, [eventFilter, searchQuery, dateFrom, dateTo, fetchLogs]);

  // Auto-refresh every 10 seconds if monitor is running
  useEffect(() => {
    if (!status.running) return;
    const interval = setInterval(refreshAll, 10000);
    return () => clearInterval(interval);
  }, [status.running]);

  const [expandedIds, setExpandedIds] = useState(new Set());
  const [copiedId, setCopiedId] = useState(null);

  const toggleExpand = (id) => {
    setExpandedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const handleCopyCmd = (id, text, e) => {
    e.stopPropagation();
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getAppIcon = (name) => {
    const n = (name || '').toLowerCase();
    if (n.includes('firefox')) return '🦊';
    if (n.includes('chrome') || n.includes('chromium') || n.includes('brave') || n.includes('edge')) return '🌐';
    if (n.includes('code') || n.includes('vim') || n.includes('nano') || n.includes('sublime') || n.includes('gedit') || n.includes('editor')) return '📝';
    if (n.includes('nautilus') || n.includes('thunar') || n.includes('dolphin') || n.includes('nemo') || n.includes('files') || n.includes('file manager')) return '📁';
    if (n.includes('terminal') || n.includes('bash') || n.includes('zsh') || n.includes('konsole') || n.includes('gnome-terminal') || n.includes('xterm') || n.includes('shell')) return '💻';
    if (n.includes('pdf') || n.includes('evince') || n.includes('okular') || n.includes('document')) return '📄';
    if (n.includes('image') || n.includes('gimp') || n.includes('eog') || n.includes('shotwell') || n.includes('photo')) return '🖼️';
    if (n.includes('video') || n.includes('vlc') || n.includes('mpv') || n.includes('totem') || n.includes('media player')) return '🎬';
    if (n.includes('music') || n.includes('spotify') || n.includes('rhythmbox') || n.includes('audac')) return '🎵';
    if (n.includes('telegram') || n.includes('discord') || n.includes('slack') || n.includes('signal')) return '💬';
    if (n.includes('steam') || n.includes('game')) return '🎮';
    if (n.includes('settings') || n.includes('control') || n.includes('config')) return '⚙️';
    if (n.includes('update') || n.includes('apt') || n.includes('snap') || n.includes('flatpak') || n.includes('pip')) return '📦';
    return '🔹';
  };

  const formatTimestamp = (ts) => {
    try {
      return new Date(ts).toLocaleString();
    } catch {
      return ts;
    }
  };

  const formatRelativeTime = (ts) => {
    if (!ts) return 'N/A';
    try {
      const diff = Date.now() - new Date(ts).getTime();
      const mins = Math.floor(diff / 60000);
      const hours = Math.floor(mins / 60);
      const days = Math.floor(hours / 24);
      if (days > 0) return `${days}d ${hours % 24}h ago`;
      if (hours > 0) return `${hours}h ${mins % 60}m ago`;
      if (mins > 0) return `${mins}m ago`;
      return 'Just now';
    } catch {
      return ts;
    }
  };

  const getCleanCommandLine = (details) => {
    if (!details) return '';
    const cmdIndex = details.indexOf('CMD:');
    if (cmdIndex !== -1) {
      return details.substring(cmdIndex + 4).trim();
    }
    return details;
  };

  return (
    <div className="activity-container">
      {/* Header */}
      <div className="overview-header-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 className="section-title">🕵️ Local Activity Monitor</h2>
          <p className="section-description">
            Track application launches and closures on your machine. Detect unauthorized access and monitor all active processes in real time.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="cyber-btn" onClick={refreshAll} disabled={loading} style={{ height: 'fit-content' }}>
            <RefreshCw size={14} style={{ marginRight: '6px' }} />
            {loading ? 'SYNCING...' : 'REFRESH'}
          </button>
        </div>
      </div>

      {error && <div className="auth-alert" style={{ marginBottom: '15px' }}>{error}</div>}

      {/* Status Bar */}
      <div className="cyber-widget activity-status-bar" style={{ padding: '16px 20px', marginBottom: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className={`activity-status-dot ${status.running ? 'active' : 'inactive'}`}></span>
            <span style={{ fontFamily: 'var(--font-cyber)', fontSize: '0.95rem', fontWeight: '600', color: status.running ? '#00ff88' : '#94a3b8' }}>
              {status.running ? 'MONITORING ACTIVE' : 'MONITORING OFFLINE'}
            </span>
          </div>
          <span style={{ color: 'rgba(255,255,255,0.3)' }}>|</span>
          <span style={{ fontSize: '0.9rem', color: '#cbd5e1' }}>
            <Clock size={14} style={{ marginRight: '4px', verticalAlign: 'middle', color: '#38bdf8' }} />
            Poll Interval: <strong style={{ color: '#fff' }}>{status.poll_interval}s</strong>
          </span>
          <span style={{ color: 'rgba(255,255,255,0.3)' }}>|</span>
          <span style={{ fontSize: '0.9rem', color: '#cbd5e1' }}>
            <Activity size={14} style={{ marginRight: '4px', verticalAlign: 'middle', color: '#00ff88' }} />
            Logged Events: <strong style={{ color: '#fff' }}>{status.total_logs}</strong>
          </span>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            className={`cyber-btn ${status.enabled ? 'cyber-btn-danger' : 'cyber-btn-success'}`}
            onClick={handleToggle}
            disabled={toggling}
            style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              background: status.enabled
                ? 'linear-gradient(135deg, rgba(255,50,50,0.2), rgba(255,50,50,0.1))'
                : 'linear-gradient(135deg, rgba(0,255,136,0.2), rgba(0,255,136,0.1))',
              borderColor: status.enabled ? 'rgba(255,50,50,0.5)' : 'rgba(0,255,136,0.5)',
              color: status.enabled ? '#ff5555' : '#00ff88',
            }}
          >
            {status.enabled ? <EyeOff size={14} /> : <Eye size={14} />}
            {toggling ? 'PROCESSING...' : status.enabled ? 'DISABLE MONITOR' : 'ENABLE MONITOR'}
          </button>
          {totalLogs > 0 && (
            <button
              className="cyber-btn"
              onClick={() => setShowClearConfirm(true)}
              style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                background: 'linear-gradient(135deg, rgba(255,150,50,0.15), rgba(255,100,50,0.1))',
                borderColor: 'rgba(255,150,50,0.4)',
                color: '#ff9944',
              }}
            >
              <Trash2 size={14} /> CLEAR LOGS
            </button>
          )}
        </div>
      </div>

      {/* Summary Cards */}
      <div className="activity-summary-row" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px', marginBottom: '20px' }}>
        <div className="cyber-widget activity-stat-card" style={{ padding: '18px', textAlign: 'center' }}>
          <div style={{ fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px', fontWeight: '600' }}>
            Total Events
          </div>
          <div className="glow-cyan" style={{ fontSize: '2.2rem', fontWeight: '700', fontFamily: 'var(--font-cyber)' }}>
            {summary.total_events}
          </div>
        </div>

        <div className="cyber-widget activity-stat-card" style={{ padding: '18px', textAlign: 'center' }}>
          <div style={{ fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px', fontWeight: '600' }}>
            Unique Apps
          </div>
          <div className="glow-green" style={{ fontSize: '2.2rem', fontWeight: '700', fontFamily: 'var(--font-cyber)' }}>
            {summary.unique_apps}
          </div>
        </div>

        <div className="cyber-widget activity-stat-card" style={{ padding: '18px', textAlign: 'center' }}>
          <div style={{ fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px', fontWeight: '600' }}>
            Most Active App
          </div>
          <div style={{ fontSize: '1.15rem', fontWeight: '600', color: '#f8fafc', fontFamily: 'var(--font-cyber)' }}>
            {summary.top_apps.length > 0 ? (
              <span>
                {getAppIcon(summary.top_apps[0].name)} {summary.top_apps[0].name}
                <span style={{ color: '#38bdf8', fontSize: '0.85rem', marginLeft: '6px' }}>
                  ({summary.top_apps[0].open_count}x)
                </span>
              </span>
            ) : (
              <span style={{ color: '#64748b' }}>—</span>
            )}
          </div>
        </div>

        <div className="cyber-widget activity-stat-card" style={{ padding: '18px', textAlign: 'center' }}>
          <div style={{ fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px', fontWeight: '600' }}>
            Monitoring Since
          </div>
          <div style={{ fontSize: '1rem', fontWeight: '600', color: '#f8fafc', fontFamily: 'var(--font-cyber)' }}>
            {summary.monitoring_since ? formatRelativeTime(summary.monitoring_since) : <span style={{ color: '#64748b' }}>—</span>}
          </div>
        </div>
      </div>

      {/* Top Apps Bar (if data exists) */}
      {summary.top_apps.length > 0 && (
        <div className="cyber-widget" style={{ padding: '18px', marginBottom: '20px' }}>
          <div className="widget-title" style={{ marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <BarChart3 size={16} color="#00f0ff" />
            <span>TOP APPLICATIONS FREQUENCY</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {summary.top_apps.slice(0, 6).map((app, idx) => {
              const maxCount = summary.top_apps[0].open_count || 1;
              const pct = Math.round((app.open_count / maxCount) * 100);
              return (
                <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span style={{ width: '28px', fontSize: '1.2rem', textAlign: 'center' }}>{getAppIcon(app.name)}</span>
                  <span style={{ width: '160px', fontSize: '0.9rem', color: '#f8fafc', fontWeight: '500', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {app.name}
                  </span>
                  <div style={{ flex: 1, height: '8px', backgroundColor: 'rgba(0,240,255,0.1)', borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{
                      width: `${pct}%`,
                      height: '100%',
                      background: 'linear-gradient(90deg, #00f0ff, #00ff88)',
                      borderRadius: '4px',
                      transition: 'width 0.6s ease',
                      boxShadow: '0 0 8px rgba(0,240,255,0.3)',
                    }} />
                  </div>
                  <span style={{ width: '45px', textAlign: 'right', fontSize: '0.85rem', color: '#38bdf8', fontFamily: 'monospace', fontWeight: 'bold' }}>
                    {app.open_count}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <div className="cyber-widget activity-filter-bar" style={{ padding: '14px 18px', marginBottom: '20px', display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Filter size={15} color="#38bdf8" />
          <span style={{ fontSize: '0.85rem', color: '#cbd5e1', textTransform: 'uppercase', letterSpacing: '1px', fontWeight: '600' }}>Filters</span>
        </div>

        <select
          value={eventFilter}
          onChange={(e) => setEventFilter(e.target.value)}
          className="cyber-select"
          style={{
            background: 'rgba(0,15,30,0.9)',
            border: '1px solid rgba(0,240,255,0.3)',
            color: '#f8fafc',
            padding: '7px 14px',
            borderRadius: '4px',
            fontFamily: 'var(--font-cyber)',
            fontSize: '0.85rem',
            cursor: 'pointer',
          }}
        >
          <option value="">All Events (Opened & Closed)</option>
          <option value="APP_OPENED">▲ App Opened Only</option>
          <option value="APP_CLOSED">▼ App Closed Only</option>
        </select>

        <div style={{ position: 'relative', flex: '1', minWidth: '180px', maxWidth: '320px' }}>
          <Search size={15} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: '#38bdf8' }} />
          <input
            type="text"
            placeholder="Search app name (e.g. Firefox, Chrome)..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              background: 'rgba(0,15,30,0.9)',
              border: '1px solid rgba(0,240,255,0.3)',
              color: '#f8fafc',
              padding: '7px 12px 7px 34px',
              borderRadius: '4px',
              fontFamily: 'var(--font-cyber)',
              fontSize: '0.85rem',
              outline: 'none',
            }}
          />
        </div>

        <input
          type="date"
          value={dateFrom}
          onChange={(e) => setDateFrom(e.target.value)}
          title="From date"
          style={{
            background: 'rgba(0,15,30,0.9)',
            border: '1px solid rgba(0,240,255,0.3)',
            color: '#f8fafc',
            padding: '7px 10px',
            borderRadius: '4px',
            fontFamily: 'var(--font-cyber)',
            fontSize: '0.85rem',
          }}
        />
        <span style={{ color: 'rgba(255,255,255,0.4)' }}>→</span>
        <input
          type="date"
          value={dateTo}
          onChange={(e) => setDateTo(e.target.value)}
          title="To date"
          style={{
            background: 'rgba(0,15,30,0.9)',
            border: '1px solid rgba(0,240,255,0.3)',
            color: '#f8fafc',
            padding: '7px 10px',
            borderRadius: '4px',
            fontFamily: 'var(--font-cyber)',
            fontSize: '0.85rem',
          }}
        />
      </div>

      {/* Activity Log List */}
      <div className="cyber-widget" style={{ padding: '20px' }}>
        <div className="widget-title" style={{ marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Monitor size={16} color="#00f0ff" />
            APPLICATION ACTIVITY & EVENT TRAIL
          </span>
          <span className="glow-cyan" style={{ fontSize: '0.9rem', fontWeight: 'bold' }}>{totalLogs} EVENTS</span>
        </div>

        {logs.length === 0 ? (
          <div className="recs-empty-placeholder" style={{ padding: '50px', textAlign: 'center' }}>
            <Eye size={44} style={{ color: 'rgba(0,240,255,0.4)', marginBottom: '16px' }} />
            <p style={{ color: '#f8fafc', fontSize: '1rem', fontWeight: '600', marginBottom: '8px' }}>
              No activity events recorded.
            </p>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
              {status.enabled
                ? 'Monitor is active. Events will appear as applications are opened or closed.'
                : 'Enable the Activity Monitor above to start tracking applications.'}
            </p>
          </div>
        ) : (
          <div className="activity-log-list" style={{ display: 'flex', flexDirection: 'column', gap: '12px', maxHeight: '650px', overflowY: 'auto', paddingRight: '6px' }}>
            {logs.map((entry) => {
              const isExpanded = expandedIds.has(entry.id);
              const cmdLine = getCleanCommandLine(entry.details);
              const isOpened = entry.event_type === 'APP_OPENED';

              return (
                <div
                  key={entry.id}
                  onClick={() => toggleExpand(entry.id)}
                  className={`activity-event-item ${isOpened ? 'activity-event-opened' : 'activity-event-closed'}`}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    padding: '14px 18px',
                    backgroundColor: isExpanded ? 'rgba(15, 35, 70, 0.6)' : 'rgba(10, 25, 50, 0.45)',
                    border: isExpanded ? '1px solid rgba(0, 240, 255, 0.35)' : '1px solid rgba(0, 240, 255, 0.15)',
                    borderLeft: `4px solid ${isOpened ? '#00ff88' : '#ff5555'}`,
                    borderRadius: '8px',
                    cursor: 'pointer',
                    transition: 'all 0.2s ease',
                    boxShadow: isExpanded ? '0 0 20px rgba(0, 240, 255, 0.1)' : 'none',
                  }}
                >
                  {/* Top Row / Main Summary */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                    {/* App Icon */}
                    <span style={{ fontSize: '1.6rem', flexShrink: 0, lineHeight: 1 }}>
                      {getAppIcon(entry.target)}
                    </span>

                    {/* Target & Event Badge */}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <span style={{ fontWeight: '700', fontSize: '1rem', color: '#f8fafc', letterSpacing: '0.3px' }}>
                            {entry.target}
                          </span>
                          <span
                            style={{
                              fontSize: '0.75rem',
                              fontWeight: 'bold',
                              padding: '3px 9px',
                              borderRadius: '4px',
                              backgroundColor: isOpened ? 'rgba(0,255,136,0.18)' : 'rgba(255,85,85,0.18)',
                              color: isOpened ? '#00ff88' : '#ff5555',
                              border: `1px solid ${isOpened ? 'rgba(0,255,136,0.4)' : 'rgba(255,85,85,0.4)'}`,
                              letterSpacing: '0.5px',
                            }}
                          >
                            {isOpened ? '▲ LAUNCHED' : '▼ TERMINATED'}
                          </span>
                        </div>

                        {/* Timestamp & Expand indicator */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: '500' }}>
                            {formatTimestamp(entry.timestamp)}
                          </span>
                          <span style={{
                            fontSize: '0.75rem',
                            color: '#38bdf8',
                            backgroundColor: 'rgba(0, 240, 255, 0.1)',
                            padding: '2px 8px',
                            borderRadius: '4px',
                            border: '1px solid rgba(0, 240, 255, 0.2)',
                          }}>
                            {isExpanded ? '▲ Hide Details' : '▼ Details'}
                          </span>
                        </div>
                      </div>

                      {/* Human-Readable Event Summary Sentence */}
                      <div style={{ marginTop: '4px', fontSize: '0.85rem', color: '#cbd5e1', fontWeight: '400' }}>
                        {isOpened ? (
                          <span>Application <strong>{entry.target}</strong> was opened by user <code style={{ color: '#38bdf8', background: 'rgba(0,240,255,0.1)', padding: '1px 5px', borderRadius: '3px' }}>{entry.username || 'unknown'}</code> (PID: <strong style={{ color: '#fff' }}>{entry.pid || 'N/A'}</strong>)</span>
                        ) : (
                          <span>Application <strong>{entry.target}</strong> was closed or terminated (PID: <strong style={{ color: '#fff' }}>{entry.pid || 'N/A'}</strong>)</span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Expanded Detailed View */}
                  {isExpanded && (
                    <div
                      style={{
                        marginTop: '14px',
                        paddingTop: '14px',
                        borderTop: '1px solid rgba(0, 240, 255, 0.15)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '10px',
                      }}
                      onClick={(e) => e.stopPropagation()}
                    >
                      {/* Metadata Badges */}
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', fontSize: '0.85rem' }}>
                        <div style={{ background: 'rgba(0,0,0,0.3)', padding: '6px 12px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.1)' }}>
                          <span style={{ color: '#94a3b8' }}>Process ID: </span>
                          <strong style={{ color: '#00f0ff', fontFamily: 'monospace' }}>{entry.pid || 'N/A'}</strong>
                        </div>
                        <div style={{ background: 'rgba(0,0,0,0.3)', padding: '6px 12px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.1)' }}>
                          <span style={{ color: '#94a3b8' }}>System User: </span>
                          <strong style={{ color: '#00ff88', fontFamily: 'monospace' }}>{entry.username || 'unknown'}</strong>
                        </div>
                        <div style={{ background: 'rgba(0,0,0,0.3)', padding: '6px 12px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.1)' }}>
                          <span style={{ color: '#94a3b8' }}>Event Type: </span>
                          <strong style={{ color: isOpened ? '#00ff88' : '#ff5555' }}>{entry.event_type}</strong>
                        </div>
                        <div style={{ background: 'rgba(0,0,0,0.3)', padding: '6px 12px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.1)' }}>
                          <span style={{ color: '#94a3b8' }}>Logged At: </span>
                          <strong style={{ color: '#e2e8f0' }}>{formatTimestamp(entry.timestamp)}</strong>
                        </div>
                      </div>

                      {/* Full Command Line Box with Copy Button */}
                      {cmdLine && (
                        <div style={{ marginTop: '6px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                            <span style={{ fontSize: '0.8rem', fontWeight: 'bold', color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                              Execution Command Line
                            </span>
                            <button
                              className="cyber-btn"
                              onClick={(e) => handleCopyCmd(entry.id, cmdLine, e)}
                              style={{ fontSize: '0.75rem', padding: '3px 10px', height: 'auto', minWidth: 'auto' }}
                            >
                              {copiedId === entry.id ? '✓ COPIED' : '📋 COPY CMD'}
                            </button>
                          </div>
                          <pre
                            style={{
                              margin: 0,
                              padding: '10px 14px',
                              backgroundColor: 'rgba(0, 10, 25, 0.8)',
                              border: '1px solid rgba(0, 240, 255, 0.2)',
                              borderRadius: '4px',
                              color: '#cbd5e1',
                              fontFamily: 'monospace',
                              fontSize: '0.82rem',
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-all',
                              maxHeight: '180px',
                              overflowY: 'auto',
                            }}
                          >
                            {cmdLine}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Clear Confirmation Modal */}
      {showClearConfirm && (
        <div className="activity-clear-modal" style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.75)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          backdropFilter: 'blur(4px)',
        }}>
          <div className="cyber-widget" style={{
            padding: '30px',
            maxWidth: '420px',
            width: '90%',
            textAlign: 'center',
            border: '1px solid rgba(255,150,50,0.4)',
            boxShadow: '0 0 40px rgba(255,100,50,0.15)',
          }}>
            <Trash2 size={36} style={{ color: '#ff9944', marginBottom: '16px' }} />
            <h3 style={{ color: '#e2e8f0', marginBottom: '10px', fontFamily: 'var(--font-cyber)' }}>
              CONFIRM LOG PURGE
            </h3>
            <p style={{ color: 'rgba(255,255,255,0.6)', fontSize: '0.9rem', marginBottom: '24px' }}>
              This will permanently delete <strong style={{ color: '#ff9944' }}>{totalLogs}</strong> activity log entries. This action cannot be undone.
            </p>
            <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
              <button
                className="cyber-btn"
                onClick={() => setShowClearConfirm(false)}
                style={{ padding: '8px 20px' }}
              >
                CANCEL
              </button>
              <button
                className="cyber-btn"
                onClick={handleClearLogs}
                style={{
                  padding: '8px 20px',
                  background: 'linear-gradient(135deg, rgba(255,50,50,0.25), rgba(255,50,50,0.1))',
                  borderColor: 'rgba(255,50,50,0.5)',
                  color: '#ff5555',
                }}
              >
                <Trash2 size={14} style={{ marginRight: '6px' }} /> PURGE ALL LOGS
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ActivityMonitor;
