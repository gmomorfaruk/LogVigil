import React from 'react';
import logoImg from '../assets/logvigil_logo.png';
import {
  LayoutDashboard,
  Shield,
  Flame,
  FileSearch,
  Activity,
  AlertTriangle,
  Clock,
  Fish,
  FileText,
  Settings,
  User,
  LogOut,
  Eye
} from 'lucide-react';

function Sidebar({ activeTab, setActiveTab, user, onLogout }) {
  const menuItems = [
    { id: 'overview', label: 'System Overview', icon: LayoutDashboard },
    { id: 'vault', label: 'Encrypted Vault', icon: Shield },
    { id: 'firewall', label: 'Firewall Rules', icon: Flame },
    { id: 'integrity', label: 'File Integrity', icon: FileSearch },
    { id: 'network', label: 'Network Monitor', icon: Activity },
    { id: 'threats', label: 'Threat Engine', icon: AlertTriangle },
    { id: 'timeline', label: 'System Timeline', icon: Clock },
    { id: 'activity', label: 'Activity Monitor', icon: Eye },
    { id: 'phishing', label: 'Phishing Check', icon: Fish },
    { id: 'reports', label: 'PDF Reports', icon: FileText },
    { id: 'settings', label: 'Preferences', icon: Settings },
  ];

  return (
    <div className="cyber-sidebar">
      <div className="sidebar-brand">
        <span className="brand-logo">
          <img src={logoImg} alt="LogVigil" className="brand-logo-img" />
        </span>
        <div className="brand-title">
          <h3>LogVigil</h3>
          <span>Security Monitor</span>
        </div>
      </div>

      <nav className="sidebar-menu">
        {menuItems.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              className={`menu-item ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
            >
              <Icon size={18} style={{ color: activeTab === item.id ? '#00f0ff' : '#6b8a8a' }} />
              <span className="menu-label">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {user && (
        <div className="sidebar-footer">
          <div className="operator-profile">
            <span className="operator-avatar" style={{ display: 'flex', alignItems: 'center' }}>
              <User size={20} color="#00f0ff" />
            </span>
            <div className="operator-info">
              <span className="operator-label">OPERATOR</span>
              <span className="operator-name glow-green">{user.toUpperCase()}</span>
            </div>
          </div>
          <button className="sidebar-logout-btn" onClick={onLogout} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
            <LogOut size={14} /> TERMINATE SESSION
          </button>
        </div>
      )}
    </div>
  );
}

export default Sidebar;
