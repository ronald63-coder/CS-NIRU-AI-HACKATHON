// src/components/Header.jsx
import React from 'react';
import { Menu } from 'lucide-react';

function Header({ onMenuClick }) {
  return (
    <header className="header">
      <div className="header-content">
        <button className="menu-btn" onClick={onMenuClick}>
          <Menu size={24} />
        </button>
        <div className="header-title">
          <h2>CyberSentry Dashboard</h2>
          <p>Real-time Threat Detection & Response</p>
        </div>
        <div className="header-user">
          <div className="user-info">
            <div className="user-name">Admin</div>
            <div className="user-email">admin@cybersentry.local</div>
          </div>
          <button className="logout-btn">🚪 Logout</button>
        </div>
      </div>
    </header>
  );
}

export default Header;