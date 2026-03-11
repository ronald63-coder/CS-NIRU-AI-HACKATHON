// src/App.jsx
import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import FileAnalysis from './pages/FileAnalysis';
import UserMonitoring from './pages/UserMonitoring';
import ThreatHistory from './pages/ThreatHistory';
import SystemHealth from './pages/SystemHealth';
import AgentControl from './pages/AgentControl';
import './App.css';

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <Router>
      <div className="app-container">
        <Sidebar isOpen={sidebarOpen} />
        <div className="main-content">
          <Header onMenuClick={() => setSidebarOpen(!sidebarOpen)} />
          <div className="page-content">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/file-analysis" element={<FileAnalysis />} />
              <Route path="/user-monitoring" element={<UserMonitoring />} />
              <Route path="/threat-history" element={<ThreatHistory />} />
              <Route path="/system-health" element={<SystemHealth />} />
              <Route path="/agent-control" element={<AgentControl />} />
            </Routes>
          </div>
        </div>
      </div>
    </Router>
  );
}

export default App;