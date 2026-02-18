import React from "react";
import { BrowserRouter, Routes, Route, Link } from "react-router-dom";
import { AuthProvider, useAuth } from "./AuthContext";
import LoginPage from "./LoginPage";
import CallbackPage from "./CallbackPage";
import HomePage from "./HomePage";

function AppShell() {
  const { auth, logout } = useAuth();

  const handleLogout = () => {
    // 1. Clear React session
    logout();

    // 2. Redirect to server logout (RP-Initiated Logout)
    const idTokenHint = auth?.idToken;
    const clientId = "demo-client";
    const postLogoutRedirect = encodeURIComponent("http://localhost:3000");

  // Redirect to server logout with id_token_hint
  window.location.href =
    `http://localhost:4000/logout?` +
    `client_id=${clientId}` +
    `&post_logout_redirect_uri=${postLogoutRedirect}` +
    (idTokenHint ? `&id_token_hint=${encodeURIComponent(idTokenHint)}` : "");

  };

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
      <nav style={{ 
        background: 'rgba(255,255,255,0.95)', 
        padding: '15px 30px', 
        boxShadow: '0 2px 10px rgba(0,0,0,0.1)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
          <h2 style={{ margin: 0, color: '#667eea' }}>🔐 OIDC Demo</h2>
          <Link to="/" style={{ textDecoration: 'none', color: '#555', fontWeight: 500 }}>Home</Link>
          {!auth && <Link to="/login" style={{ textDecoration: 'none', color: '#555', fontWeight: 500 }}>Login</Link>}
        </div>
        {auth && (
          <button onClick={handleLogout} style={{
            background: '#dc3545',
            color: 'white',
            border: 'none',
            padding: '8px 20px',
            borderRadius: '20px',
            cursor: 'pointer',
            fontWeight: 'bold',
            fontSize: '14px'
          }}>Logout</button>
        )}
      </nav>
      <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '40px 20px' }}>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/callback" element={<CallbackPage />} />
        </Routes>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <AppShell />
      </BrowserRouter>
    </AuthProvider>
  );
}
