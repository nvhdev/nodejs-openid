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
    <div style={{ padding: 20 }}>
      <nav style={{ marginBottom: 20 }}>
        <Link to="/">Home</Link>{" | "}
        <Link to="/login">Login</Link>{" | "}
        {auth && <button onClick={handleLogout}>Logout</button>}
      </nav>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/callback" element={<CallbackPage />} />
      </Routes>
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
