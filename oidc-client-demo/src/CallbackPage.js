import React, { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "./AuthContext";
import { decodeJwt } from "./utils/jwt";

export default function CallbackPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const hasRun = useRef(false); // Prevent double execution in React StrictMode

  useEffect(() => {
    // Prevent double execution in development
    if (hasRun.current) return;
    hasRun.current = true;
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const returnedState = params.get("state");
    const storedState = sessionStorage.getItem("oauth_state");
    const codeVerifier = sessionStorage.getItem("oauth_code_verifier");
    const nonce = sessionStorage.getItem("oauth_nonce");

    // Validate state
    if (returnedState !== storedState) {
      console.error("Invalid state - possible CSRF attack");
      navigate("/login");
      return;
    }

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: "http://localhost:3000/callback",
      client_id: "demo-client",
      client_secret: "supersecret", // Note: In production, use backend proxy
      code_verifier: codeVerifier
    });

    fetch("http://localhost:4000/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    })
      .then(res => {
        if (!res.ok) {
          throw new Error(`Token request failed: ${res.status}`);
        }
        return res.json();
      })
      .then(tokens => {
        console.log("Received tokens:", tokens);
        const claims = decodeJwt(tokens.id_token);
        console.log("Decoded claims:", claims);

        // Validate nonce
        if (claims.nonce !== nonce) {
          console.error("Invalid nonce - possible token replay attack");
          navigate("/login");
          return;
        }

        // Clear session storage
        sessionStorage.removeItem("oauth_state");
        sessionStorage.removeItem("oauth_code_verifier");
        sessionStorage.removeItem("oauth_nonce");

        const authData = {
          idToken: tokens.id_token,
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token, // Store refresh token
          tokenType: tokens.token_type,
          expiresIn: tokens.expires_in,
          claims,
          loginTime: Date.now()
        };
        
        console.log("Storing auth data:", authData);
        login(authData);

        navigate("/");
      })
      .catch(error => {
        console.error("Token exchange failed:", error);
        navigate("/login");
      });
  }, [login, navigate]);

  return (
    <div style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      minHeight: '60vh',
      textAlign: 'center'
    }}>
      <div style={{
        background: 'white',
        padding: '40px 60px',
        borderRadius: '16px',
        boxShadow: '0 10px 40px rgba(0,0,0,0.15)'
      }}>
        <div style={{ 
          fontSize: '48px', 
          animation: 'spin 1s linear infinite',
          display: 'inline-block',
          marginBottom: '20px'
        }}>⚙️</div>
        <h2 style={{ color: '#667eea', marginBottom: '10px' }}>Processing Login</h2>
        <p style={{ color: '#666' }}>Exchanging authorization code for tokens...</p>
        <style>{`
          @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }
        `}</style>
      </div>
    </div>
  );
}
