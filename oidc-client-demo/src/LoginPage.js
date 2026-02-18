import React from "react";

// PKCE helper functions
function generateRandomString(length) {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let result = '';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < length; i++) {
    result += charset[randomValues[i] % charset.length];
  }
  return result;
}

async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

export default function LoginPage() {
  const handleLogin = async () => {
    const clientId = "demo-client";
    const redirectUri = encodeURIComponent("http://localhost:3000/callback");

    // Generate PKCE parameters
    const codeVerifier = generateRandomString(128);
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    
    // Generate random state and nonce
    const state = crypto.randomUUID(); 
    const nonce = crypto.randomUUID();
    
    // Store in session for callback
    sessionStorage.setItem("oauth_state", state);
    sessionStorage.setItem("oauth_code_verifier", codeVerifier);
    sessionStorage.setItem("oauth_nonce", nonce);

    const authUrl =
      `http://localhost:4000/authorize?` +
      `response_type=code&client_id=${clientId}` +
      `&redirect_uri=${redirectUri}` +
      `&scope=openid%20profile%20offline_access` + // Added offline_access for refresh token
      `&state=${state}` +
      `&nonce=${nonce}` +
      `&code_challenge=${codeChallenge}` +
      `&code_challenge_method=S256`;

    window.location.href = authUrl;
  };

  return (
    <div style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      minHeight: '60vh'
    }}>
      <div style={{
        background: 'white',
        padding: '60px 80px',
        borderRadius: '16px',
        boxShadow: '0 10px 40px rgba(0,0,0,0.15)',
        textAlign: 'center',
        maxWidth: '500px'
      }}>
        <div style={{ fontSize: '64px', marginBottom: '20px' }}>🔐</div>
        <h1 style={{ color: '#333', marginBottom: '10px' }}>Welcome Back</h1>
        <p style={{ color: '#666', marginBottom: '40px' }}>Sign in with your OpenID Connect provider</p>
        <button onClick={handleLogin} style={{
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          color: 'white',
          border: 'none',
          padding: '16px 40px',
          borderRadius: '30px',
          cursor: 'pointer',
          fontWeight: 'bold',
          fontSize: '16px',
          boxShadow: '0 4px 15px rgba(102, 126, 234, 0.4)',
          transition: 'transform 0.2s',
          width: '100%'
        }}
        onMouseOver={(e) => e.target.style.transform = 'scale(1.05)'}
        onMouseOut={(e) => e.target.style.transform = 'scale(1)'}
        >
          🚀 Login with OIDC
        </button>
        <p style={{ marginTop: '30px', fontSize: '12px', color: '#999' }}>
          Secured with PKCE • State validation • RS256 signing
        </p>
      </div>
    </div>
  );
}
