import React from "react";

export default function LoginPage() {
  const handleLogin = () => {
    const clientId = "demo-client";
const redirectUri = encodeURIComponent("http://localhost:3000/callback");

// Generate a random state 
const state = crypto.randomUUID(); 
sessionStorage.setItem("oauth_state", state);

const authUrl =
  `http://localhost:4000/authorize?` +
  `response_type=code&client_id=${clientId}` +
  `&redirect_uri=${redirectUri}&scope=openid profile` +
  `&state=${state}`;

window.location.href = authUrl;

  };

  return (
    <div>
      <h1>Login</h1>
      <button onClick={handleLogin}>Login with OIDC Provider</button>
    </div>
  );
}
