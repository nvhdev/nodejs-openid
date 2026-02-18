import React, { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "./AuthContext";
import { decodeJwt } from "./utils/jwt";

export default function CallbackPage() {
  const { login } = useAuth();
  const navigate = useNavigate();


useEffect(() => {
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  const returnedState = params.get("state");
    const storedState = sessionStorage.getItem("oauth_state");

    if (returnedState !== storedState) {
    console.error("Invalid state");
    return;
    }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: "http://localhost:3000/callback",
    client_id: "demo-client"
  });

  fetch("http://localhost:4000/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  })
    .then(res => res.json())
    .then(tokens => {
      const claims = decodeJwt(tokens.id_token);

      login({
        idToken: tokens.id_token,
        accessToken: tokens.access_token,
        tokenType: tokens.token_type,
        expiresIn: tokens.expires_in,
        claims,
        loginTime: Date.now()
      });

      navigate("/");
    });
}, []);


  return <div>Processing login…</div>;
}
