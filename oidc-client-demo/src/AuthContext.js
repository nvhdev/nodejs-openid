import React, { createContext, useContext, useState, useEffect } from "react";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [auth, setAuth] = useState(() => {
    const stored = sessionStorage.getItem("auth");
    return stored ? JSON.parse(stored) : null;
  });

  useEffect(() => {
    if (auth) {
      sessionStorage.setItem("auth", JSON.stringify(auth));
      
      // Set up automatic token refresh
      const expiresAt = auth.loginTime + (auth.expiresIn * 1000);
      const timeUntilExpiry = expiresAt - Date.now();
      
      // Refresh 5 minutes before expiration
      const refreshTime = timeUntilExpiry - (5 * 60 * 1000);
      
      if (refreshTime > 0 && auth.refreshToken) {
        const timer = setTimeout(() => {
          refreshAccessToken(auth.refreshToken);
        }, refreshTime);
        
        return () => clearTimeout(timer);
      }
    } else {
      sessionStorage.removeItem("auth");
    }
  }, [auth]);

  const refreshAccessToken = async (refreshToken) => {
    try {
      const response = await fetch("http://localhost:4000/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: "demo-client",
          client_secret: "supersecret"
        })
      });

      if (response.ok) {
        const tokens = await response.json();
        
        setAuth(prev => ({
          ...prev,
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token,
          expiresIn: tokens.expires_in,
          loginTime: Date.now()
        }));
        
        console.log("Token refreshed successfully");
      } else {
        console.error("Token refresh failed, logging out");
        logout();
      }
    } catch (error) {
      console.error("Token refresh error:", error);
      logout();
    }
  };

  const login = (tokens) => setAuth(tokens);
  const logout = () => setAuth(null);

  return (
    <AuthContext.Provider value={{ auth, login, logout, refreshAccessToken }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
