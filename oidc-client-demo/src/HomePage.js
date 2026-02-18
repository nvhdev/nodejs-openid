import React, { useState, useEffect } from "react";
import { useAuth } from "./AuthContext";
import { Link } from "react-router-dom";

export default function HomePage() {
  const { auth, refreshAccessToken } = useAuth();
  const [userInfo, setUserInfo] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchUserInfo = async () => {
    if (!auth?.accessToken) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch("http://localhost:4000/userinfo", {
        headers: {
          Authorization: `Bearer ${auth.accessToken}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setUserInfo(data);
      } else if (response.status === 401) {
        setError("Token expired. Try refreshing...");
      } else {
        setError(`Failed to fetch user info: ${response.status}`);
      }
    } catch (err) {
      setError(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleRefreshToken = async () => {
    if (auth?.refreshToken) {
      await refreshAccessToken(auth.refreshToken);
    }
  };

  useEffect(() => {
    if (auth?.accessToken) {
      fetchUserInfo();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auth?.accessToken]); // Refetch when access token changes

  if (!auth) {
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
          padding: '60px 80px',
          borderRadius: '16px',
          boxShadow: '0 10px 40px rgba(0,0,0,0.15)'
        }}>
          <div style={{ fontSize: '64px', marginBottom: '20px' }}>🔒</div>
          <h1 style={{ color: '#333', marginBottom: '10px' }}>Not Authenticated</h1>
          <p style={{ color: '#666', marginBottom: '30px' }}>Please sign in to continue</p>
          <Link to="/login" style={{
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            color: 'white',
            textDecoration: 'none',
            padding: '12px 30px',
            borderRadius: '25px',
            fontWeight: 'bold',
            display: 'inline-block',
            boxShadow: '0 4px 15px rgba(102, 126, 234, 0.4)'
          }}>Go to Login</Link>
        </div>
      </div>
    );
  }

  const expiresAt = new Date(auth.loginTime + (auth.expiresIn * 1000));
  const timeRemaining = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));

  const formatTime = (seconds) => {
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}m ${secs}s`;
  };

  return (
    <div style={{
      padding: '40px 20px',
      maxWidth: '1200px',
      margin: '0 auto'
    }}>
      <div style={{
        background: 'white',
        borderRadius: '16px',
        padding: '40px',
        boxShadow: '0 10px 40px rgba(0,0,0,0.1)',
        marginBottom: '30px'
      }}>
        <h1 style={{
          color: '#667eea',
          marginBottom: '10px',
          display: 'flex',
          alignItems: 'center',
          gap: '15px'
        }}>
          <span style={{ fontSize: '40px' }}>👤</span>
          Welcome, {auth.name || 'User'}!
        </h1>
        <p style={{
          color: '#666',
          fontSize: '16px',
          margin: '0 0 30px 0'
        }}>
          ✅ You are successfully authenticated with OpenID Connect
        </p>

        {/* Token Status Card */}
        <div style={{
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          padding: '25px',
          borderRadius: '12px',
          color: 'white',
          marginBottom: '30px'
        }}>
          <h3 style={{ margin: '0 0 15px 0', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span>🔑</span> Token Status
          </h3>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '20px'
          }}>
            <div>
              <div style={{ fontSize: '12px', opacity: 0.9, marginBottom: '5px' }}>Access Token Expires In</div>
              <div style={{ fontSize: '28px', fontWeight: 'bold' }}>{formatTime(timeRemaining)}</div>
            </div>
            <div>
              <div style={{ fontSize: '12px', opacity: 0.9, marginBottom: '5px' }}>Refresh Token</div>
              <div style={{ fontSize: '28px', fontWeight: 'bold' }}>{auth.refreshToken ? '✓ Available' : '✗ None'}</div>
            </div>
          </div>
          {auth.refreshToken && (
            <button
              onClick={handleRefreshToken}
              style={{
                marginTop: '20px',
                background: 'rgba(255,255,255,0.2)',
                border: '2px solid white',
                color: 'white',
                padding: '10px 20px',
                borderRadius: '20px',
                cursor: 'pointer',
                fontWeight: 'bold',
                transition: 'all 0.3s'
              }}
              onMouseOver={(e) => {
                e.target.style.background = 'white';
                e.target.style.color = '#667eea';
              }}
              onMouseOut={(e) => {
                e.target.style.background = 'rgba(255,255,255,0.2)';
                e.target.style.color = 'white';
              }}
            >
              🔄 Refresh Token Now
            </button>
          )}
        </div>

        {/* ID Token Claims Card */}
        <div style={{
          background: '#f8f9fa',
          padding: '25px',
          borderRadius: '12px',
          marginBottom: '30px',
          border: '2px solid #e9ecef'
        }}>
          <h3 style={{
            color: '#667eea',
            marginTop: 0,
            marginBottom: '20px',
            display: 'flex',
            alignItems: 'center',
            gap: '10px'
          }}>
            <span>🎫</span> ID Token Claims
          </h3>
          {auth.claims ? (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))',
              gap: '15px'
            }}>
              {Object.entries(auth.claims).map(([key, value]) => (
                <div key={key} style={{
                  background: 'white',
                  padding: '15px',
                  borderRadius: '8px',
                  boxShadow: '0 2px 8px rgba(0,0,0,0.05)'
                }}>
                  <div style={{
                    fontSize: '11px',
                    color: '#999',
                    textTransform: 'uppercase',
                    fontWeight: 'bold',
                    marginBottom: '5px',
                    letterSpacing: '0.5px'
                  }}>{key}</div>
                  <div style={{
                    fontSize: '14px',
                    color: '#333',
                    wordBreak: 'break-all',
                    fontFamily: 'monospace'
                  }}>{typeof value === 'object' ? JSON.stringify(value) : String(value)}</div>
                </div>
              ))}
            </div>
          ) : (
            <div>
              <p style={{ color: '#ff9800', fontStyle: 'italic', marginBottom: '15px' }}>⚠️ No claims found in auth object</p>
              <details style={{ marginTop: '15px' }}>
                <summary style={{ cursor: 'pointer', color: '#667eea', fontWeight: 'bold' }}>🔍 Debug: Full Auth Object</summary>
                <pre style={{ 
                  background: '#fff3cd', 
                  padding: '15px', 
                  borderRadius: '8px', 
                  fontSize: '12px',
                  overflow: 'auto',
                  marginTop: '10px'
                }}>
                  {JSON.stringify(auth, null, 2)}
                </pre>
              </details>
            </div>
          )}
        </div>

        {/* UserInfo Card */}
        <div style={{
          background: '#f8f9fa',
          padding: '25px',
          borderRadius: '12px',
          border: '2px solid #e9ecef'
        }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '20px'
          }}>
            <h3 style={{
              color: '#667eea',
              margin: 0,
              display: 'flex',
              alignItems: 'center',
              gap: '10px'
            }}>
              <span>ℹ️</span> UserInfo Endpoint Response
            </h3>
            <button
              onClick={fetchUserInfo}
              disabled={loading}
              style={{
                background: loading ? '#ccc' : 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                color: 'white',
                border: 'none',
                padding: '8px 16px',
                borderRadius: '20px',
                cursor: loading ? 'not-allowed' : 'pointer',
                fontWeight: 'bold',
                fontSize: '13px',
                transition: 'transform 0.2s'
              }}
              onMouseOver={(e) => !loading && (e.target.style.transform = 'scale(1.05)')}
              onMouseOut={(e) => e.target.style.transform = 'scale(1)'}
            >
              {loading ? '⏳ Loading...' : '🔄 Refresh'}
            </button>
          </div>

          {error && (
            <div style={{
              background: '#fee',
              color: '#c33',
              padding: '15px',
              borderRadius: '8px',
              marginBottom: '15px',
              border: '1px solid #fcc'
            }}>
              {error}
            </div>
          )}

          {userInfo ? (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))',
              gap: '15px'
            }}>
              {Object.entries(userInfo).map(([key, value]) => (
                <div key={key} style={{
                  background: 'white',
                  padding: '15px',
                  borderRadius: '8px',
                  boxShadow: '0 2px 8px rgba(0,0,0,0.05)'
                }}>
                  <div style={{
                    fontSize: '11px',
                    color: '#999',
                    textTransform: 'uppercase',
                    fontWeight: 'bold',
                    marginBottom: '5px',
                    letterSpacing: '0.5px'
                  }}>{key}</div>
                  <div style={{
                    fontSize: '14px',
                    color: '#333',
                    wordBreak: 'break-all',
                    fontFamily: 'monospace'
                  }}>{typeof value === 'object' ? JSON.stringify(value) : String(value)}</div>
                </div>
              ))}
            </div>
          ) : !loading && !error && (
            <div style={{ textAlign: 'center', padding: '40px 20px', color: '#999' }}>
              <div style={{ fontSize: '48px', marginBottom: '15px' }}>📋</div>
              <p style={{ fontStyle: 'italic' }}>Click refresh to load user information</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

