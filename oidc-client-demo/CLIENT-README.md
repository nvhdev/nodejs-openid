# OIDC Client Demo

A React-based demonstration client for OpenID Connect authentication.

## Features

✅ **Core OIDC Flow**
- Authorization Code Flow with PKCE
- State and Nonce validation
- ID Token parsing
- UserInfo endpoint calls

✅ **Token Management**
- Refresh token support
- Automatic token refresh (5 min before expiry)
- Manual refresh token button
- Token expiration countdown

✅ **Security**
- PKCE (Proof Key for Code Exchange)
- State parameter (CSRF protection)
- Nonce validation (replay attack prevention)
- Secure session storage

✅ **User Experience**
- Real-time token status
- UserInfo data display
- RP-Initiated Logout
- Error handling

## Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Configure (if needed):**
   Edit `src/config.js` to change OIDC provider settings

3. **Start the demo:**
   ```bash
   npm start
   ```
   
   Opens at http://localhost:3000

## Usage Flow

1. Click **"Login with OIDC Provider"**
2. Redirected to OIDC server login
3. Enter credentials (see server's predefined-users.json)
4. Redirected back to app with tokens
5. View ID Token claims and UserInfo
6. Watch token auto-refresh before expiration
7. Click **Logout** to end session

## Token Display

The home page shows:
- **ID Token Claims** - From the JWT
- **UserInfo Response** - From `/userinfo` endpoint
- **Token Expiration** - Countdown timer
- **Refresh Status** - Whether refresh token available

## Configuration

Default settings in `src/config.js`:

```javascript
{
  issuer: 'http://localhost:4000',
  clientId: 'demo-client',
  redirectUri: 'http://localhost:3000/callback',
  scopes: ['openid', 'profile', 'offline_access']
}
```

## Security Notes

⚠️ **For Demo Purposes Only**

- Client secret is exposed in frontend code
- No backend proxy for token exchange
- HTTP only (no HTTPS)

**Production Requirements:**
1. Move token exchange to backend
2. Never expose client_secret in frontend
3. Use HTTPS
4. Implement proper error boundaries
5. Add request timeout handling
6. Store tokens in httpOnly cookies (via backend)

## Testing Refresh Tokens

1. Login successfully
2. Wait for token to expire (or click manual refresh)
3. Observe automatic token refresh
4. Try calling UserInfo - should work with new token

## Troubleshooting

**"Invalid state"**
- Clear browser session storage
- Try login again

**"Token expired"**
- Click "Manually Refresh Token"
- Or wait for automatic refresh

**CORS errors**
- Ensure server has correct CORS settings
- Check server is running on port 4000

## Architecture

```
LoginPage
  ↓ (generates PKCE, state, nonce)
OIDC Server /authorize
  ↓ (user authenticates)
CallbackPage
  ↓ (exchanges code for tokens)
AuthContext
  ↓ (stores tokens, auto-refresh)
HomePage
  ↓ (displays claims, calls UserInfo)
```

## Dependencies

- React 19
- React Router 7
- Native Web Crypto API (PKCE)
- Fetch API (token exchange)
