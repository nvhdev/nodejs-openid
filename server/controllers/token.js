
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const AuthCodes = require('../models/auth-codes');
const RefreshTokens = require('../models/refresh-tokens');
const Client = require('../models/client');
const User = require('../models/user');

let PRIVATE_KEY;
try {
  PRIVATE_KEY = fs.readFileSync(path.join(__dirname, '..', 'keys/private.pem'), 'utf8');
} catch (err) {
  console.error('FATAL: Cannot load private key:', err.message);
  process.exit(1);
}

const KEY_ID = 'main-rs256-key';
const ISSUER = process.env.ISSUER || 'http://localhost:4000';

function base64url(input) {
  return input.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}


function signIdToken(claims, { client_id, nonce }) {
  const payload = {
    ...claims,
    aud: client_id,
    iss: ISSUER,
    nonce,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };

  return jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256', keyid: KEY_ID });
}

function signAccessToken(claims, { client_id }) {
  const payload = {
    sub: claims.sub,
    scope: claims.scope || "openid profile",
    aud: client_id,
    iss: ISSUER,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };

  return jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256', keyid: KEY_ID });
}


exports.postToken = (req, res, next) => {
     let {
        grant_type,
        code,
        redirect_uri,
        client_id,
        client_secret,
        code_verifier,
        refresh_token,
        scope
      } = req.body;
    
      // Support client_secret_basic authentication (Authorization header)
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Basic ')) {
        const base64Credentials = authHeader.slice(6);
        const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
        const [headerClientId, headerClientSecret] = credentials.split(':');
        
        // Use header credentials if not provided in body
        client_id = client_id || headerClientId;
        client_secret = client_secret || headerClientSecret;
      }
    
      // Validate client credentials first
      const client = Client.findById(client_id);
      if (!client) {
        return res.status(401).json({ error: "invalid_client" });
      }
    
      // Handle different grant types
      if (grant_type === "authorization_code") {
        return handleAuthorizationCodeGrant(req, res, {
          code,
          redirect_uri,
          client_id,
          client_secret,
          code_verifier,
          client
        });
      } else if (grant_type === "refresh_token") {
        return handleRefreshTokenGrant(req, res, {
          refresh_token,
          client_id,
          client_secret,
          scope,
          client
        });
      } else {
        return res.status(400).json({ error: "unsupported_grant_type" });
      }
};

function handleAuthorizationCodeGrant(req, res, params) {
  const { code, redirect_uri, client_id, client_secret, code_verifier, client } = params;
    
      const auth = AuthCodes.get(code);
      if (!auth) {
        return res.status(400).json({ error: "invalid_grant" });
      }
    
      // For confidential clients: require client_secret
      // For public clients with PKCE: allow without secret
      const isPKCEFlow = auth.code_challenge && code_verifier;
      if (!isPKCEFlow && client.client_secret !== client_secret) {
        return res.status(401).json({ error: "invalid_client" });
      }
    
      if (auth.client_id !== client_id || auth.redirect_uri !== redirect_uri) {
        return res.status(400).json({ error: "invalid_grant" });
      }
    
      // Optional: validate PKCE
      if (auth.code_challenge) {
        const expected = base64url(crypto.createHash("sha256").update(code_verifier).digest());
        if (expected !== auth.code_challenge) {
          return res.status(400).json({ error: "invalid_grant" });
        }
      }
    
      AuthCodes.delete(code); // one-time use
    
      const id_token = signIdToken(auth.claims, {
        client_id,
        nonce: auth.nonce
      });
    
      const access_token = signAccessToken(auth.claims, {
        client_id
      });
    
      // Check if offline_access scope is requested
      const scopes = auth.claims.scope ? auth.claims.scope.split(' ') : ['openid'];
      let refresh_token_value = null;
      
      if (scopes.includes('offline_access')) {
        refresh_token_value = RefreshTokens.create(
          client_id,
          auth.claims.sub,
          scopes.join(' ')
        );
      }
    
      const response = {
        access_token,
        id_token,
        token_type: "Bearer",
        expires_in: 3600
      };
      
      if (refresh_token_value) {
        response.refresh_token = refresh_token_value;
      }
    
      res.json(response);
}

function handleRefreshTokenGrant(req, res, params) {
  const { refresh_token, client_id, client_secret, scope, client } = params;
  
  // Validate client secret (refresh tokens always require authentication)
  if (client.client_secret !== client_secret) {
    return res.status(401).json({ error: "invalid_client" });
  }
  
  // Validate refresh token
  const tokenData = RefreshTokens.get(refresh_token);
  if (!tokenData) {
    return res.status(400).json({ error: "invalid_grant" });
  }
  
  // Verify token belongs to this client
  if (tokenData.clientId !== client_id) {
    return res.status(400).json({ error: "invalid_grant" });
  }
  
  // Get user data
  const user = User.findBySub(tokenData.userId);
  if (!user) {
    RefreshTokens.revoke(refresh_token);
    return res.status(400).json({ error: "invalid_grant" });
  }
  
  // Build claims from user
  const claims = {
    sub: user.sub,
    email: user.email,
    name: user.name,
    role: user.role,
    scope: scope || tokenData.scope
  };
  
  // Issue new access token
  const access_token = signAccessToken(claims, { client_id });
  
  // Optionally rotate refresh token (recommended for security)
  const newRefreshToken = RefreshTokens.create(
    client_id,
    user.sub,
    claims.scope
  );
  
  // Revoke old refresh token
  RefreshTokens.revoke(refresh_token);
  
  res.json({
    access_token,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: newRefreshToken,
    scope: claims.scope
  });
}