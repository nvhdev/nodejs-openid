
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const AuthCodes = require('../models/auth-codes');

const ID_TOKEN_SECRET = "id-token-secret"; 
const ACCESS_TOKEN_SECRET = "access-token-secret";

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
    iss: "http://localhost:4000",
    nonce,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };

  return jwt.sign(payload, ID_TOKEN_SECRET);
}

function signAccessToken(claims, { client_id }) {
  const payload = {
    sub: claims.sub,
    scope: claims.scope || "openid profile",
    aud: client_id,
    iss: "http://localhost:4000",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };

  return jwt.sign(payload, ACCESS_TOKEN_SECRET);
}


exports.postToken = (req, res, next) => {
     const {
        grant_type,
        code,
        redirect_uri,
        client_id,
        client_secret,
        code_verifier
      } = req.body;
    
      if (grant_type !== "authorization_code") {
        return res.status(400).json({ error: "unsupported_grant_type" });
      }
    
      const auth = AuthCodes.get(code);
      if (!auth) {
        return res.status(400).json({ error: "invalid_grant" });
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
    
      res.json({
        access_token,
        id_token,
        token_type: "Bearer",
        expires_in: 3600
      });
};