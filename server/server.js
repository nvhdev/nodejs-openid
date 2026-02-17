const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { importSPKI, exportJWK } = require('jose');
const session = require('express-session');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
  secret: 'super-secret-session-key',
  resave: false,
  saveUninitialized: false,
  rolling: true, // refresh expiration on each request
  cookie: {
    maxAge: 15 * 60 * 1000, // 15 minutes
    httpOnly: true,
    secure: false // set to true if using HTTPS
  }
}));


const clients = JSON.parse(fs.readFileSync(path.join(__dirname, 'clients.json'), 'utf8'));
const users = JSON.parse(fs.readFileSync(path.join(__dirname, 'users.json'), 'utf8'));

const ISSUER = 'http://localhost:4000';

// Load RS256 keys
const PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'keys/private.pem'), 'utf8');
const PUBLIC_KEY = fs.readFileSync(path.join(__dirname, 'keys/public.pem'), 'utf8');
const KEY_ID = 'main-rs256-key';

// In-memory stores
const authCodes = new Map();      // code -> { client_id, redirect_uri, claims, code_challenge, code_challenge_method, nonce }
const refreshTokens = new Map();  // refresh_token -> { client_id, sub, claims }
const revokedTokens = new Set();  // access/refresh tokens

const predefinedUsers = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'predefined-users.json'), 'utf8')
);

function getClient(client_id) {
  return clients.find(c => c.client_id === client_id);
}

function getUser(sub) {
  return users.find(u => u.sub === sub);
}

function base64url(input) {
  return input.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function verifyPKCE(code_verifier, code_challenge, method) {
  if (!code_challenge) return true;
  if (method === 'S256') {
    const hash = crypto.createHash('sha256').update(code_verifier).digest();
    const expected = base64url(hash);
    return expected === code_challenge;
  }
  if (method === 'plain') {
    return code_verifier === code_challenge;
  }
  return false;
}

// Discovery
app.get('/.well-known/openid-configuration', (req, res) => {
  const issuer = ISSUER;
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/jwks.json`,
    revocation_endpoint: `${issuer}/revoke`,
    end_session_endpoint: `${issuer}/logout`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    scopes_supported: ['openid', 'profile', 'offline_access'],
    claims_supported: ['sub', 'email', 'name', 'role']
  });
});

// JWKS
app.get('/jwks.json', async (req, res) => {
  const publicKey = await importSPKI(PUBLIC_KEY, 'RS256');
  const jwk = await exportJWK(publicKey);

  jwk.use = 'sig';
  jwk.alg = 'RS256';
  jwk.kid = KEY_ID;

  res.json({ keys: [jwk] });
});


// Authorization endpoint
app.get('/authorize', (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope,
    state,
    code_challenge,
    code_challenge_method,
    nonce
  } = req.query;

  const client = getClient(client_id);
  if (!client) return res.status(400).send('invalid_client');

  // 🔥 If user already logged in → skip login page
  if (req.session.user) {
    const code = uuidv4();

    authCodes.set(code, {
      client_id,
      redirect_uri,
      claims: req.session.user.claims,
      code_challenge,
      code_challenge_method,
      nonce
    });

    const url = new URL(redirect_uri);
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state);

    return res.redirect(url.toString());
  }

  // Otherwise show login page

  res.render('login', {
    client,
    redirect_uri,
    state: state || '',
    code_challenge: code_challenge || '',
    code_challenge_method: code_challenge_method || '',
    nonce: nonce || '',
    predefined: predefinedUsers[client_id] || []
    });

});


// Login handler
app.post('/login', (req, res) => {
  const {
    client_id,
    redirect_uri,
    state,
    code_challenge,
    code_challenge_method,
    nonce,
    sub,
    password,
    ...rest
  } = req.body;

  const client = getClient(client_id);
  if (!client) return res.status(400).send('invalid_client');
  if (!client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).send('invalid_redirect_uri');
  }

  const user = getUser(sub);
  if (!user || user.password !== password) {
    return res.status(401).send('invalid_credentials');
  }

  // Build claims
    const claims = { sub: user.sub };

    // Predefined claims
    client.allowed_claim_fields.forEach(field => {
    if (req.body[field]) {
        claims[field] = req.body[field];
    } else if (user[field]) {
        claims[field] = user[field];
    }
    });

    // Dynamic claims
    console.log("BODY:", req.body);

    let names = req.body.claim_name;
    let values = req.body.claim_value;

    console.log("Parsed dynamic claims:", names, values);

    if (names && values) {
    if (!Array.isArray(names)) names = [names];
    if (!Array.isArray(values)) values = [values];

    for (let i = 0; i < names.length; i++) {
        const key = names[i].trim();
        const value = values[i].trim();
        if (key && value) {
        claims[key] = value;
        }
    }
    }




  const code = uuidv4();
  authCodes.set(code, {
    client_id,
    redirect_uri,
    claims,
    code_challenge,
    code_challenge_method,
    nonce
  });

  const url = new URL(redirect_uri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);

  req.session.user = {
    sub: user.sub,
    claims
  };

  res.redirect(url.toString());
});

// Token endpoint
app.post('/token', (req, res) => {
  const {
    grant_type,
    code,
    redirect_uri,
    client_id,
    client_secret,
    code_verifier,
    refresh_token
  } = req.body;

  const client = getClient(client_id);
  if (!client || client.client_secret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  const now = Math.floor(Date.now() / 1000);

  if (grant_type === 'authorization_code') {
    const codeData = authCodes.get(code);
    if (!codeData) return res.status(400).json({ error: 'invalid_grant' });
    if (codeData.client_id !== client_id) return res.status(400).json({ error: 'invalid_grant' });
    if (codeData.redirect_uri !== redirect_uri) return res.status(400).json({ error: 'invalid_grant' });

    if (!verifyPKCE(code_verifier || '', codeData.code_challenge, codeData.code_challenge_method)) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
    }

    authCodes.delete(code);

    const idTokenPayload = {
      iss: ISSUER,
      aud: client_id,
      iat: now,
      exp: now + 3600,
      nonce: codeData.nonce || undefined,
      ...codeData.claims
    };

    const id_token = jwt.sign(idTokenPayload, PRIVATE_KEY, {
      algorithm: 'RS256',
      keyid: KEY_ID
    });

    const accessTokenPayload = {
      iss: ISSUER,
      sub: codeData.claims.sub,
      aud: client_id,
      iat: now,
      exp: now + 3600,
      scope: 'openid profile offline_access'
    };

    const access_token = jwt.sign(accessTokenPayload, PRIVATE_KEY, {
      algorithm: 'RS256',
      keyid: KEY_ID
    });

    const newRefreshToken = uuidv4();
    refreshTokens.set(newRefreshToken, {
      client_id,
      sub: codeData.claims.sub,
      claims: codeData.claims
    });

    return res.json({
      token_type: 'Bearer',
      expires_in: 3600,
      access_token,
      id_token,
      refresh_token: newRefreshToken
    });
  }

  if (grant_type === 'refresh_token') {
    const data = refreshTokens.get(refresh_token);
    if (!data || data.client_id !== client_id) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    if (revokedTokens.has(refresh_token)) {
      return res.status(400).json({ error: 'invalid_grant' });
    }

    const idTokenPayload = {
      iss: ISSUER,
      aud: client_id,
      iat: now,
      exp: now + 3600,
      ...data.claims
    };

    const id_token = jwt.sign(idTokenPayload, PRIVATE_KEY, {
      algorithm: 'RS256',
      keyid: KEY_ID
    });

    const accessTokenPayload = {
      iss: ISSUER,
      sub: data.sub,
      aud: client_id,
      iat: now,
      exp: now + 3600,
      scope: 'openid profile offline_access'
    };

    const access_token = jwt.sign(accessTokenPayload, PRIVATE_KEY, {
      algorithm: 'RS256',
      keyid: KEY_ID
    });

    const newRefreshToken = uuidv4();
    refreshTokens.set(newRefreshToken, data);
    revokedTokens.add(refresh_token);

    return res.json({
      token_type: 'Bearer',
      expires_in: 3600,
      access_token,
      id_token,
      refresh_token: newRefreshToken
    });
  }

  return res.status(400).json({ error: 'unsupported_grant_type' });
});

// Revocation endpoint
app.post('/revoke', (req, res) => {
  const { token, token_type_hint, client_id, client_secret } = req.body;

  const client = getClient(client_id);
  if (!client || client.client_secret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  revokedTokens.add(token);
  refreshTokens.delete(token);

  res.status(200).send('');
});

// JWT auth middleware
function jwtAuthMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const parts = auth.split(' ');

  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const token = parts[1];

  if (revokedTokens.has(token)) {
    return res.status(401).json({ error: 'revoked_token' });
  }

  try {
    const payload = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
    req.tokenPayload = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// Userinfo
app.get('/userinfo', jwtAuthMiddleware, (req, res) => {
  const { iss, aud, iat, exp, scope, nonce, ...claims } = req.tokenPayload;
  res.json(claims);
});

// Logout (end_session_endpoint)
app.post('/logout', (req, res) => {
  const { id_token_hint, post_logout_redirect_uri } = req.body;

  if (id_token_hint) {
    try {
      jwt.verify(id_token_hint, PUBLIC_KEY, { algorithms: ['RS256'] });
    } catch (e) {
      // ignore invalid id_token_hint
    }
  }

  if (post_logout_redirect_uri) {
    return res.redirect(post_logout_redirect_uri);
  }

  res.send('Logged out');
});

app.get('/logout', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/session-expired');
    }

  req.session.destroy(() => {
    const { post_logout_redirect_uri } = req.query;
    if (post_logout_redirect_uri) {
      return res.redirect(post_logout_redirect_uri);
    }
    res.send('Logged out');
  });
});
app.get('/session-expired', (req, res) => {
    res.send('Your session has expired. Please log in again.');
});


app.listen(4000, () => {
  console.log('OIDC server running at http://localhost:4000');
});
