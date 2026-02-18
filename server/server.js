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
const SQLiteStore = require('connect-sqlite3')(session);
const app = express();

const cors = require("cors"); 

app.use(cors({ origin: "http://localhost:3000", credentials: false }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.set('trust proxy', 1); // important if behind proxy

app.use(session({
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    dir: './data',        // you can choose any folder,
    ttl: 5 * 60 // 5 minutes
  }),
  secret: 'super-secret-session-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 10 * 60 * 60, // 10 mins
    sameSite: 'lax',
    secure: false           // set true if using HTTPS
  }
}));



const clients = JSON.parse(fs.readFileSync(path.join(__dirname, 'clients.json'), 'utf8'));
const users = JSON.parse(fs.readFileSync(path.join(__dirname, 'users.json'), 'utf8'));

const CLIENT_SESSION_TTL_MS = 15 * 60 * 1000;

const ISSUER = 'http://localhost:4000';

const ID_TOKEN_SECRET = "id-token-secret"; 
const ACCESS_TOKEN_SECRET = "access-token-secret";
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


function getClient(client_id) {
  return clients.find(c => c.client_id === client_id);
}

function getUser(sub) {
  return users.find(u => u.sub === sub);
}
function findUser(client_id, sub, password) {
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

function buildClaimsForUser(user, body) {
  const claims = {};

  // 1. Base user fields
  claims.sub = user.sub;

  // 2. Predefined claim fields (from login form)
  for (const key in body) {
    if (
      key !== "sub" &&
      key !== "password" &&
      key !== "client_id" &&
      key !== "redirect_uri" &&
      key !== "state" &&
      key !== "code_challenge" &&
      key !== "code_challenge_method" &&
      key !== "nonce" &&
      key !== "claim_name[]" &&
      key !== "claim_value[]"  &&
      key !== "claim_name" &&
      key !== "claim_value"
    ) {
      claims[key] = body[key];
    }
  }

  // 3. Dynamic claims
const rawNames =
  body["claim_name[]"] ||
  body["claim_name"] ||
  [];
const rawValues =
  body["claim_value[]"] ||
  body["claim_value"] ||
  [];

const names = Array.isArray(rawNames) ? rawNames : [rawNames];
const values = Array.isArray(rawValues) ? rawValues : [rawValues];

for (let i = 0; i < names.length; i++) {
  const name = names[i];
  const value = values[i];

  if (name && value) {
    claims[name] = value;
  }
}


  return claims;
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
app.get("/authorize", (req, res) => {
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

  console.log("Authorize request:", req.query);

  // 1. Validate client
  const client = getClient(client_id);
  if (!client) {
    console.log("Invalid client");
    return res.status(400).send("invalid_client");
  }

  // 2. Validate response_type
  if (response_type !== "code") {
    console.log("Invalid response_type");
    return res.status(400).send("unsupported_response_type");
  }

  // 3. Check if user already logged in for this client
  const clientSession = req.session.clients?.[client_id];

  if (clientSession) {
    console.log("Auto-login branch");

    const code = uuidv4();

    authCodes.set(code, {
      client_id,
      redirect_uri,
      claims: clientSession.claims,
      code_challenge,
      code_challenge_method,
      nonce
    });

    const url = new URL(redirect_uri);
    url.searchParams.set("code", code);
    if (state) url.searchParams.set("state", state);

    return res.redirect(url.toString());   // IMPORTANT: return!
  }

  // 4. Otherwise show login page
  console.log("Show login page branch");

  return res.render("login", {
    client,
    client_id,
    redirect_uri,
    state: state || "",
    code_challenge: code_challenge || "",
    code_challenge_method: code_challenge_method || "",
    nonce: nonce || "",
    predefined: predefinedUsers[client_id] || []
  });
});



// Login handler
app.post("/login", (req, res) => {
  const { sub, password, client_id, redirect_uri, state, code_challenge, code_challenge_method, nonce } = req.body;

  const user = findUser(client_id, sub, password);
  if (!user) return res.status(401).send("invalid_credentials");

  const claims = buildClaimsForUser(user, req.body);
  
  // store per-client session
  req.session.clients = req.session.clients || {};
  req.session.clients[client_id] = {
    sub: user.sub,
    claims,
    loginTime: Date.now()
  };

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
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);

  res.redirect(url.toString());
});


// Token endpoint
app.post("/token", express.urlencoded({ extended: false }), (req, res) => {
  const {
    grant_type,
    code,
    redirect_uri,
    client_id,
    code_verifier
  } = req.body;

  if (grant_type !== "authorization_code") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }

  const auth = authCodes.get(code);
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

  authCodes.delete(code); // one-time use

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
app.get("/logout", (req, res) => {
  const { client_id, post_logout_redirect_uri, id_token_hint } = req.query;

  console.log("Logout request:", { client_id });

  // 1. Decode id_token_hint
  let hintSub = null;
  if (id_token_hint) {
    try {
      const decoded = jwt.decode(id_token_hint);
      hintSub = decoded?.sub;
      console.log("id_token_hint sub:", hintSub);
    } catch (err) {
      console.log("Invalid id_token_hint");
    }
  }

  // 2. Get session user
  const sessionEntry = req.session.clients?.[client_id];
  if (!sessionEntry) {
    console.log("Logout denied: no active session for client");
    return res.status(400).send("invalid_logout_request");
  }
  const sessionSub = sessionEntry?.sub;

  // 3. Validate id_token_hint matches session
  if (id_token_hint && hintSub && sessionSub && hintSub !== sessionSub) {
    console.log("Logout denied: id_token_hint mismatch");
    return res.status(400).send("invalid_logout_request");
  }

  // 4. Remove this client's session
  if (sessionEntry) {
    delete req.session.clients[client_id];
  }

  // 5. Destroy entire session if empty
  if (!req.session.clients || Object.keys(req.session.clients).length === 0) {
    return req.session.destroy(() => {
      res.clearCookie("connect.sid");
      if (post_logout_redirect_uri) {
        return res.redirect(post_logout_redirect_uri);
      }
      return res.send("Logged out");
    });
  }

  // 6. Otherwise redirect back
  if (post_logout_redirect_uri) {
    return res.redirect(post_logout_redirect_uri);
  }

  return res.send("Logged out for this client");
});




app.get('/session-expired', (req, res) => {
    res.send('Your session has expired. Please log in again.');
});


app.listen(4000, () => {
  console.log('OIDC server running at http://localhost:4000');
});
