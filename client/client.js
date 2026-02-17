import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import crypto from 'crypto';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// -------------------------------
// CONFIG
// -------------------------------
const ISSUER = 'http://localhost:4000';
const CLIENT_ID = 'demo-client';
const CLIENT_SECRET = 'supersecret';
const REDIRECT_URI = 'http://localhost:3000/callback';

// -------------------------------
// DISCOVERY DOCUMENT
// -------------------------------
let discovery = null;
let JWKS = null;

async function loadDiscovery() {
  const res = await fetch(`${ISSUER}/.well-known/openid-configuration`);
  discovery = await res.json();

  JWKS = createRemoteJWKSet(new URL(discovery.jwks_uri));

  console.log('Loaded discovery document:');
  console.log(discovery);
}

await loadDiscovery();

// -------------------------------
// SESSION
// -------------------------------
let session = {
  id_token: null,
  access_token: null,
  refresh_token: null,
  claims: null,
  code_verifier: null
};

// -------------------------------
// HOME PAGE
// -------------------------------
app.get('/', (req, res) => {
  res.render('home', {
    loggedIn: !!session.id_token,
    claims: session
  });
});

// -------------------------------
// LOGIN → Redirect to /authorize
// -------------------------------
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(8).toString('hex');
  const nonce = crypto.randomBytes(8).toString('hex');

  // PKCE
  const code_verifier = crypto.randomBytes(32).toString('hex');
  const hash = crypto.createHash('sha256').update(code_verifier).digest();
  const code_challenge = hash
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  session.code_verifier = code_verifier;

  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('scope', 'openid profile offline_access');
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', code_challenge);
  url.searchParams.set('code_challenge_method', 'S256');

  res.redirect(url.toString());
});

// -------------------------------
// CALLBACK → Exchange code for tokens
// -------------------------------
app.get('/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing code');

  const tokenRes = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code_verifier: session.code_verifier
    })
  });

  if (!tokenRes.ok) {
    const err = await tokenRes.text();
    return res.status(500).send('Token error:\n' + err);
  }

  const tokenData = await tokenRes.json();
  const { id_token, access_token, refresh_token } = tokenData;

  // Verify ID token via JWKS
  try {
    const { payload } = await jwtVerify(id_token, JWKS, {
      issuer: discovery.issuer,
      audience: CLIENT_ID
    });

    session.id_token = id_token;
    session.access_token = access_token;
    session.refresh_token = refresh_token;
    session.claims = payload;

    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(401).send('Invalid ID token');
  }
});

// -------------------------------
// REVOKE ACCESS TOKEN
// -------------------------------
app.post('/revoke', async (req, res) => {
  if (!session.access_token) {
    return res.redirect('/');
  }

  await fetch(discovery.revocation_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token: session.access_token,
      token_type_hint: 'access_token',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET
    })
  });

  session.access_token = null;

  res.redirect('/');
});

// -------------------------------
// LOGOUT (end_session_endpoint)
// -------------------------------
app.post('/logout', async (req, res) => {
  const id_token_hint = session.id_token;

  // Clear local session
  session = {
    id_token: null,
    access_token: null,
    refresh_token: null,
    claims: null,
    code_verifier: null
  };

  // Redirect browser to the OIDC logout endpoint
  const url = new URL(discovery.end_session_endpoint);
  url.searchParams.set('id_token_hint', id_token_hint);
  url.searchParams.set('post_logout_redirect_uri', 'http://localhost:3000');

  res.redirect(url.toString());
});


// -------------------------------
app.listen(3000, () => {
  console.log('Client running at http://localhost:3000');
});
