
const { v4: uuidv4 } = require('uuid');

const User = require('../models/user');
const AuthCodes = require('../models/auth-codes');

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

exports.postLogin = (req, res, next) => {
  
  const { sub, password, client_id, redirect_uri, state, code_challenge, code_challenge_method, nonce } = req.body;
  
    const user = User.findBySub(sub);
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
  
    AuthCodes.set(code, {
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
};