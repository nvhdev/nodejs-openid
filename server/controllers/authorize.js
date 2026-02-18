
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const AuthCodes = require('../models/auth-codes');
const Client = require('../models/client');
const PredefinedUser = require('../models/predefined-user');

exports.getAuthorize = (req, res, next) => {
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
  const client = Client.findById(client_id);
  if (!client) {
    console.log("Invalid client");
    return res.status(400).send("invalid_client");
  }

  // 2. Validate redirect_uri
  if (!redirect_uri || !client.isRedirectUriAllowed(redirect_uri)) {
    console.log("Invalid redirect_uri");
    return res.status(400).send("invalid_redirect_uri");
  }

  // 3. Validate response_type
  if (response_type !== "code") {
    console.log("Invalid response_type");
    return res.status(400).send("unsupported_response_type");
  }

  // 3. Check if user already logged in for this client
  const clientSession = req.session.clients?.[client_id];

  if (clientSession) {
    console.log("Auto-login branch");

    const code = uuidv4();

    AuthCodes.set(code, {
      client_id,
      redirect_uri,
      claims: { ...clientSession.claims, scope }, // Include scope
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
    scope: scope || "openid",
    state: state || "",
    code_challenge: code_challenge || "",
    code_challenge_method: code_challenge_method || "",
    nonce: nonce || "",
    predefined: PredefinedUser.getForClient(client_id)
  });
};