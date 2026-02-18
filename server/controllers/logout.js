
const jwt = require('jsonwebtoken');
const RefreshTokens = require('../models/refresh-tokens');

exports.getLogout = async (req, res) => {
  let { client_id, post_logout_redirect_uri, id_token_hint } = req.query;

  console.log("Logout request:", { client_id, has_id_token_hint: !!id_token_hint });

  // 1. Decode id_token_hint
  let hintSub = null;
  if (id_token_hint) {
    try {
      const decoded = jwt.decode(id_token_hint);
      hintSub = decoded?.sub;
      
      // Extract client_id from token if not provided
      if (!client_id && decoded?.aud) {
        client_id = decoded.aud;
        console.log("Extracted client_id from id_token_hint:", client_id);
      }
      
      console.log("id_token_hint sub:", hintSub);
    } catch (err) {
      console.log("Invalid id_token_hint");
    }
  }
  
  // Require client_id (from query or token)
  if (!client_id) {
    console.log("Logout denied: no client_id provided");
    return res.status(400).send("invalid_logout_request");
  }

  // 2. Get session user
  console.log(req.session.clients);
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
    
    // Revoke all refresh tokens for this user/client
    if (sessionSub) {
      RefreshTokens.revokeAllForUser(client_id, sessionSub);
      console.log("Revoked all refresh tokens for user:", sessionSub);
    }
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
};
