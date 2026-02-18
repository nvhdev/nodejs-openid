const Client = require('../models/client');
const RefreshTokens = require('../models/refresh-tokens');

// In-memory revoked token store (use Redis in production)
const revokedTokens = new Set();

exports.postRevoke = async (req, res) => {
  let { token, token_type_hint, client_id, client_secret } = req.body;
  
  // Support client_secret_basic authentication
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Basic ')) {
    const base64Credentials = authHeader.slice(6);
    const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
    const [headerClientId, headerClientSecret] = credentials.split(':');
    
    client_id = client_id || headerClientId;
    client_secret = client_secret || headerClientSecret;
  }

  const client = Client.findById(client_id);
  if (!client || client.client_secret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  // Reject ID token revocation
  if (token_type_hint === 'id_token') {
    return res.status(400).json({ error: 'unsupported_token_type' });
  }

  // Revoke refresh tokens
  if (token_type_hint === 'refresh_token' || !token_type_hint) {
    RefreshTokens.revoke(token);
  }

  // Revoke access tokens
  if (token_type_hint === 'access_token' || !token_type_hint) {
    revokedTokens.add(token);
  }

  return res.status(200).send('');
};

// Export for token validation middleware
exports.isTokenRevoked = (token) => {
  return revokedTokens.has(token);
};
