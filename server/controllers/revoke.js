const Client = require('../models/client');
exports.postRevoke = async (req, res) => {
  const { token, token_type_hint, client_id, client_secret } = req.body;

  const client = Client.findById(client_id);
  if (!client || client.client_secret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  // Reject ID token revocation
  if (token_type_hint === 'id_token') {
    return res.status(400).json({ error: 'unsupported_token_type' });
  }

  // Revoke refresh tokens
  if (token_type_hint === 'refresh_token') {
    refreshTokens.delete(token);
  }

  // Revoke access tokens
  if (token_type_hint === 'access_token') {
    revokedTokens.add(token);
  }

  return res.status(200).send('');
};
