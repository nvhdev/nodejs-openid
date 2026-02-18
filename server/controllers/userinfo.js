
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { isTokenRevoked } = require('./revoke');

let PUBLIC_KEY;
try {
  PUBLIC_KEY = fs.readFileSync(path.join(__dirname, '..', 'keys/public.pem'), 'utf8');
} catch (err) {
  console.error('FATAL: Cannot load public key:', err.message);
  process.exit(1);
}
// JWT auth middleware
exports.jwtAuthMiddleware = (req, res, next) => {
  const auth = req.headers.authorization || '';
  const parts = auth.split(' ');

  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const token = parts[1];

  // Check if token is revoked
  if (isTokenRevoked(token)) {
    return res.status(401).json({ error: 'invalid_token', error_description: 'Token has been revoked' });
  }

  try {
    const payload = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
    req.tokenPayload = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

exports.getUserInfo = (req, res) => {
  const { iss, aud, iat, exp, scope, nonce, ...claims } = req.tokenPayload;
  res.json(claims);
};
