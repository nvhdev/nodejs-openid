const fs = require('fs');
const path = require('path');
const { importSPKI, exportJWK } = require('jose');

let PUBLIC_KEY;
try {
  PUBLIC_KEY = fs.readFileSync(path.join(__dirname, '..', 'keys/public.pem'), 'utf8');
} catch (err) {
  console.error('FATAL: Cannot load public key:', err.message);
  process.exit(1);
}

const KEY_ID = 'main-rs256-key';

exports.getJwk = async (req, res, next) => {
  const publicKey = await importSPKI(PUBLIC_KEY, 'RS256');
  const jwk = await exportJWK(publicKey);

  jwk.use = 'sig';
  jwk.alg = 'RS256';
  jwk.kid = KEY_ID;

  res.json({ keys: [jwk] });
};