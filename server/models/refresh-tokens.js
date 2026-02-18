const crypto = require('crypto');

const refreshTokens = new Map();

// Refresh tokens expire after 30 days
const REFRESH_TOKEN_EXPIRATION_MS = 30 * 24 * 60 * 60 * 1000;

module.exports = {
  create(clientId, userId, scope) {
    const token = crypto.randomBytes(32).toString('hex');
    
    refreshTokens.set(token, {
      clientId,
      userId,
      scope,
      createdAt: Date.now()
    });
    
    return token;
  },

  get(token) {
    const data = refreshTokens.get(token);
    if (!data) return null;

    // Check expiration
    const age = Date.now() - data.createdAt;
    if (age > REFRESH_TOKEN_EXPIRATION_MS) {
      refreshTokens.delete(token);
      return null;
    }

    return data;
  },

  revoke(token) {
    refreshTokens.delete(token);
  },

  revokeAllForUser(clientId, userId) {
    for (const [token, data] of refreshTokens.entries()) {
      if (data.clientId === clientId && data.userId === userId) {
        refreshTokens.delete(token);
      }
    }
  },

  // Cleanup expired tokens every hour
  startCleanup() {
    setInterval(() => {
      const now = Date.now();
      for (const [token, data] of refreshTokens.entries()) {
        if (now - data.createdAt > REFRESH_TOKEN_EXPIRATION_MS) {
          refreshTokens.delete(token);
        }
      }
    }, 60 * 60 * 1000);
  }
};
