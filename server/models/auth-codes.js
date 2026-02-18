const authCodes = new Map();

// Auth codes should expire after 10 minutes per OIDC spec
const CODE_EXPIRATION_MS = 10 * 60 * 1000;

module.exports = {
  set(code, data) {
    authCodes.set(code, {
      ...data,
      createdAt: Date.now()
    });
  },

  get(code) {
    const data = authCodes.get(code);
    if (!data) return null;

    // Check expiration
    const age = Date.now() - data.createdAt;
    if (age > CODE_EXPIRATION_MS) {
      authCodes.delete(code);
      return null;
    }

    return data;
  },

  delete(code) {
    authCodes.delete(code);
  },

  // Cleanup expired codes every 5 minutes
  startCleanup() {
    setInterval(() => {
      const now = Date.now();
      for (const [code, data] of authCodes.entries()) {
        if (now - data.createdAt > CODE_EXPIRATION_MS) {
          authCodes.delete(code);
        }
      }
    }, 5 * 60 * 1000);
  }
};
