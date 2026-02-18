const fs = require('fs');
const path = require('path');

// Load predefined-users.json from one directory up
const predefineds = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'data', 'predefined-users.json'), 'utf8')
);

class PredefinedUser {
  constructor(data) {
    this.label = data.label;
    this.sub = data.sub;
    this.password = data.password;
    this.claims = data.claims || {};
  }

  /**
   * Get all predefined users for a client
   */
  static getForClient(clientId) {
    const list = predefineds[clientId] || [];
    return list.map(u => new PredefinedUser(u));
  }

  /**
   * Authenticate a predefined user for a specific client
   */
  static authenticate(clientId, sub, password) {
    const list = predefineds[clientId] || [];
    const data = list.find(u => u.sub === sub && u.password === password);
    return data ? new PredefinedUser(data) : null;
  }

  /**
   * Find a predefined user by sub (useful for session lookups)
   */
  static findBySub(clientId, sub) {
    const list = predefineds[clientId] || [];
    const data = list.find(u => u.sub === sub);
    return data ? new PredefinedUser(data) : null;
  }
}

module.exports = PredefinedUser;
