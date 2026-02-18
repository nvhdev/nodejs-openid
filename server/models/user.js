const fs = require('fs');
const path = require('path');

// Load users.json from one directory up
const users = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'data', 'users.json'), 'utf8')
);

class User {
  constructor(data) {
    this.sub = data.sub;
    this.password = data.password;
    this.email = data.email;
    this.name = data.name;
    this.role = data.role;
  }

  // Find user by sub + password
  static authenticate(sub, password) {
    const data = users.find(u => u.sub === sub && u.password === password);
    return data ? new User(data) : null;
  }

  // Find user by sub only (useful for sessions)
  static findBySub(sub) {
    const data = users.find(u => u.sub === sub);
    return data ? new User(data) : null;
  }
}

module.exports = User;
