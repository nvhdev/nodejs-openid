const fs = require('fs');
const path = require('path');

// Load JSON from one directory up
const clients = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'data', 'clients.json'), 'utf8')
);

class Client {
  constructor(data) {
    this.client_id = data.client_id;
    this.client_secret = data.client_secret;
    this.redirect_uris = data.redirect_uris || [];
    this.allowed_claim_fields = data.allowed_claim_fields || [];
  }

  // Find a client by ID
  static findById(clientId) {
    const data = clients.find(c => c.client_id === clientId);
    return data ? new Client(data) : null;
  }

  // Validate redirect_uri
  isRedirectUriAllowed(uri) {
    return this.redirect_uris.includes(uri);
  }

  // Validate claim fields
  isClaimAllowed(field) {
    return this.allowed_claim_fields.includes(field);
  }
}

module.exports = Client;
