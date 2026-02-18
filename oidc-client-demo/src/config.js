// OIDC Configuration
const config = {
  issuer: 'http://localhost:4000',
  clientId: 'demo-client',
  clientSecret: 'supersecret', // Note: Should be in backend proxy for production
  redirectUri: 'http://localhost:3000/callback',
  postLogoutRedirectUri: 'http://localhost:3000',
  scopes: ['openid', 'profile', 'offline_access']
};

export default config;
