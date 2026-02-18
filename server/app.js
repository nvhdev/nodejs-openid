
const path = require('path');
require('dotenv').config();

const express = require('express');
const session = require('express-session');

const SQLiteStore = require('connect-sqlite3')(session);

const app = express();

const authenticationRoutes = require('./routes/authentication');
const AuthCodes = require('./models/auth-codes');
const RefreshTokens = require('./models/refresh-tokens');

// Start auth code cleanup job
AuthCodes.startCleanup();

// Start refresh token cleanup job
RefreshTokens.startCleanup();

const cors = require("cors"); 

app.use(cors({ 
  origin: ["http://localhost:3000"],
  credentials: true 
}));

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path} - Client: ${req.ip}`);
  next();
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
// For parsing application/json
app.use(express.json());
// For parsing application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    dir: './data',
    ttl: 10 * 60 * 60 // 10 hours (match cookie maxAge)
  }),
  secret: process.env.SESSION_SECRET || 'super-secret-session-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 10 * 60 * 60, // 10 mins
    sameSite: 'lax',
    secure: false           // set true if using HTTPS
  }
}));

app.use(authenticationRoutes);

// Global error handler
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${err.stack}`);
  res.status(500).json({ 
    error: 'server_error',
    error_description: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`OIDC server running at http://localhost:${PORT}`);
});
