
const path = require('path');

const express = require('express');
const session = require('express-session');

const SQLiteStore = require('connect-sqlite3')(session);

const app = express();

const authenticationRoutes = require('./routes/authentication');

const cors = require("cors"); 

app.use(cors({ origin: "*", credentials: false }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
// For parsing application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    dir: './data',        // you can choose any folder,
    ttl: 5 * 60 // 5 minutes
  }),
  secret: 'super-secret-session-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 10 * 60 * 60, // 10 mins
    sameSite: 'lax',
    secure: false           // set true if using HTTPS
  }
}));

app.use(authenticationRoutes);

app.listen(4000, () => {
  console.log('OIDC server running at http://localhost:4000');
});