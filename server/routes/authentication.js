const path = require('path');

const express = require('express');

const discoveryController = require('../controllers/discovery');
const jwksController = require('../controllers/jwks');
const authorizeController = require('../controllers/authorize');
const loginController = require('../controllers/login');
const tokenController = require('../controllers/token');
const revokeController = require('../controllers/revoke');
const logoutController = require('../controllers/logout');
const userInfoController = require('../controllers/userinfo');

const router = express.Router();

router.get('/.well-known/openid-configuration', discoveryController.getOpenIDConfig);
router.get('/jwks.json', jwksController.getJwk);
router.get('/authorize', authorizeController.getAuthorize);
router.post('/login', loginController.postLogin);
router.post('/token', tokenController.postToken);
router.post('/revoke', revokeController.postRevoke);
router.get('/logout', logoutController.getLogout);
router.get('/userinfo', userInfoController.jwtAuthMiddleware, userInfoController.getUserInfo);

module.exports = router;
