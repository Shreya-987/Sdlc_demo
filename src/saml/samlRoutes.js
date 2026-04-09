'use strict';

const express = require('express');
const passport = require('passport');
const { createSamlStrategy, extractUserProfile, buildServiceProviderMetadata } = require('./samlService');
const { logAuthEvent } = require('../logging/authLogger');
const { syncUserProfile } = require('../profile/profileSyncService');

const router = express.Router();

/**
 * Register the SAML strategy with passport.
 * Must be called before using SAML routes.
 */
function initSamlRoutes() {
  const strategy = createSamlStrategy(async (profile, done) => {
    try {
      const user = extractUserProfile(profile);
      // Sync profile from IdP on every login
      const syncedUser = await syncUserProfile(user, 'saml');
      logAuthEvent('saml_login_success', {
        userId: user.id,
        email: user.email,
        provider: 'saml',
      });
      return done(null, syncedUser);
    } catch (err) {
      logAuthEvent('saml_login_error', { error: err.message });
      return done(err);
    }
  });

  passport.use('saml', strategy);
}

/**
 * GET /auth/saml
 * Initiates SSO by redirecting the user to the IdP.
 */
router.get(
  '/saml',
  (req, res, next) => {
    logAuthEvent('saml_login_initiated', {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });
    next();
  },
  passport.authenticate('saml', { failureRedirect: '/auth/error' })
);

/**
 * POST /auth/saml/callback
 * Assertion Consumer Service (ACS) endpoint.
 * The IdP POST the SAML response here after authentication.
 */
router.post(
  '/saml/callback',
  (req, res, next) => {
    passport.authenticate('saml', (err, user) => {
      if (err || !user) {
        logAuthEvent('saml_login_failed', {
          ip: req.ip,
          error: err ? err.message : 'No user returned',
        });
        return res.status(401).json({ error: 'Authentication failed', details: err ? err.message : 'Unknown error' });
      }
      req.logIn(user, (loginErr) => {
        if (loginErr) {
          return next(loginErr);
        }
        logAuthEvent('saml_session_created', {
          userId: user.id,
          email: user.email,
        });
        return res.json({ message: 'Authentication successful', user });
      });
    })(req, res, next);
  }
);

/**
 * GET /auth/saml/metadata
 * Returns the Service Provider metadata XML for IdP registration.
 */
router.get('/saml/metadata', (req, res) => {
  const xml = buildServiceProviderMetadata();
  res.set('Content-Type', 'application/xml');
  res.send(xml);
});

/**
 * POST /auth/saml/logout
 * Initiates SLO (Single Logout).
 */
router.post('/saml/logout', (req, res) => {
  if (req.user) {
    logAuthEvent('saml_logout', {
      userId: req.user.id,
      email: req.user.email,
    });
  }
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    req.session.destroy();
    res.json({ message: 'Logged out successfully' });
  });
});

module.exports = { router, initSamlRoutes };
