'use strict';

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const rateLimit = require('express-rate-limit');
const { doubleCsrf } = require('csrf-csrf');
const { router: samlRouter, initSamlRoutes } = require('./saml/samlRoutes');
const { router: oidcRouter } = require('./oidc/oidcRoutes');
const { router: profileRouter } = require('./profile/profileRoutes');
const { router: authEventRouter } = require('./logging/authEventRoutes');
const { schedulePeriodicSync } = require('./profile/profileSyncService');
const { getLogger, logAuthEvent, AUTH_EVENT_TYPES } = require('./logging/authLogger');

const logger = getLogger('app');

/**
 * Build and configure the Express application.
 * Exported as a factory so it can be reused in tests.
 * @returns {express.Application}
 */
function createApp() {
  const app = express();

  // ── Body parsing ─────────────────────────────────────────────────────────
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  // ── Session ───────────────────────────────────────────────────────────────
  app.use(
    session({
      secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 8 * 60 * 60 * 1000, // 8 hours
      },
    })
  );

  // ── CSRF protection ───────────────────────────────────────────────────────
  // The SAML ACS endpoint (/auth/saml/callback) is a cross-origin POST from
  // the IdP, so it must be exempted from CSRF checks.
  const { generateToken, doubleCsrfProtection } = doubleCsrf({
    getSecret: () => process.env.CSRF_SECRET || 'csrf-secret-change-in-production',
    cookieName: '__Host-enterprise-sso.x-csrf-token',
    cookieOptions: {
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      httpOnly: true,
    },
    size: 64,
    ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  });

  // Apply CSRF protection to all routes except the IdP callback endpoints
  app.use((req, res, next) => {
    const samlCallback = req.path === '/auth/saml/callback' && req.method === 'POST';
    if (samlCallback) {
      return next();
    }
    return doubleCsrfProtection(req, res, next);
  });

  // Endpoint to retrieve a fresh CSRF token (for SPA / form rendering)
  app.get('/auth/csrf-token', (req, res) => {
    res.json({ csrfToken: generateToken(req, res) });
  });

  // ── Rate limiting on authentication endpoints ─────────────────────────────
  const authRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many authentication attempts. Please try again later.' },
  });

  // ── Passport ──────────────────────────────────────────────────────────────
  app.use(passport.initialize());
  app.use(passport.session());

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => {
    const { getUserById } = require('./profile/profileSyncService');
    const user = getUserById(id);
    done(null, user || false);
  });

  // Initialise SAML strategy
  initSamlRoutes();

  // ── Routes ────────────────────────────────────────────────────────────────
  app.use('/auth', authRateLimiter, samlRouter);
  app.use('/auth', authRateLimiter, oidcRouter);
  app.use('/api/users', profileRouter);
  app.use('/api/auth-events', authEventRouter);

  // Health check
  app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // 401 handler for unauthenticated requests to protected routes
  app.use('/auth/error', (req, res) => {
    logAuthEvent(AUTH_EVENT_TYPES.UNAUTHORIZED_ACCESS, { path: req.path });
    res.status(401).json({ error: 'Authentication required' });
  });

  // ── Global error handler ──────────────────────────────────────────────────
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    logger.error('Unhandled error', { error: err.message, stack: err.stack });
    res.status(err.status || 500).json({
      error: err.message || 'Internal server error',
    });
  });

  return app;
}

/**
 * Start the HTTP server.
 */
function startServer() {
  const app = createApp();
  const PORT = process.env.PORT || 3000;

  const server = app.listen(PORT, () => {
    logger.info(`Enterprise SSO server listening on port ${PORT}`);

    // Start background profile sync job (hourly by default)
    if (process.env.NODE_ENV !== 'test') {
      const cronExpr = process.env.SYNC_CRON || '0 * * * *';
      schedulePeriodicSync(cronExpr);
      logger.info('Background profile sync scheduled', { cronExpr });
    }
  });

  return server;
}

// Only start the server when this file is executed directly
if (require.main === module) {
  startServer();
}

module.exports = { createApp, startServer };
