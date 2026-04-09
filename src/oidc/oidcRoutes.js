'use strict';

const express = require('express');
const {
  buildOidcConfig,
  discoverIssuer,
  buildOidcClient,
  generateAuthorizationUrl,
  exchangeAuthorizationCode,
  fetchUserInfo,
  extractUserProfile,
} = require('./oidcService');
const { logAuthEvent, getLogger } = require('../logging/authLogger');
const { syncUserProfile } = require('../profile/profileSyncService');

const router = express.Router();
const logger = getLogger('oidc-routes');

// In-memory client cache – initialised on first request
let oidcClient = null;

/**
 * Lazy-initialise the OIDC client by discovering the issuer metadata.
 * Caches the client instance for subsequent requests.
 * @returns {Promise<Client>}
 */
async function getOidcClient() {
  if (!oidcClient) {
    const issuer = await discoverIssuer();
    oidcClient = buildOidcClient(issuer);
  }
  return oidcClient;
}

/**
 * GET /auth/oidc
 * Redirect the user to the OIDC identity provider login page.
 */
router.get('/oidc', async (req, res) => {
  try {
    const client = await getOidcClient();
    const { url, codeVerifier, state, nonce } = generateAuthorizationUrl(client);

    // Persist PKCE verifier, state, and nonce in the session for callback validation
    req.session.oidcState = state;
    req.session.oidcNonce = nonce;
    req.session.oidcCodeVerifier = codeVerifier;

    logAuthEvent('oidc_login_initiated', {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      state,
    });

    res.redirect(url);
  } catch (err) {
    logger.error('Failed to initiate OIDC login', { error: err.message });
    res.status(500).json({ error: 'Failed to initiate authentication', details: err.message });
  }
});

/**
 * GET /auth/oidc/callback
 * Handles the redirect back from the identity provider.
 * Exchanges the authorization code for tokens and creates a session.
 */
router.get('/oidc/callback', async (req, res) => {
  try {
    const client = await getOidcClient();

    const checks = {
      state: req.session.oidcState,
      nonce: req.session.oidcNonce,
      code_verifier: req.session.oidcCodeVerifier,
    };

    const tokenSet = await exchangeAuthorizationCode(client, req.query, checks);
    const claims = tokenSet.claims();

    // Optionally fetch additional claims from the userinfo endpoint
    let userinfoClaims = {};
    try {
      userinfoClaims = await fetchUserInfo(client, tokenSet.access_token);
    } catch (uiErr) {
      logger.warn('UserInfo fetch failed, falling back to ID token claims', {
        error: uiErr.message,
      });
    }

    const mergedClaims = { ...claims, ...userinfoClaims };
    const user = extractUserProfile(mergedClaims);

    // Synchronise profile attributes with the local user store
    const syncedUser = await syncUserProfile(user, 'oidc');

    // Store token refresh info in session
    req.session.oidcTokens = {
      accessToken: tokenSet.access_token,
      refreshToken: tokenSet.refresh_token,
      expiresAt: tokenSet.expires_at,
    };

    logAuthEvent('oidc_login_success', {
      userId: user.id,
      email: user.email,
      provider: 'oidc',
    });

    req.logIn(syncedUser, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Session creation failed' });
      }
      logAuthEvent('oidc_session_created', {
        userId: user.id,
        email: user.email,
      });
      res.json({ message: 'Authentication successful', user: syncedUser });
    });
  } catch (err) {
    logAuthEvent('oidc_login_failed', {
      ip: req.ip,
      error: err.message,
    });
    logger.error('OIDC callback error', { error: err.message });
    res.status(401).json({ error: 'Authentication failed', details: err.message });
  }
});

/**
 * POST /auth/oidc/logout
 * Ends the session and optionally redirects to the IdP end-session endpoint.
 */
router.post('/oidc/logout', async (req, res) => {
  if (req.user) {
    logAuthEvent('oidc_logout', {
      userId: req.user.id,
      email: req.user.email,
    });
  }
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    req.session.destroy();

    // Redirect to IdP end-session endpoint if configured
    const config = buildOidcConfig();
    if (process.env.OIDC_END_SESSION_ENDPOINT) {
      const endSessionUrl = new URL(process.env.OIDC_END_SESSION_ENDPOINT);
      endSessionUrl.searchParams.set('post_logout_redirect_uri', config.postLogoutRedirectUri);
      return res.json({ message: 'Logged out', endSessionUrl: endSessionUrl.toString() });
    }

    res.json({ message: 'Logged out successfully' });
  });
});

/**
 * POST /auth/oidc/token/refresh
 * Refresh an expiring access token using the refresh token.
 */
router.post('/oidc/token/refresh', async (req, res) => {
  try {
    if (!req.session.oidcTokens || !req.session.oidcTokens.refreshToken) {
      return res.status(400).json({ error: 'No refresh token available' });
    }
    const client = await getOidcClient();
    const tokenSet = await client.refresh(req.session.oidcTokens.refreshToken);

    req.session.oidcTokens = {
      accessToken: tokenSet.access_token,
      refreshToken: tokenSet.refresh_token || req.session.oidcTokens.refreshToken,
      expiresAt: tokenSet.expires_at,
    };

    logAuthEvent('oidc_token_refreshed', { userId: req.user && req.user.id });
    res.json({ message: 'Token refreshed', expiresAt: tokenSet.expires_at });
  } catch (err) {
    logger.error('Token refresh failed', { error: err.message });
    res.status(401).json({ error: 'Token refresh failed', details: err.message });
  }
});

module.exports = { router };
