'use strict';

const { Issuer, generators } = require('openid-client');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { getLogger } = require('../logging/authLogger');

const logger = getLogger('oidc');

/**
 * OIDC Service – implements SUBTASK-2: Implement OpenID Connect authentication flow.
 *
 * Supports:
 *  - Authorization Code Flow (recommended)
 *  - PKCE (Proof Key for Code Exchange)
 *  - Token validation via JWKS endpoint
 *  - UserInfo retrieval
 */

/**
 * Build the OIDC client configuration from environment variables.
 * @returns {object} OIDC configuration.
 */
function buildOidcConfig() {
  return {
    issuerUrl:
      process.env.OIDC_ISSUER_URL ||
      'https://login.microsoftonline.com/common/v2.0',
    clientId: process.env.OIDC_CLIENT_ID || 'your-client-id',
    clientSecret: process.env.OIDC_CLIENT_SECRET || 'your-client-secret',
    redirectUri:
      process.env.OIDC_REDIRECT_URI || 'http://localhost:3000/auth/oidc/callback',
    scopes: (process.env.OIDC_SCOPES || 'openid profile email').split(' '),
    postLogoutRedirectUri:
      process.env.OIDC_POST_LOGOUT_URI || 'http://localhost:3000',
  };
}

/**
 * Discover and return an OIDC Issuer instance.
 * @param {string} [issuerUrl] - Override issuer URL.
 * @returns {Promise<Issuer>} OIDC Issuer.
 */
async function discoverIssuer(issuerUrl) {
  const url = issuerUrl || buildOidcConfig().issuerUrl;
  logger.info('Discovering OIDC issuer', { url });
  try {
    const issuer = await Issuer.discover(url);
    logger.info('OIDC issuer discovered', { issuer: issuer.metadata.issuer });
    return issuer;
  } catch (err) {
    logger.error('Failed to discover OIDC issuer', { url, error: err.message });
    throw err;
  }
}

/**
 * Build an openid-client Client from the discovered issuer.
 * @param {Issuer} issuer - Discovered OIDC Issuer.
 * @param {object} [configOverrides] - Optional config overrides.
 * @returns {Client} openid-client Client instance.
 */
function buildOidcClient(issuer, configOverrides = {}) {
  const config = { ...buildOidcConfig(), ...configOverrides };
  const client = new issuer.Client({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uris: [config.redirectUri],
    post_logout_redirect_uris: [config.postLogoutRedirectUri],
    response_types: ['code'],
  });
  logger.info('OIDC client created', {
    clientId: config.clientId,
    redirectUri: config.redirectUri,
  });
  return client;
}

/**
 * Generate an authorization URL with PKCE state & nonce.
 * @param {Client} client - openid-client Client.
 * @param {object} [configOverrides] - Config overrides.
 * @returns {{ url: string, codeVerifier: string, state: string, nonce: string }}
 */
function generateAuthorizationUrl(client, configOverrides = {}) {
  const config = { ...buildOidcConfig(), ...configOverrides };
  const codeVerifier = generators.codeVerifier();
  const codeChallenge = generators.codeChallenge(codeVerifier);
  const state = generators.state();
  const nonce = generators.nonce();

  const url = client.authorizationUrl({
    scope: config.scopes.join(' '),
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  logger.debug('Generated authorization URL', { state });
  return { url, codeVerifier, state, nonce };
}

/**
 * Exchange authorization code for tokens.
 * @param {Client} client - openid-client Client.
 * @param {object} callbackParams - Parameters from the redirect callback.
 * @param {object} checks - State/nonce/codeVerifier for validation.
 * @returns {Promise<TokenSet>} Token set containing id_token, access_token, etc.
 */
async function exchangeAuthorizationCode(client, callbackParams, checks) {
  logger.info('Exchanging authorization code for tokens');
  try {
    const config = buildOidcConfig();
    const tokenSet = await client.callback(config.redirectUri, callbackParams, checks);
    logger.info('Token exchange successful', {
      expiresAt: tokenSet.expires_at,
      scope: tokenSet.scope,
    });
    return tokenSet;
  } catch (err) {
    logger.error('Token exchange failed', { error: err.message });
    throw err;
  }
}

/**
 * Validate a JWT ID token using the issuer's JWKS endpoint.
 * @param {string} idToken - The raw JWT ID token.
 * @param {string} jwksUri - The JWKS URI from the issuer metadata.
 * @param {object} [options] - jwt.verify options overrides.
 * @returns {Promise<object>} Decoded JWT payload.
 */
async function validateIdToken(idToken, jwksUri, options = {}) {
  logger.debug('Validating ID token');
  return new Promise((resolve, reject) => {
    const client = jwksClient({ jwksUri, cache: true, rateLimit: true });

    function getKey(header, callback) {
      client.getSigningKey(header.kid, (err, key) => {
        if (err) {
          return callback(err);
        }
        const signingKey = key.getPublicKey();
        callback(null, signingKey);
      });
    }

    const verifyOptions = {
      algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
      ...options,
    };

    jwt.verify(idToken, getKey, verifyOptions, (err, decoded) => {
      if (err) {
        logger.warn('ID token validation failed', { error: err.message });
        return reject(err);
      }
      logger.debug('ID token validated successfully', { sub: decoded.sub });
      resolve(decoded);
    });
  });
}

/**
 * Fetch user info from the OIDC userinfo endpoint.
 * @param {Client} client - openid-client Client.
 * @param {string} accessToken - OAuth2 access token.
 * @returns {Promise<object>} User info claims.
 */
async function fetchUserInfo(client, accessToken) {
  logger.info('Fetching user info from OIDC userinfo endpoint');
  try {
    const userinfo = await client.userinfo(accessToken);
    logger.debug('User info fetched', { sub: userinfo.sub });
    return userinfo;
  } catch (err) {
    logger.error('Failed to fetch user info', { error: err.message });
    throw err;
  }
}

/**
 * Normalise OIDC user info claims into a standard internal profile.
 * @param {object} claims - OIDC claims (from ID token or userinfo).
 * @returns {object} Normalised user profile.
 */
function extractUserProfile(claims) {
  if (!claims) {
    throw new Error('OIDC claims are required');
  }
  return {
    id: claims.sub,
    email: claims.email,
    firstName: claims.given_name || null,
    lastName: claims.family_name || null,
    displayName: claims.name || claims.email || claims.sub,
    groups: Array.isArray(claims.groups) ? claims.groups : [],
    roles: Array.isArray(claims.roles) ? claims.roles : [],
    provider: 'oidc',
    raw: claims,
  };
}

module.exports = {
  buildOidcConfig,
  discoverIssuer,
  buildOidcClient,
  generateAuthorizationUrl,
  exchangeAuthorizationCode,
  validateIdToken,
  fetchUserInfo,
  extractUserProfile,
};
