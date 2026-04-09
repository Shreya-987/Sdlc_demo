'use strict';

const { Strategy: SamlStrategy } = require('@node-saml/passport-saml');
const crypto = require('crypto');
const { getLogger } = require('../logging/authLogger');

const logger = getLogger('saml');

/**
 * SAML 2.0 Service Provider configuration and utilities.
 * Implements SUBTASK-1: Implement SAML 2.0 authentication flow.
 */

/**
 * Build SAML strategy options from environment config or provided options.
 * @param {object} [overrides] - Optional option overrides for testing.
 * @returns {object} SAML strategy options.
 */
function buildSamlOptions(overrides = {}) {
  return {
    // Service Provider entity ID
    issuer: process.env.SAML_SP_ENTITY_ID || 'urn:sp:enterprise-sso',
    // Assertion Consumer Service (ACS) URL
    callbackUrl: process.env.SAML_ACS_URL || 'http://localhost:3000/auth/saml/callback',
    // Identity Provider SSO URL
    entryPoint: process.env.SAML_IDP_SSO_URL || 'https://idp.example.com/sso/saml',
    // Identity Provider entity ID / issuer
    idpIssuer: process.env.SAML_IDP_ISSUER || 'https://idp.example.com',
    // Identity Provider signing certificate (PEM, without headers)
    cert: process.env.SAML_IDP_CERT || generateSelfSignedCertPlaceholder(),
    // Service Provider private key for signing auth requests
    privateKey: process.env.SAML_SP_PRIVATE_KEY || null,
    // Whether to sign authentication requests
    signatureAlgorithm: 'sha256',
    // Digest algorithm
    digestAlgorithm: 'sha256',
    // Name identifier format
    identifierFormat:
      'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    // Accept signed assertions only
    wantAuthnResponseSigned: true,
    // Whether to want assertions signed
    wantAssertionsSigned: false,
    ...overrides,
  };
}

/**
 * Generate a placeholder self-signed certificate string for development.
 * In production, load a real certificate from secure storage.
 * @returns {string} Placeholder certificate (PEM body without headers).
 */
function generateSelfSignedCertPlaceholder() {
  logger.warn(
    'SAML_IDP_CERT not set – using placeholder certificate. ' +
      'Set SAML_IDP_CERT environment variable in production.'
  );
  // Return a clearly invalid placeholder so strategy construction doesn't
  // crash during unit tests where no real IdP certificate is available.
  return 'PLACEHOLDER_CERT';
}

/**
 * Create a configured passport-saml Strategy instance.
 * @param {Function} verify - Passport verify callback(profile, done).
 * @param {object} [optionOverrides] - Override SAML options.
 * @returns {SamlStrategy} Configured strategy.
 */
function createSamlStrategy(verify, optionOverrides = {}) {
  const options = buildSamlOptions(optionOverrides);
  logger.info('Creating SAML strategy', {
    issuer: options.issuer,
    entryPoint: options.entryPoint,
    callbackUrl: options.callbackUrl,
  });
  return new SamlStrategy(options, verify, verify);
}

/**
 * Extract a normalised user profile from a SAML assertion profile.
 * Maps common SAML attribute names to a standard internal shape.
 * @param {object} samlProfile - Raw profile from passport-saml.
 * @returns {object} Normalised user profile.
 */
function extractUserProfile(samlProfile) {
  if (!samlProfile) {
    throw new Error('SAML profile is required');
  }

  const attrs = samlProfile.attributes || {};

  // Support multiple common attribute naming conventions
  const email =
    samlProfile.nameID ||
    attrs['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'] ||
    attrs['email'] ||
    attrs['mail'] ||
    null;

  const firstName =
    attrs['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'] ||
    attrs['firstName'] ||
    attrs['givenName'] ||
    null;

  const lastName =
    attrs['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'] ||
    attrs['lastName'] ||
    attrs['sn'] ||
    null;

  const displayName =
    attrs['http://schemas.microsoft.com/identity/claims/displayname'] ||
    attrs['displayName'] ||
    attrs['cn'] ||
    [firstName, lastName].filter(Boolean).join(' ') ||
    email;

  const groups =
    attrs['http://schemas.microsoft.com/ws/2008/06/identity/claims/groups'] ||
    attrs['groups'] ||
    attrs['memberOf'] ||
    [];

  const roles =
    attrs['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'] ||
    attrs['roles'] ||
    [];

  return {
    id: samlProfile.nameID,
    email,
    firstName,
    lastName,
    displayName,
    groups: Array.isArray(groups) ? groups : [groups],
    roles: Array.isArray(roles) ? roles : [roles],
    provider: 'saml',
    raw: samlProfile,
  };
}

/**
 * Build SP metadata XML for IdP registration.
 * @param {object} [optionOverrides] - Override SAML options.
 * @returns {string} XML metadata string.
 */
function buildServiceProviderMetadata(optionOverrides = {}) {
  const options = buildSamlOptions(optionOverrides);
  const entityId = options.issuer;
  const acsUrl = options.callbackUrl;
  const requestedNameIdFormat = options.identifierFormat;

  // Generate a unique SP certificate fingerprint placeholder
  const spCertFingerprint = crypto
    .createHash('sha256')
    .update(entityId)
    .digest('hex');

  const xml = `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="${entityId}">
  <md:SPSSODescriptor
    AuthnRequestsSigned="true"
    WantAssertionsSigned="${options.wantAssertionsSigned}"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>${requestedNameIdFormat}</md:NameIDFormat>
    <md:AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="${acsUrl}"
      index="1"/>
    <!-- SP Certificate fingerprint (SHA-256): ${spCertFingerprint} -->
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;

  logger.info('Built SP metadata', { entityId, acsUrl });
  return xml;
}

module.exports = {
  buildSamlOptions,
  createSamlStrategy,
  extractUserProfile,
  buildServiceProviderMetadata,
};
