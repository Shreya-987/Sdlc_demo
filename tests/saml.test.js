'use strict';

const { buildSamlOptions, extractUserProfile, buildServiceProviderMetadata } = require('../src/saml/samlService');

describe('SUBTASK-1: SAML 2.0 Service', () => {
  describe('buildSamlOptions()', () => {
    it('returns default options when no env vars are set', () => {
      const opts = buildSamlOptions();
      expect(opts.issuer).toBeDefined();
      expect(opts.callbackUrl).toBeDefined();
      expect(opts.entryPoint).toBeDefined();
      expect(opts.signatureAlgorithm).toBe('sha256');
      expect(opts.digestAlgorithm).toBe('sha256');
    });

    it('allows option overrides', () => {
      const opts = buildSamlOptions({ issuer: 'urn:custom-sp' });
      expect(opts.issuer).toBe('urn:custom-sp');
    });

    it('picks up environment variables', () => {
      process.env.SAML_SP_ENTITY_ID = 'urn:env-test';
      const opts = buildSamlOptions();
      expect(opts.issuer).toBe('urn:env-test');
      delete process.env.SAML_SP_ENTITY_ID;
    });
  });

  describe('extractUserProfile()', () => {
    it('throws when profile is null', () => {
      expect(() => extractUserProfile(null)).toThrow('SAML profile is required');
    });

    it('extracts email from nameID', () => {
      const profile = { nameID: 'alice@example.com', attributes: {} };
      const user = extractUserProfile(profile);
      expect(user.email).toBe('alice@example.com');
      expect(user.provider).toBe('saml');
    });

    it('extracts first/last name from standard SAML attributes', () => {
      const profile = {
        nameID: 'alice@example.com',
        attributes: {
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': 'Alice',
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': 'Smith',
        },
      };
      const user = extractUserProfile(profile);
      expect(user.firstName).toBe('Alice');
      expect(user.lastName).toBe('Smith');
      expect(user.displayName).toBe('Alice Smith');
    });

    it('extracts first/last name from short-form attributes', () => {
      const profile = {
        nameID: 'bob@example.com',
        attributes: { firstName: 'Bob', lastName: 'Jones', groups: ['admins', 'users'] },
      };
      const user = extractUserProfile(profile);
      expect(user.firstName).toBe('Bob');
      expect(user.lastName).toBe('Jones');
      expect(user.groups).toEqual(['admins', 'users']);
    });

    it('wraps scalar group in an array', () => {
      const profile = {
        nameID: 'carol@example.com',
        attributes: { groups: 'everyone' },
      };
      const user = extractUserProfile(profile);
      expect(Array.isArray(user.groups)).toBe(true);
      expect(user.groups).toContain('everyone');
    });

    it('includes raw profile', () => {
      const profile = { nameID: 'dave@example.com', attributes: {} };
      const user = extractUserProfile(profile);
      expect(user.raw).toBe(profile);
    });
  });

  describe('buildServiceProviderMetadata()', () => {
    it('returns valid XML with entityID', () => {
      const xml = buildServiceProviderMetadata({ issuer: 'urn:test-sp', callbackUrl: 'https://sp.example.com/acs' });
      expect(xml).toContain('urn:test-sp');
      expect(xml).toContain('https://sp.example.com/acs');
      expect(xml).toContain('EntityDescriptor');
      expect(xml).toContain('SPSSODescriptor');
      expect(xml).toContain('AssertionConsumerService');
    });

    it('includes signature algorithm settings', () => {
      const xml = buildServiceProviderMetadata();
      expect(xml).toContain('AuthnRequestsSigned="true"');
    });
  });
});
