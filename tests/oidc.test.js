'use strict';

const {
  buildOidcConfig,
  extractUserProfile,
} = require('../src/oidc/oidcService');

describe('SUBTASK-2: OpenID Connect Service', () => {
  describe('buildOidcConfig()', () => {
    it('returns defaults when no env vars are set', () => {
      const config = buildOidcConfig();
      expect(config.clientId).toBeDefined();
      expect(config.redirectUri).toBeDefined();
      expect(Array.isArray(config.scopes)).toBe(true);
      expect(config.scopes).toContain('openid');
    });

    it('reads environment variables', () => {
      process.env.OIDC_CLIENT_ID = 'env-client-id';
      const config = buildOidcConfig();
      expect(config.clientId).toBe('env-client-id');
      delete process.env.OIDC_CLIENT_ID;
    });

    it('splits scopes into an array', () => {
      process.env.OIDC_SCOPES = 'openid profile email phone';
      const config = buildOidcConfig();
      expect(config.scopes).toEqual(['openid', 'profile', 'email', 'phone']);
      delete process.env.OIDC_SCOPES;
    });
  });

  describe('extractUserProfile()', () => {
    it('throws when claims are null', () => {
      expect(() => extractUserProfile(null)).toThrow('OIDC claims are required');
    });

    it('maps standard OIDC claims to internal profile', () => {
      const claims = {
        sub: 'oidc-user-123',
        email: 'alice@example.com',
        given_name: 'Alice',
        family_name: 'Smith',
        name: 'Alice Smith',
      };
      const user = extractUserProfile(claims);
      expect(user.id).toBe('oidc-user-123');
      expect(user.email).toBe('alice@example.com');
      expect(user.firstName).toBe('Alice');
      expect(user.lastName).toBe('Smith');
      expect(user.displayName).toBe('Alice Smith');
      expect(user.provider).toBe('oidc');
    });

    it('defaults displayName to email when name claim is absent', () => {
      const claims = { sub: 'u1', email: 'bob@example.com' };
      const user = extractUserProfile(claims);
      expect(user.displayName).toBe('bob@example.com');
    });

    it('defaults displayName to sub when email and name are absent', () => {
      const claims = { sub: 'u2' };
      const user = extractUserProfile(claims);
      expect(user.displayName).toBe('u2');
    });

    it('maps groups claim to array', () => {
      const claims = {
        sub: 'u3',
        email: 'carol@example.com',
        groups: ['admins', 'devs'],
      };
      const user = extractUserProfile(claims);
      expect(user.groups).toEqual(['admins', 'devs']);
    });

    it('defaults groups to empty array when claim is absent', () => {
      const claims = { sub: 'u4', email: 'dave@example.com' };
      const user = extractUserProfile(claims);
      expect(user.groups).toEqual([]);
    });

    it('preserves raw claims', () => {
      const claims = { sub: 'u5', email: 'eve@example.com', custom_claim: 'value' };
      const user = extractUserProfile(claims);
      expect(user.raw).toBe(claims);
    });
  });
});
