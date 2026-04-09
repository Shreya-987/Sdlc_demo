'use strict';

const {
  logAuthEvent,
  getAuthEvents,
  clearAuthEvents,
  getAuthStats,
  AUTH_EVENT_TYPES,
} = require('../src/logging/authLogger');

beforeEach(() => {
  clearAuthEvents();
});

describe('SUBTASK-4: Authentication Logging and Monitoring', () => {
  describe('AUTH_EVENT_TYPES', () => {
    it('defines SAML event types', () => {
      expect(AUTH_EVENT_TYPES.SAML_LOGIN_SUCCESS).toBe('saml_login_success');
      expect(AUTH_EVENT_TYPES.SAML_LOGIN_FAILED).toBe('saml_login_failed');
      expect(AUTH_EVENT_TYPES.SAML_LOGOUT).toBe('saml_logout');
    });

    it('defines OIDC event types', () => {
      expect(AUTH_EVENT_TYPES.OIDC_LOGIN_SUCCESS).toBe('oidc_login_success');
      expect(AUTH_EVENT_TYPES.OIDC_LOGIN_FAILED).toBe('oidc_login_failed');
      expect(AUTH_EVENT_TYPES.OIDC_LOGOUT).toBe('oidc_logout');
      expect(AUTH_EVENT_TYPES.OIDC_TOKEN_REFRESHED).toBe('oidc_token_refreshed');
    });

    it('defines profile sync event types', () => {
      expect(AUTH_EVENT_TYPES.PROFILE_SYNC_STARTED).toBe('profile_sync_started');
      expect(AUTH_EVENT_TYPES.PROFILE_SYNC_SUCCESS).toBe('profile_sync_success');
      expect(AUTH_EVENT_TYPES.PROFILE_SYNC_FAILED).toBe('profile_sync_failed');
    });
  });

  describe('logAuthEvent()', () => {
    it('records an event with a unique ID and timestamp', () => {
      const event = logAuthEvent('saml_login_success', { userId: 'u1', email: 'a@b.com' });
      expect(event.eventId).toBeDefined();
      expect(event.eventType).toBe('saml_login_success');
      expect(event.timestamp).toBeDefined();
      expect(event.userId).toBe('u1');
    });

    it('each event gets a unique ID', () => {
      const e1 = logAuthEvent('saml_login_initiated');
      const e2 = logAuthEvent('saml_login_initiated');
      expect(e1.eventId).not.toBe(e2.eventId);
    });

    it('stores events retrievable via getAuthEvents', () => {
      logAuthEvent('oidc_login_success', { userId: 'u2' });
      const events = getAuthEvents();
      expect(events).toHaveLength(1);
      expect(events[0].eventType).toBe('oidc_login_success');
    });
  });

  describe('getAuthEvents()', () => {
    beforeEach(() => {
      logAuthEvent('saml_login_success', { userId: 'u1', email: 'alice@example.com' });
      logAuthEvent('saml_login_failed', { userId: 'u2', email: 'bob@example.com' });
      logAuthEvent('oidc_login_success', { userId: 'u1', email: 'alice@example.com' });
    });

    it('returns all events when no filter is applied', () => {
      expect(getAuthEvents()).toHaveLength(3);
    });

    it('filters by eventType', () => {
      const events = getAuthEvents({ eventType: 'saml_login_success' });
      expect(events).toHaveLength(1);
      expect(events[0].eventType).toBe('saml_login_success');
    });

    it('filters by userId', () => {
      const events = getAuthEvents({ userId: 'u1' });
      expect(events).toHaveLength(2);
    });

    it('filters by email', () => {
      const events = getAuthEvents({ email: 'bob@example.com' });
      expect(events).toHaveLength(1);
      expect(events[0].userId).toBe('u2');
    });

    it('filters by since timestamp', () => {
      const future = new Date(Date.now() + 60000).toISOString();
      const events = getAuthEvents({ since: future });
      expect(events).toHaveLength(0);
    });
  });

  describe('getAuthStats()', () => {
    it('reports zero stats on empty store', () => {
      const stats = getAuthStats();
      expect(stats.total).toBe(0);
      expect(stats.failures).toBe(0);
      expect(stats.successRate).toBe(100);
    });

    it('counts total and failure events', () => {
      logAuthEvent('saml_login_success');
      logAuthEvent('saml_login_success');
      logAuthEvent('saml_login_failed');
      const stats = getAuthStats();
      expect(stats.total).toBe(3);
      expect(stats.failures).toBe(1);
    });

    it('calculates success rate correctly', () => {
      logAuthEvent('saml_login_success');
      logAuthEvent('saml_login_failed');
      const stats = getAuthStats();
      expect(stats.successRate).toBeCloseTo(50);
    });

    it('breaks down events by type', () => {
      logAuthEvent('saml_login_success');
      logAuthEvent('oidc_login_success');
      logAuthEvent('saml_login_success');
      const stats = getAuthStats();
      expect(stats.byType['saml_login_success']).toBe(2);
      expect(stats.byType['oidc_login_success']).toBe(1);
    });
  });

  describe('clearAuthEvents()', () => {
    it('empties the event store', () => {
      logAuthEvent('saml_login_success');
      logAuthEvent('saml_login_failed');
      clearAuthEvents();
      expect(getAuthEvents()).toHaveLength(0);
    });
  });
});
