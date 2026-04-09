'use strict';

const {
  transformProfile,
  mergeUser,
  syncUserProfile,
  getUserById,
  listUsers,
  deleteUser,
  clearUserStore,
} = require('../src/profile/profileSyncService');

beforeEach(() => {
  clearUserStore();
});

describe('SUBTASK-3: User Profile Synchronization Service', () => {
  describe('transformProfile()', () => {
    it('maps SAML profile attributes to canonical user', () => {
      const samlProfile = {
        id: 'alice@example.com',
        email: 'alice@example.com',
        firstName: 'Alice',
        lastName: 'Smith',
        groups: ['admins'],
      };
      const user = transformProfile(samlProfile, 'saml');
      expect(user.email).toBe('alice@example.com');
      expect(user.firstName).toBe('Alice');
      expect(user.lastName).toBe('Smith');
      expect(user.groups).toEqual(['admins']);
      expect(user.provider).toBe('saml');
    });

    it('maps OIDC claims to canonical user', () => {
      const oidcProfile = {
        id: 'sub-123',
        email: 'bob@example.com',
        given_name: 'Bob',
        family_name: 'Jones',
        groups: ['users'],
      };
      const user = transformProfile(oidcProfile, 'oidc');
      expect(user.id).toBe('bob@example.com');
      expect(user.firstName).toBe('Bob');
      expect(user.provider).toBe('oidc');
    });

    it('derives displayName from firstName + lastName', () => {
      const profile = { id: 'carol@example.com', email: 'carol@example.com', firstName: 'Carol', lastName: 'White' };
      const user = transformProfile(profile, 'saml');
      expect(user.displayName).toBe('Carol White');
    });

    it('falls back to email for displayName', () => {
      const profile = { id: 'dave@example.com', email: 'dave@example.com' };
      const user = transformProfile(profile, 'oidc');
      expect(user.displayName).toBe('dave@example.com');
    });

    it('normalises group strings to array', () => {
      const profile = { id: 'eve@example.com', email: 'eve@example.com', groups: 'everyone' };
      const user = transformProfile(profile, 'saml');
      expect(Array.isArray(user.groups)).toBe(true);
    });

    it('trims whitespace from string attributes', () => {
      const profile = { id: 'f@example.com', email: 'f@example.com', firstName: '  Frank  ' };
      const user = transformProfile(profile, 'saml');
      expect(user.firstName).toBe('Frank');
    });
  });

  describe('mergeUser()', () => {
    it('preserves createdAt from existing record', () => {
      const existing = { id: 'u1', createdAt: '2024-01-01T00:00:00.000Z', localRoles: ['admin'], loginCount: 5 };
      const incoming = { id: 'u1', createdAt: '2025-01-01T00:00:00.000Z', roles: ['viewer'] };
      const merged = mergeUser(existing, incoming);
      expect(merged.createdAt).toBe('2024-01-01T00:00:00.000Z');
    });

    it('increments loginCount', () => {
      const existing = { id: 'u1', loginCount: 3, localRoles: [] };
      const incoming = { id: 'u1', roles: [] };
      const merged = mergeUser(existing, incoming);
      expect(merged.loginCount).toBe(4);
    });

    it('merges local and provider roles without duplicates', () => {
      const existing = { id: 'u1', loginCount: 1, localRoles: ['admin', 'viewer'] };
      const incoming = { id: 'u1', roles: ['viewer', 'editor'] };
      const merged = mergeUser(existing, incoming);
      expect(merged.roles).toContain('admin');
      expect(merged.roles).toContain('viewer');
      expect(merged.roles).toContain('editor');
      // No duplicates
      const viewerCount = merged.roles.filter((r) => r === 'viewer').length;
      expect(viewerCount).toBe(1);
    });
  });

  describe('syncUserProfile()', () => {
    it('creates a new user on first sync', async () => {
      const profile = { id: 'alice@example.com', email: 'alice@example.com', firstName: 'Alice' };
      const user = await syncUserProfile(profile, 'saml');
      expect(user.email).toBe('alice@example.com');
      expect(user.loginCount).toBe(1);
    });

    it('updates an existing user on subsequent sync', async () => {
      const profile = { id: 'bob@example.com', email: 'bob@example.com', firstName: 'Bob' };
      await syncUserProfile(profile, 'saml');
      const updatedProfile = { ...profile, firstName: 'Robert' };
      const user = await syncUserProfile(updatedProfile, 'saml');
      expect(user.firstName).toBe('Robert');
      expect(user.loginCount).toBe(2);
    });

    it('persists user to the store', async () => {
      const profile = { id: 'carol@example.com', email: 'carol@example.com' };
      await syncUserProfile(profile, 'oidc');
      const stored = getUserById('carol@example.com');
      expect(stored).not.toBeNull();
    });
  });

  describe('listUsers()', () => {
    it('returns empty list when store is empty', () => {
      const result = listUsers();
      expect(result.totalResults).toBe(0);
      expect(result.resources).toHaveLength(0);
    });

    it('lists all created users', async () => {
      await syncUserProfile({ id: 'a@example.com', email: 'a@example.com' }, 'saml');
      await syncUserProfile({ id: 'b@example.com', email: 'b@example.com' }, 'oidc');
      const result = listUsers();
      expect(result.totalResults).toBe(2);
    });

    it('supports pagination', async () => {
      for (let i = 0; i < 5; i++) {
        await syncUserProfile({ id: `u${i}@example.com`, email: `u${i}@example.com` }, 'saml');
      }
      const page1 = listUsers({ startIndex: 1, count: 3 });
      expect(page1.itemsPerPage).toBe(3);
      const page2 = listUsers({ startIndex: 4, count: 3 });
      expect(page2.itemsPerPage).toBe(2);
    });
  });

  describe('deleteUser()', () => {
    it('removes the user from the store', async () => {
      await syncUserProfile({ id: 'temp@example.com', email: 'temp@example.com' }, 'saml');
      const deleted = deleteUser('temp@example.com');
      expect(deleted).toBe(true);
      expect(getUserById('temp@example.com')).toBeNull();
    });

    it('returns false for non-existent user', () => {
      expect(deleteUser('noone@example.com')).toBe(false);
    });
  });
});
