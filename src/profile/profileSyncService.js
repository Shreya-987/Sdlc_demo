'use strict';

const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');
const { getLogger, logAuthEvent, AUTH_EVENT_TYPES } = require('../logging/authLogger');

const logger = getLogger('profile-sync');

/**
 * User Profile Synchronization Service
 * SUBTASK-3: Build user profile synchronization service.
 *
 * Responsibilities:
 *  - Map identity-provider attributes to a canonical internal user schema
 *  - Transform and normalise attribute values
 *  - Persist / update user records in the local user store
 *  - Run periodic background synchronisation jobs (SCIM-inspired)
 */

/**
 * In-memory user store used as a stand-in for a real database.
 * In production, replace with a database adapter (Postgres, DynamoDB, etc.).
 * @type {Map<string, object>}
 */
const userStore = new Map();

/**
 * Attribute mapping configuration.
 * Defines how incoming provider fields map to internal user fields.
 * Keys are internal field names; values are ordered arrays of source keys.
 */
const ATTRIBUTE_MAPPINGS = {
  email: ['email', 'mail', 'upn', 'preferred_username'],
  firstName: ['firstName', 'given_name', 'givenName', 'first_name'],
  lastName: ['lastName', 'family_name', 'sn', 'last_name'],
  displayName: ['displayName', 'name', 'cn', 'display_name'],
  department: ['department', 'extensionAttribute1'],
  jobTitle: ['jobTitle', 'title'],
  phone: ['phone', 'telephoneNumber', 'mobile'],
  groups: ['groups', 'memberOf'],
  roles: ['roles', 'role'],
};

/**
 * Resolve a value from the incoming profile using the ordered source-key list.
 * @param {object} profile - Raw provider profile.
 * @param {string[]} sourceKeys - Ordered keys to try.
 * @param {*} defaultValue - Fallback value.
 * @returns {*}
 */
function resolveAttribute(profile, sourceKeys, defaultValue = null) {
  for (const key of sourceKeys) {
    if (profile[key] !== undefined && profile[key] !== null && profile[key] !== '') {
      return profile[key];
    }
    // Also check inside a nested `attributes` object (common in SAML profiles)
    if (profile.attributes && profile.attributes[key] !== undefined) {
      return profile.attributes[key];
    }
  }
  return defaultValue;
}

/**
 * Normalise a value to ensure consistent types.
 * @param {*} value - Raw value.
 * @param {string} fieldName - Internal field name.
 * @returns {*} Normalised value.
 */
function normaliseAttribute(value, fieldName) {
  if (value === null || value === undefined) {
    return null;
  }
  // Lists should always be arrays
  if (fieldName === 'groups' || fieldName === 'roles') {
    if (Array.isArray(value)) {
      return value.map((v) => String(v).trim()).filter(Boolean);
    }
    return [String(value).trim()].filter(Boolean);
  }
  // Strings – trim whitespace
  if (typeof value === 'string') {
    return value.trim() || null;
  }
  return value;
}

/**
 * Transform a raw provider profile into a canonical internal user object.
 * @param {object} providerProfile - Profile from SAML or OIDC.
 * @param {string} provider - Provider name ('saml' | 'oidc').
 * @returns {object} Canonical user object.
 */
function transformProfile(providerProfile, provider) {
  const user = {
    provider,
    providerId: providerProfile.id || providerProfile.sub || providerProfile.nameID,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  for (const [internalField, sourceKeys] of Object.entries(ATTRIBUTE_MAPPINGS)) {
    const raw = resolveAttribute(providerProfile, sourceKeys);
    user[internalField] = normaliseAttribute(raw, internalField);
  }

  // Derive displayName from firstName + lastName if not provided directly
  if (!user.displayName) {
    user.displayName = [user.firstName, user.lastName].filter(Boolean).join(' ') || user.email;
  }

  // Derive a stable internal ID: prefer email, then sub/nameID
  user.id = user.email || user.providerId || uuidv4();

  return user;
}

/**
 * Merge an existing user record with updated attributes from the provider.
 * Preserves locally managed fields (e.g. app-specific roles) not present in the provider.
 * @param {object} existing - Current user record.
 * @param {object} incoming - Freshly transformed user from the provider.
 * @returns {object} Merged user record.
 */
function mergeUser(existing, incoming) {
  return {
    ...existing,
    ...incoming,
    // Preserve locally assigned roles by merging with provider roles
    roles: Array.from(new Set([...(existing.localRoles || []), ...(incoming.roles || [])])),
    localRoles: existing.localRoles || [],
    createdAt: existing.createdAt, // preserve original creation time
    updatedAt: new Date().toISOString(),
    loginCount: (existing.loginCount || 0) + 1,
    lastLoginAt: new Date().toISOString(),
  };
}

/**
 * Synchronise a user profile from the identity provider.
 * Creates a new user record on first login; updates on subsequent logins.
 *
 * @param {object} providerProfile - Raw profile from SAML or OIDC service.
 * @param {string} provider - 'saml' | 'oidc'
 * @returns {Promise<object>} The synced user record.
 */
async function syncUserProfile(providerProfile, provider) {
  logAuthEvent(AUTH_EVENT_TYPES.PROFILE_SYNC_STARTED, {
    userId: providerProfile.id,
    provider,
  });

  try {
    const transformed = transformProfile(providerProfile, provider);
    const userId = transformed.id;

    const existing = userStore.get(userId);
    let user;

    if (existing) {
      logger.info('Updating existing user profile', { userId, provider });
      user = mergeUser(existing, transformed);
    } else {
      logger.info('Creating new user profile', { userId, provider });
      user = {
        ...transformed,
        loginCount: 1,
        lastLoginAt: new Date().toISOString(),
        localRoles: [],
      };
    }

    userStore.set(userId, user);

    logAuthEvent(AUTH_EVENT_TYPES.PROFILE_SYNC_SUCCESS, {
      userId,
      provider,
      isNew: !existing,
    });

    return user;
  } catch (err) {
    logAuthEvent(AUTH_EVENT_TYPES.PROFILE_SYNC_FAILED, {
      userId: providerProfile.id,
      provider,
      error: err.message,
    });
    logger.error('Profile sync failed', { error: err.message });
    throw err;
  }
}

/**
 * Retrieve a user by their internal ID (email or provider sub).
 * @param {string} userId - Internal user ID.
 * @returns {object|null}
 */
function getUserById(userId) {
  return userStore.get(userId) || null;
}

/**
 * Return all users in the store (for admin/SCIM use).
 * @param {object} [pagination] - Optional pagination.
 * @param {number} [pagination.startIndex=1] - 1-based start index.
 * @param {number} [pagination.count=100] - Page size.
 * @returns {{ totalResults: number, startIndex: number, itemsPerPage: number, resources: object[] }}
 */
function listUsers({ startIndex = 1, count = 100 } = {}) {
  const all = Array.from(userStore.values());
  const sliced = all.slice(startIndex - 1, startIndex - 1 + count);
  return {
    totalResults: all.length,
    startIndex,
    itemsPerPage: sliced.length,
    resources: sliced,
  };
}

/**
 * Remove a user from the local store (e.g. on de-provisioning).
 * @param {string} userId - Internal user ID.
 * @returns {boolean} True if the user was found and deleted.
 */
function deleteUser(userId) {
  return userStore.delete(userId);
}

/**
 * Periodic synchronisation job (SCIM-inspired).
 * In production this would call the IdP's SCIM endpoint and reconcile
 * local user records. Here we log and run a stub reconciliation.
 */
async function runPeriodicSync() {
  logger.info('Periodic profile sync job started');
  const users = Array.from(userStore.values());
  let synced = 0;
  let errors = 0;

  for (const user of users) {
    try {
      // Stub: in production, re-fetch the user from the SCIM API and update
      userStore.set(user.id, { ...user, lastSyncedAt: new Date().toISOString() });
      synced++;
    } catch (err) {
      logger.error('Error syncing user during periodic job', {
        userId: user.id,
        error: err.message,
      });
      errors++;
    }
  }

  logger.info('Periodic profile sync job complete', { synced, errors });
}

/**
 * Schedule the periodic sync job.
 * Default: runs every hour at :00.
 * @param {string} [cronExpression] - node-cron expression. Defaults to hourly.
 * @returns {cron.ScheduledTask}
 */
function schedulePeriodicSync(cronExpression = '0 * * * *') {
  logger.info('Scheduling periodic profile sync', { cronExpression });
  const task = cron.schedule(cronExpression, async () => {
    try {
      await runPeriodicSync();
    } catch (err) {
      logger.error('Periodic sync job threw an error', { error: err.message });
    }
  });
  return task;
}

/**
 * Clear the user store (primarily for testing).
 */
function clearUserStore() {
  userStore.clear();
}

module.exports = {
  syncUserProfile,
  transformProfile,
  mergeUser,
  getUserById,
  listUsers,
  deleteUser,
  runPeriodicSync,
  schedulePeriodicSync,
  clearUserStore,
  ATTRIBUTE_MAPPINGS,
};
