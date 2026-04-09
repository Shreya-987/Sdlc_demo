'use strict';

const winston = require('winston');
const { v4: uuidv4 } = require('uuid');

/**
 * Authentication Logging and Monitoring Service
 * SUBTASK-4: Implement authentication logging and monitoring.
 *
 * Captures login attempts, failures, session creation/destruction, and
 * logout events with structured metadata for auditing and forensic analysis.
 */

const LOG_LEVEL = process.env.LOG_LEVEL || 'info';

/**
 * Custom log format that enriches entries with a correlation ID and timestamp.
 */
const authLogFormat = winston.format.combine(
  winston.format.timestamp({ format: 'ISO' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

/**
 * Singleton root logger – all module loggers are children of this.
 */
const rootLogger = winston.createLogger({
  level: LOG_LEVEL,
  format: authLogFormat,
  defaultMeta: { service: 'enterprise-sso' },
  transports: [
    new winston.transports.Console({
      silent: process.env.NODE_ENV === 'test',
    }),
    // In production, add file transports or external sinks (e.g. CloudWatch, Splunk)
    ...(process.env.AUTH_LOG_FILE
      ? [
          new winston.transports.File({
            filename: process.env.AUTH_LOG_FILE,
            maxsize: 10 * 1024 * 1024, // 10 MB
            maxFiles: 10,
            tailable: true,
          }),
        ]
      : []),
  ],
});

/**
 * In-memory event store used as a secondary audit trail.
 * In production, replace with a persistent store (DB, SIEM, S3).
 */
const authEventStore = [];

/**
 * Enumerate all supported authentication event types.
 */
const AUTH_EVENT_TYPES = Object.freeze({
  // SAML events
  SAML_LOGIN_INITIATED: 'saml_login_initiated',
  SAML_LOGIN_SUCCESS: 'saml_login_success',
  SAML_LOGIN_FAILED: 'saml_login_failed',
  SAML_LOGIN_ERROR: 'saml_login_error',
  SAML_SESSION_CREATED: 'saml_session_created',
  SAML_LOGOUT: 'saml_logout',

  // OIDC events
  OIDC_LOGIN_INITIATED: 'oidc_login_initiated',
  OIDC_LOGIN_SUCCESS: 'oidc_login_success',
  OIDC_LOGIN_FAILED: 'oidc_login_failed',
  OIDC_SESSION_CREATED: 'oidc_session_created',
  OIDC_LOGOUT: 'oidc_logout',
  OIDC_TOKEN_REFRESHED: 'oidc_token_refreshed',

  // Profile events
  PROFILE_SYNC_STARTED: 'profile_sync_started',
  PROFILE_SYNC_SUCCESS: 'profile_sync_success',
  PROFILE_SYNC_FAILED: 'profile_sync_failed',

  // Generic session events
  SESSION_EXPIRED: 'session_expired',
  SESSION_INVALIDATED: 'session_invalidated',
  UNAUTHORIZED_ACCESS: 'unauthorized_access',
});

/**
 * Get a named child logger for a specific module.
 * @param {string} moduleName - Module identifier (e.g. 'saml', 'oidc').
 * @returns {winston.Logger}
 */
function getLogger(moduleName) {
  return rootLogger.child({ module: moduleName });
}

/**
 * Log a structured authentication event.
 * Every event gets a unique correlation ID for tracing.
 *
 * @param {string} eventType - One of AUTH_EVENT_TYPES values.
 * @param {object} [metadata] - Additional key/value metadata.
 * @returns {object} The recorded event.
 */
function logAuthEvent(eventType, metadata = {}) {
  const event = {
    eventId: uuidv4(),
    eventType,
    timestamp: new Date().toISOString(),
    ...metadata,
  };

  // Determine log level based on event type
  const isFailure =
    eventType.includes('failed') ||
    eventType.includes('error') ||
    eventType === AUTH_EVENT_TYPES.UNAUTHORIZED_ACCESS;

  const level = isFailure ? 'warn' : 'info';
  rootLogger[level]({ ...event, msg: `AUTH_EVENT:${eventType}` });

  // Persist to the in-memory audit store
  authEventStore.push(event);

  // Keep the store bounded (retain last 10 000 events in memory)
  if (authEventStore.length > 10000) {
    authEventStore.shift();
  }

  return event;
}

/**
 * Retrieve all stored authentication events, optionally filtered.
 * @param {object} [filters] - Optional filter criteria.
 * @param {string} [filters.eventType] - Filter by event type.
 * @param {string} [filters.userId] - Filter by user ID.
 * @param {string} [filters.email] - Filter by email address.
 * @param {Date}   [filters.since] - Only return events after this date.
 * @returns {object[]} Matching events.
 */
function getAuthEvents(filters = {}) {
  let events = [...authEventStore];

  if (filters.eventType) {
    events = events.filter((e) => e.eventType === filters.eventType);
  }
  if (filters.userId) {
    events = events.filter((e) => e.userId === filters.userId);
  }
  if (filters.email) {
    events = events.filter((e) => e.email === filters.email);
  }
  if (filters.since) {
    const since = new Date(filters.since).getTime();
    events = events.filter((e) => new Date(e.timestamp).getTime() >= since);
  }

  return events;
}

/**
 * Clear the in-memory event store (primarily for testing).
 */
function clearAuthEvents() {
  authEventStore.length = 0;
}

/**
 * Return a summary of authentication statistics.
 * @returns {object} Statistics snapshot.
 */
function getAuthStats() {
  const total = authEventStore.length;
  const byType = authEventStore.reduce((acc, e) => {
    acc[e.eventType] = (acc[e.eventType] || 0) + 1;
    return acc;
  }, {});

  const failures = authEventStore.filter(
    (e) => e.eventType.includes('failed') || e.eventType.includes('error')
  ).length;

  return { total, failures, successRate: total ? ((total - failures) / total) * 100 : 100, byType };
}

module.exports = {
  getLogger,
  logAuthEvent,
  getAuthEvents,
  clearAuthEvents,
  getAuthStats,
  AUTH_EVENT_TYPES,
};
