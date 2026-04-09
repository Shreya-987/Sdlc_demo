'use strict';

const express = require('express');
const { getAuthEvents, getAuthStats, AUTH_EVENT_TYPES } = require('../logging/authLogger');

const router = express.Router();

/**
 * GET /api/auth-events
 * Return authentication events with optional filtering.
 * Query params: eventType, userId, email, since (ISO timestamp).
 */
router.get('/', (req, res) => {
  const filters = {};
  if (req.query.eventType) filters.eventType = req.query.eventType;
  if (req.query.userId) filters.userId = req.query.userId;
  if (req.query.email) filters.email = req.query.email;
  if (req.query.since) filters.since = req.query.since;

  const events = getAuthEvents(filters);
  res.json({ count: events.length, events });
});

/**
 * GET /api/auth-events/stats
 * Return aggregated authentication statistics.
 */
router.get('/stats', (req, res) => {
  const stats = getAuthStats();
  res.json(stats);
});

/**
 * GET /api/auth-events/types
 * Return all supported event types (useful for dashboard dropdowns).
 */
router.get('/types', (req, res) => {
  res.json({ eventTypes: Object.values(AUTH_EVENT_TYPES) });
});

module.exports = { router };
