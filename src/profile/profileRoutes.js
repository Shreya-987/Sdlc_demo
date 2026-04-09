'use strict';

const express = require('express');
const { getUserById, listUsers, deleteUser, runPeriodicSync } = require('./profileSyncService');
const { getLogger } = require('../logging/authLogger');

const router = express.Router();
const logger = getLogger('profile-routes');

/**
 * GET /api/users
 * List users (SCIM-compatible response envelope).
 * Query params: startIndex (1-based), count.
 */
router.get('/', (req, res) => {
  const startIndex = parseInt(req.query.startIndex, 10) || 1;
  const count = Math.min(parseInt(req.query.count, 10) || 100, 200);
  const result = listUsers({ startIndex, count });
  res.json(result);
});

/**
 * GET /api/users/:id
 * Get a single user profile by ID.
 */
router.get('/:id', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(user);
});

/**
 * DELETE /api/users/:id
 * Deprovision a user.
 */
router.delete('/:id', (req, res) => {
  const deleted = deleteUser(req.params.id);
  if (!deleted) {
    return res.status(404).json({ error: 'User not found' });
  }
  logger.info('User deprovisioned', { userId: req.params.id });
  res.status(204).send();
});

/**
 * POST /api/users/sync
 * Trigger an immediate profile synchronisation run.
 */
router.post('/sync', async (req, res) => {
  try {
    await runPeriodicSync();
    res.json({ message: 'Sync completed' });
  } catch (err) {
    logger.error('Manual sync failed', { error: err.message });
    res.status(500).json({ error: 'Sync failed', details: err.message });
  }
});

module.exports = { router };
