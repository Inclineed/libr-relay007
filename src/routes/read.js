const { Router } = require('express');
const db = require('../db/mongo');
const config = require('../config');

const router = Router();

/**
 * GET /mods
 * Returns all mod entries whose lastSeen is within the configured TTL.
 * Response: [{ peerId, publicKey, lastSeen }]
 */
router.get('/mods', async (_req, res) => {
  try {
    const mods = await db.getMods(config.entryTtlMs);
    res.json(mods);
  } catch (err) {
    console.error('GET /mods error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /relays
 * Returns all relay entries whose lastSeen is within the configured TTL.
 * Response: [{ address, publicKey, lastSeen }]
 */
router.get('/relays', async (_req, res) => {
  try {
    const relays = await db.getRelays(config.entryTtlMs);
    res.json(relays);
  } catch (err) {
    console.error('GET /relays error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /nodes
 * Returns all bootstrap DB node entries (static, no TTL).
 * Response: [{ node_id, peer_id }]
 */
router.get('/nodes', async (_req, res) => {
  try {
    const nodes = await db.getNodes();
    res.json(nodes);
  } catch (err) {
    console.error('GET /nodes error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
