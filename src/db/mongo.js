const { MongoClient } = require('mongodb');
const config = require('../config');
const logger = require('../logger');

let db;

async function connect() {
  const client = new MongoClient(config.mongoUri);
  await client.connect();
  db = client.db('Addrs');
  logger.info('MongoDB connected');
}

// ── Mods allowlist (admin-managed, static) ────────────────────────────────────
// Collection: 'mods'  — contains { publicKey } for every permitted moderator.
// Only admins write to this collection directly in MongoDB.

/**
 * Returns true if the given publicKey exists in the mods allowlist.
 */
async function isModAllowed(publicKey) {
  const doc = await db.collection('mods').findOne({ publicKey }, { projection: { _id: 1 } });
  return doc !== null;
}

// ── Online mods live registry (server-managed, TTL-based) ─────────────────────
// Collection: 'onlinemods' — contains { peerId, publicKey, lastSeen } for mods
// that are currently online. Written by the server on register/refresh/deregister.

function getMods(sinceMs) {
  const filter = sinceMs ? { lastSeen: { $gte: new Date(Date.now() - sinceMs) } } : {};
  return db.collection('onlinemods').find(filter, { projection: { _id: 0 } }).toArray();
}

function upsertMod(peerId, publicKey) {
  return db.collection('onlinemods').updateOne(
    { publicKey },
    { $set: { peerId, publicKey, lastSeen: new Date() } },
    { upsert: true },
  );
}

function touchMod(publicKey) {
  return db.collection('onlinemods').updateOne({ publicKey }, { $set: { lastSeen: new Date() } });
}

function removeMod(publicKey) {
  return db.collection('onlinemods').deleteOne({ publicKey });
}

function removeStaleModsBefore(cutoff) {
  return db.collection('onlinemods').deleteMany({ lastSeen: { $lt: cutoff } });
}

// ── Relays ────────────────────────────────────────────────────────────────────

function getRelays(sinceMs) {
  const filter = sinceMs ? { lastSeen: { $gte: new Date(Date.now() - sinceMs) } } : {};
  return db.collection('relays').find(filter, { projection: { _id: 0 } }).toArray();
}

function upsertRelay(address, publicKey) {
  return db.collection('relays').updateOne(
    { publicKey },
    { $set: { address, publicKey, lastSeen: new Date() } },
    { upsert: true },
  );
}

function touchRelay(publicKey) {
  return db.collection('relays').updateOne({ publicKey }, { $set: { lastSeen: new Date() } });
}

function removeRelay(publicKey) {
  return db.collection('relays').deleteOne({ publicKey });
}

function removeStaleRelaysBefore(cutoff) {
  return db.collection('relays').deleteMany({ lastSeen: { $lt: cutoff } });
}

// ── Nodes (bootstrap DB nodes — static, no TTL) ───────────────────────────────

function getNodes() {
  return db.collection('nodes').find({}, { projection: { _id: 0 } }).toArray();
}

module.exports = {
  connect,
  isModAllowed,
  getMods,
  upsertMod,
  touchMod,
  removeMod,
  removeStaleModsBefore,
  getRelays,
  upsertRelay,
  touchRelay,
  removeRelay,
  removeStaleRelaysBefore,
  getNodes,
};
