const { MongoClient } = require('mongodb');
const config = require('../config');

let db;

async function connect() {
  const client = new MongoClient(config.mongoUri);
  await client.connect();
  db = client.db('Addrs');
  console.log('✅ MongoDB connected');
}

// ── Mods ─────────────────────────────────────────────────────────────────────

function getMods(sinceMs) {
  const filter = sinceMs ? { lastSeen: { $gte: new Date(Date.now() - sinceMs) } } : {};
  return db.collection('mods').find(filter, { projection: { _id: 0 } }).toArray();
}

function upsertMod(peerId, publicKey) {
  return db.collection('mods').updateOne(
    { publicKey },
    { $set: { peerId, publicKey, lastSeen: new Date() } },
    { upsert: true },
  );
}

function touchMod(publicKey) {
  return db.collection('mods').updateOne({ publicKey }, { $set: { lastSeen: new Date() } });
}

function removeMod(publicKey) {
  return db.collection('mods').deleteOne({ publicKey });
}

function removeStaleModsBefore(cutoff) {
  return db.collection('mods').deleteMany({ lastSeen: { $lt: cutoff } });
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
