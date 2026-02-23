const db = require('../db/mongo');
const config = require('../config');
const logger = require('../logger');

/**
 * Periodically removes mod and relay entries that have not been refreshed
 * within the configured TTL. This makes the registry self-healing — offline
 * nodes disappear automatically without requiring an explicit deregister call.
 *
 * Runs every EXPIRY_JOB_INTERVAL_SECONDS (default 90 s).
 * GET /mods and GET /relays also filter by lastSeen as a second line of defence.
 */
function startExpiryJob() {
  const interval = setInterval(async () => {
    const cutoff = new Date(Date.now() - config.entryTtlMs);
    try {
      const modResult = await db.removeStaleModsBefore(cutoff);
      const relayResult = await db.removeStaleRelaysBefore(cutoff);
      const removed = modResult.deletedCount + relayResult.deletedCount;
      if (removed > 0) {
        logger.info(
          { staleMods: modResult.deletedCount, staleRelays: relayResult.deletedCount, cutoff },
          'Expiry job removed stale entries',
        );
      }
    } catch (err) {
      logger.error({ err }, 'Expiry job error');
    }
  }, config.expiryJobIntervalMs);

  // Don't block process exit
  if (interval.unref) interval.unref();

  logger.info(
    { ttlSeconds: config.entryTtlMs / 1000, sweepIntervalSeconds: config.expiryJobIntervalMs / 1000 },
    'Expiry job started',
  );
}

module.exports = { startExpiryJob };
