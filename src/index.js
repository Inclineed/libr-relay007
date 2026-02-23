const express = require('express');
const config = require('./config');
const { connect } = require('./db/mongo');
const readRoutes = require('./routes/read');
const writeRoutes = require('./routes/write');
const { startExpiryJob } = require('./jobs/expiry');

const app = express();
app.use(express.json());

// ── Routes ────────────────────────────────────────────────────────────────────
// Public read-only endpoints — no authentication required
app.use('/', readRoutes);

// Authenticated write endpoints — Ed25519 challenge-response required
app.use('/', writeRoutes);

// ── Startup ───────────────────────────────────────────────────────────────────
async function main() {
  await connect();
  startExpiryJob();
  app.listen(config.port, () => {
    console.log(`🚀 librserver running on port ${config.port}`);
  });
}

main().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
