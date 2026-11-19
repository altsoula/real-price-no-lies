'use strict';

const fs = require('node:fs');
const path = require('node:path');

let loaded = false;

/**
 * Loads local `.env` variables into `process.env` without external dependencies.
 * Never logs or exposes secret values.
 */
function loadLocalEnv() {
  if (loaded) return;
  loaded = true;

  const envPath = path.resolve(__dirname, '..', '..', '.env');
  if (!fs.existsSync(envPath)) {
    return;
  }

  let content;
  try {
    content = fs.readFileSync(envPath, 'utf8');
  } catch {
    return;
  }

  const lines = content.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }
    const eqIdx = line.indexOf('=');
    if (eqIdx <= 0) {
      continue;
    }
    const key = line.slice(0, eqIdx).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      continue;
    }
    let val = line.slice(eqIdx + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"') && val.length >= 2) ||
      (val.startsWith("'") && val.endsWith("'") && val.length >= 2)
    ) {
      val = val.slice(1, -1);
    }

    if (!process.env[key]) {
      process.env[key] = val;
    }
  }
}

module.exports = { loadLocalEnv };

