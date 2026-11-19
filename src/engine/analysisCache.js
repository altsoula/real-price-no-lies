'use strict';

const crypto = require('node:crypto');

/**
 * Bounded in-memory L1 LRU/TTL cache + optional shared Redis L2 cache + in-flight deduplication
 * for deterministic repeat queries and viral-link stampede protection across replicas.
 */
function createAnalysisCache({
  maxEntries = 5000,
  ttlMs = null,
  redisClient = null
} = {}) {
  const defaultHours = Math.max(1, Number(process.env.CACHE_TTL_HOURS) || 8);
  const resolvedTtlMs = typeof ttlMs === 'number' && ttlMs > 0 ? ttlMs : defaultHours * 60 * 60 * 1000;

  /** @type {Map<string, { value: object, expiresAt: number }>} */
  const store = new Map();
  /** @type {Map<string, Promise<object>>} */
  const inFlight = new Map();

  function buildRedisKey(key) {
    const hash = crypto.createHash('sha256').update(String(key)).digest('hex');
    return `rpnl:cache:${hash}`;
  }

  function get(key, now = Date.now()) {
    const entry = store.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= now) {
      store.delete(key);
      return null;
    }
    // Refresh insertion order for LRU eviction
    store.delete(key);
    store.set(key, entry);
    return structuredClone(entry.value);
  }

  function set(key, value, now = Date.now()) {
    if (store.has(key)) {
      store.delete(key);
    }
    while (store.size >= maxEntries) {
      const oldestKey = store.keys().next().value;
      if (oldestKey === undefined) break;
      store.delete(oldestKey);
    }
    store.set(key, {
      value: structuredClone(value),
      expiresAt: now + resolvedTtlMs
    });
  }

  async function getAsync(key, now = Date.now()) {
    const localHit = get(key, now);
    if (localHit) return localHit;

    if (redisClient && redisClient.isConfigured()) {
      try {
        const raw = await redisClient.get(buildRedisKey(key));
        if (raw) {
          const parsed = JSON.parse(raw);
          if (parsed && typeof parsed === 'object') {
            set(key, parsed, now);
            return structuredClone(parsed);
          }
        }
      } catch {
        // Non-fatal fallback if Redis is temporarily unavailable
      }
    }
    return null;
  }

  async function setAsync(key, value, now = Date.now()) {
    set(key, value, now);
    if (redisClient && redisClient.isConfigured()) {
      try {
        const ttlSec = Math.max(1, Math.floor(resolvedTtlMs / 1000));
        await redisClient.setEx(buildRedisKey(key), ttlSec, JSON.stringify(value));
      } catch {
        // Non-fatal fallback; L1 cache remains warm
      }
    }
  }

  function getInFlight(key) {
    return inFlight.get(key) || null;
  }

  function setInFlight(key, promise) {
    inFlight.set(key, promise);
    promise
      .finally(() => {
        if (inFlight.get(key) === promise) {
          inFlight.delete(key);
        }
      })
      .catch(() => {});
  }

  function clear() {
    store.clear();
    inFlight.clear();
  }

  return {
    get,
    set,
    getAsync,
    setAsync,
    getInFlight,
    setInFlight,
    clear,
    ttlMs: resolvedTtlMs,
    ttlHours: Math.round((resolvedTtlMs / 3_600_000) * 10) / 10,
    size: () => store.size,
    inFlightSize: () => inFlight.size
  };
}

module.exports = { createAnalysisCache };
