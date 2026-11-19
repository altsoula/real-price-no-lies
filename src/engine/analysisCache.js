'use strict';

/**
 * Bounded in-memory LRU/TTL cache + in-flight deduplication registry
 * for deterministic repeat queries and viral-link stampede protection.
 */
function createAnalysisCache({ maxEntries = 5000, ttlMs = 2 * 60 * 60 * 1000 } = {}) {
  /** @type {Map<string, { value: object, expiresAt: number }>} */
  const store = new Map();
  /** @type {Map<string, Promise<object>>} */
  const inFlight = new Map();

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
      expiresAt: now + ttlMs
    });
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
    getInFlight,
    setInFlight,
    clear,
    size: () => store.size,
    inFlightSize: () => inFlight.size
  };
}

module.exports = { createAnalysisCache };
