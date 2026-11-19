'use strict';

/**
 * Extracts a client identifier from the underlying socket unless TRUST_PROXY=true.
 * Prevents trivial rate-limit bypass via spoofable X-Forwarded-For headers.
 * @param {import('node:http').IncomingMessage} req
 * @returns {string}
 */
function getClientIp(req) {
  if (process.env.TRUST_PROXY === 'true') {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.trim()) {
      return xff.split(',')[0].trim();
    }
  }
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

/**
 * Creates a bounded-memory sliding-window IP rate limiter to guard against DoS and scraping abuse.
 */
function createRateLimiter({
  windowMs = 60_000,
  maxRequests = 25,
  maxTrackedIps = 5000
} = {}) {
  /** @type {Map<string, number[]>} */
  const buckets = new Map();

  function pruneStale(now) {
    const cutoff = now - windowMs;
    for (const [ip, timestamps] of buckets.entries()) {
      const fresh = timestamps.filter((ts) => ts > cutoff);
      if (fresh.length === 0) {
        buckets.delete(ip);
      } else {
        buckets.set(ip, fresh);
      }
    }
    // Hard cap on tracked IPs to prevent memory exhaustion under distributed floods.
    while (buckets.size >= maxTrackedIps) {
      const oldestKey = buckets.keys().next().value;
      if (oldestKey === undefined) {
        break;
      }
      buckets.delete(oldestKey);
    }
  }

  /**
   * Checks and consumes one request quota unit for the given client IP.
   * @param {string} ip
   * @param {number} [now]
   */
  function consume(ip, now = Date.now()) {
    const key = String(ip || 'unknown');
    if (buckets.size >= maxTrackedIps && !buckets.has(key)) {
      pruneStale(now);
    }

    const cutoff = now - windowMs;
    const existing = buckets.get(key) || [];
    const active = existing.filter((ts) => ts > cutoff);

    if (active.length >= maxRequests) {
      buckets.set(key, active);
      const oldestActive = active[0];
      const resetMs = oldestActive + windowMs;
      const retryAfterSec = Math.max(1, Math.ceil((resetMs - now) / 1000));
      return {
        allowed: false,
        limit: maxRequests,
        remaining: 0,
        resetEpochSec: Math.ceil(resetMs / 1000),
        retryAfterSec
      };
    }

    active.push(now);
    buckets.set(key, active);

    const oldest = active[0];
    const resetMs = oldest + windowMs;
    return {
      allowed: true,
      limit: maxRequests,
      remaining: Math.max(0, maxRequests - active.length),
      resetEpochSec: Math.ceil(resetMs / 1000),
      retryAfterSec: 0
    };
  }

  return {
    consume,
    getClientIp,
    size: () => buckets.size
  };
}

module.exports = {
  createRateLimiter,
  getClientIp
};

