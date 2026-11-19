'use strict';

const crypto = require('node:crypto');

/**
 * Extracts a client identifier from the underlying socket unless TRUST_PROXY=true.
 * Prefers Cloudflare's verified CF-Connecting-IP when behind Cloudflare proxy,
 * preventing trivial rate-limit bypass via spoofable headers when untrusted.
 * @param {import('node:http').IncomingMessage} req
 * @returns {string}
 */
function getClientIp(req) {
  if (process.env.TRUST_PROXY === 'true' && req && req.headers) {
    const cfIp = req.headers['cf-connecting-ip'];
    if (typeof cfIp === 'string' && cfIp.trim()) {
      return cfIp.split(',')[0].trim();
    }
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.trim()) {
      return xff.split(',')[0].trim();
    }
  }
  return (req && req.socket && req.socket.remoteAddress) || 'unknown';
}

/**
 * Creates a bounded-memory sliding-window IP rate limiter with optional Redis backing
 * for shared multi-replica enforcement.
 */
function createRateLimiter({
  windowMs = 60_000,
  maxRequests = 25,
  maxTrackedIps = 5000,
  redisClient = null
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
   * Checks and consumes one request quota unit synchronously from volatile memory.
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

  /**
   * Distributed Redis-backed rate-limit check with automatic fallback to in-memory limiting.
   * Hashes client IP before persisting Redis keys to preserve zero-PII hygiene.
   * @param {string} ip
   * @param {number} [now]
   */
  async function consumeAsync(ip, now = Date.now()) {
    if (redisClient && redisClient.isConfigured()) {
      try {
        const ipHash = crypto.createHash('sha256').update(String(ip || 'unknown')).digest('hex').slice(0, 32);
        const bucket = Math.floor(now / windowMs);
        const redisKey = `rpnl:rl:${ipHash}:${bucket}`;
        const count = await redisClient.incr(redisKey);
        if (count === 1) {
          await redisClient.pexpire(redisKey, windowMs);
        }
        const resetMs = (bucket + 1) * windowMs;
        const retryAfterSec = Math.max(1, Math.ceil((resetMs - now) / 1000));
        if (count > maxRequests) {
          return {
            allowed: false,
            limit: maxRequests,
            remaining: 0,
            resetEpochSec: Math.ceil(resetMs / 1000),
            retryAfterSec
          };
        }
        return {
          allowed: true,
          limit: maxRequests,
          remaining: Math.max(0, maxRequests - count),
          resetEpochSec: Math.ceil(resetMs / 1000),
          retryAfterSec: 0
        };
      } catch {
        // Fallback smoothly to in-memory rate limiter
      }
    }
    return consume(ip, now);
  }

  return {
    consume,
    consumeAsync,
    getClientIp,
    size: () => buckets.size
  };
}

module.exports = {
  createRateLimiter,
  getClientIp
};
