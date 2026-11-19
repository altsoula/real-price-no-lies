'use strict';

const { getSharedRedisClient } = require('./redisClient');

const PREFIX = 'rpnl:stats';

function getTodayKey() {
  return new Date().toISOString().slice(0, 10);
}

/**
 * Zero-PII aggregate proof-of-traffic telemetry.
 * Stores strictly aggregate totals (page views, analyses, cache hits, retailer distribution).
 * Never logs or persists IP addresses, raw query URLs, or personal user identifiers.
 */
function createTrafficMetrics({ redisClient = null } = {}) {
  const mem = {
    startedAt: new Date().toISOString(),
    totalPageViews: 0,
    totalAnalyses: 0,
    cacheHits: 0,
    dailyDate: getTodayKey(),
    dailyAnalyses: 0,
    retailerCounts: {}
  };

  function syncDailyMem() {
    const today = getTodayKey();
    if (mem.dailyDate !== today) {
      mem.dailyDate = today;
      mem.dailyAnalyses = 0;
    }
    return today;
  }

  async function recordPageView() {
    mem.totalPageViews += 1;
    if (redisClient && redisClient.isConfigured()) {
      try {
        await redisClient.incr(`${PREFIX}:pageviews`);
      } catch {
        // Non-fatal fallback to memory counter
      }
    }
  }

  async function recordAnalysis({ retailerName = 'Online Store', cached = false } = {}) {
    const today = syncDailyMem();
    mem.totalAnalyses += 1;
    mem.dailyAnalyses += 1;
    if (cached) mem.cacheHits += 1;
    mem.retailerCounts[retailerName] = (mem.retailerCounts[retailerName] || 0) + 1;

    if (redisClient && redisClient.isConfigured()) {
      try {
        const dayKey = `${PREFIX}:analyses:${today}`;
        await redisClient.incr(`${PREFIX}:analyses:total`);
        await redisClient.incr(dayKey);
        await redisClient.expire(dayKey, 7 * 24 * 60 * 60);
        if (cached) {
          await redisClient.incr(`${PREFIX}:cache_hits`);
        }
        await redisClient.hincrby(`${PREFIX}:retailers`, retailerName, 1);
      } catch {
        // Non-fatal fallback to memory counter
      }
    }
  }

  async function getStats() {
    const today = syncDailyMem();
    if (redisClient && redisClient.isConfigured()) {
      try {
        const [pv, totalA, dayA, hits, retMap] = await Promise.all([
          redisClient.get(`${PREFIX}:pageviews`),
          redisClient.get(`${PREFIX}:analyses:total`),
          redisClient.get(`${PREFIX}:analyses:${today}`),
          redisClient.get(`${PREFIX}:cache_hits`),
          redisClient.hgetall(`${PREFIX}:retailers`)
        ]);
        const retailerCounts = {};
        for (const [k, v] of Object.entries(retMap || {})) {
          const parsed = Number(v);
          if (Number.isFinite(parsed) && parsed > 0) retailerCounts[k] = parsed;
        }
        return {
          storage: 'redis',
          totalPageViews: Number(pv) || mem.totalPageViews,
          totalAnalyses: Number(totalA) || mem.totalAnalyses,
          dailyDate: today,
          dailyAnalyses: Number(dayA) || mem.dailyAnalyses,
          cacheHits: Number(hits) || mem.cacheHits,
          topRetailers: Object.entries(retailerCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 6)
            .map(([retailer, count]) => ({ retailer, count }))
        };
      } catch {
        // Fall through to in-memory telemetry
      }
    }

    return {
      storage: 'memory',
      totalPageViews: mem.totalPageViews,
      totalAnalyses: mem.totalAnalyses,
      dailyDate: today,
      dailyAnalyses: mem.dailyAnalyses,
      cacheHits: mem.cacheHits,
      topRetailers: Object.entries(mem.retailerCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6)
        .map(([retailer, count]) => ({ retailer, count }))
    };
  }

  return {
    recordPageView,
    recordAnalysis,
    getStats
  };
}

const defaultTrafficMetrics = createTrafficMetrics({
  redisClient: getSharedRedisClient()
});

module.exports = {
  createTrafficMetrics,
  defaultTrafficMetrics,
  recordPageView: () => defaultTrafficMetrics.recordPageView(),
  recordAnalysis: (info) => defaultTrafficMetrics.recordAnalysis(info),
  getPublicTrafficStats: () => defaultTrafficMetrics.getStats()
};

