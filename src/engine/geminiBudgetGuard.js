'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { getSharedRedisClient } = require('../storage/redisClient');

const DEFAULT_PERSIST_PATH = path.resolve(__dirname, '..', '..', '.gemini-budget.json');

function getUtcDateKey(now = Date.now()) {
  return new Date(now).toISOString().slice(0, 10);
}

/**
 * Hard daily + per-minute Gemini API circuit breaker to protect wallet credits
 * against unexpected traffic spikes across single or multi-replica deployments.
 */
function createGeminiBudgetGuard({
  maxDailyCalls = null,
  maxMinuteCalls = null,
  persistFilePath = DEFAULT_PERSIST_PATH,
  redisClient = null
} = {}) {
  let dailyState = {
    date: getUtcDateKey(),
    count: 0
  };
  /** @type {number[]} */
  let minuteTimestamps = [];

  if (persistFilePath) {
    try {
      if (fs.existsSync(persistFilePath)) {
        const raw = JSON.parse(fs.readFileSync(persistFilePath, 'utf8'));
        const today = getUtcDateKey();
        if (raw && raw.date === today && Number.isInteger(raw.count) && raw.count >= 0) {
          dailyState = { date: today, count: raw.count };
        }
      }
    } catch {
      // Ignore corrupt or unreadable budget file; start clean for today
    }
  }

  function getCaps() {
    const dailyCap =
      maxDailyCalls !== null
        ? maxDailyCalls
        : Number(process.env.MAX_DAILY_GEMINI_CALLS) || 500;
    const minuteCap =
      maxMinuteCalls !== null
        ? maxMinuteCalls
        : Number(process.env.MAX_MINUTE_GEMINI_CALLS) || 30;
    return {
      dailyCap: Math.max(0, dailyCap),
      minuteCap: Math.max(0, minuteCap)
    };
  }

  function persist() {
    if (!persistFilePath) return;
    try {
      fs.writeFileSync(persistFilePath, JSON.stringify(dailyState), 'utf8');
    } catch {
      // Non-fatal if running on read-only container filesystem
    }
  }

  function syncWindow(now = Date.now()) {
    const today = getUtcDateKey(now);
    if (dailyState.date !== today) {
      dailyState = { date: today, count: 0 };
      persist();
    }
    const cutoff = now - 60_000;
    minuteTimestamps = minuteTimestamps.filter((ts) => ts > cutoff);
  }

  function tryConsume(now = Date.now()) {
    syncWindow(now);
    const { dailyCap, minuteCap } = getCaps();

    if (dailyState.count >= dailyCap) {
      return {
        allowed: false,
        reason: 'DAILY_BUDGET_CAP_REACHED',
        dailyCount: dailyState.count,
        dailyCap,
        minuteCount: minuteTimestamps.length,
        minuteCap
      };
    }

    if (minuteTimestamps.length >= minuteCap) {
      return {
        allowed: false,
        reason: 'MINUTE_BURST_CAP_REACHED',
        dailyCount: dailyState.count,
        dailyCap,
        minuteCount: minuteTimestamps.length,
        minuteCap
      };
    }

    dailyState.count += 1;
    minuteTimestamps.push(now);
    persist();

    return {
      allowed: true,
      reason: 'OK',
      dailyCount: dailyState.count,
      dailyCap,
      minuteCount: minuteTimestamps.length,
      minuteCap
    };
  }

  async function tryConsumeAsync(now = Date.now()) {
    if (redisClient && redisClient.isConfigured()) {
      try {
        const { dailyCap, minuteCap } = getCaps();
        const today = getUtcDateKey(now);
        const minuteBucket = Math.floor(now / 60_000);
        const dayKey = `rpnl:budget:day:${today}`;
        const minKey = `rpnl:budget:min:${minuteBucket}`;

        const [curDayRaw, curMinRaw] = await Promise.all([
          redisClient.get(dayKey),
          redisClient.get(minKey)
        ]);
        const curDay = Number(curDayRaw) || 0;
        const curMin = Number(curMinRaw) || 0;

        if (curDay >= dailyCap) {
          return {
            allowed: false,
            reason: 'DAILY_BUDGET_CAP_REACHED',
            dailyCount: curDay,
            dailyCap,
            minuteCount: curMin,
            minuteCap
          };
        }
        if (curMin >= minuteCap) {
          return {
            allowed: false,
            reason: 'MINUTE_BURST_CAP_REACHED',
            dailyCount: curDay,
            dailyCap,
            minuteCount: curMin,
            minuteCap
          };
        }

        const [nextDay, nextMin] = await Promise.all([
          redisClient.incr(dayKey),
          redisClient.incr(minKey)
        ]);
        if (nextDay === 1) await redisClient.expire(dayKey, 48 * 3600);
        if (nextMin === 1) await redisClient.expire(minKey, 120);

        dailyState = { date: today, count: nextDay };
        persist();

        return {
          allowed: true,
          reason: 'OK',
          dailyCount: nextDay,
          dailyCap,
          minuteCount: nextMin,
          minuteCap
        };
      } catch {
        // Fall through cleanly to local in-memory circuit breaker
      }
    }
    return tryConsume(now);
  }

  function getStats(now = Date.now()) {
    syncWindow(now);
    const { dailyCap, minuteCap } = getCaps();
    return {
      date: dailyState.date,
      dailyUsed: dailyState.count,
      dailyLimit: dailyCap,
      dailyRemaining: Math.max(0, dailyCap - dailyState.count),
      minuteUsed: minuteTimestamps.length,
      minuteLimit: minuteCap
    };
  }

  async function getStatsAsync(now = Date.now()) {
    if (redisClient && redisClient.isConfigured()) {
      try {
        const { dailyCap, minuteCap } = getCaps();
        const today = getUtcDateKey(now);
        const minuteBucket = Math.floor(now / 60_000);
        const [dayRaw, minRaw] = await Promise.all([
          redisClient.get(`rpnl:budget:day:${today}`),
          redisClient.get(`rpnl:budget:min:${minuteBucket}`)
        ]);
        const dailyUsed = Number(dayRaw) || 0;
        const minuteUsed = Number(minRaw) || 0;
        return {
          date: today,
          dailyUsed,
          dailyLimit: dailyCap,
          dailyRemaining: Math.max(0, dailyCap - dailyUsed),
          minuteUsed,
          minuteLimit: minuteCap
        };
      } catch {
        // Fall back cleanly to local counter
      }
    }
    return getStats(now);
  }

  return {
    tryConsume,
    tryConsumeAsync,
    getStats,
    getStatsAsync
  };
}

const defaultBudgetGuard = createGeminiBudgetGuard({
  redisClient: getSharedRedisClient()
});

module.exports = {
  createGeminiBudgetGuard,
  defaultBudgetGuard,
  tryConsumeGeminiQuota: (now) => defaultBudgetGuard.tryConsume(now),
  tryConsumeGeminiQuotaAsync: (now) => defaultBudgetGuard.tryConsumeAsync(now),
  getBudgetStats: (now) => defaultBudgetGuard.getStats(now),
  getBudgetStatsAsync: (now) => defaultBudgetGuard.getStatsAsync(now)
};
