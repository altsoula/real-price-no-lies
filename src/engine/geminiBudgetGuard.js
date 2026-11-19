'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_PERSIST_PATH = path.resolve(__dirname, '..', '..', '.gemini-budget.json');

function getUtcDateKey(now = Date.now()) {
  return new Date(now).toISOString().slice(0, 10);
}

/**
 * Hard daily + per-minute Gemini API circuit breaker to protect wallet credits
 * against unexpected traffic spikes across all visitors.
 */
function createGeminiBudgetGuard({
  maxDailyCalls = null,
  maxMinuteCalls = null,
  persistFilePath = DEFAULT_PERSIST_PATH
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

  return {
    tryConsume,
    getStats
  };
}

const defaultBudgetGuard = createGeminiBudgetGuard();

module.exports = {
  createGeminiBudgetGuard,
  defaultBudgetGuard,
  tryConsumeGeminiQuota: (now) => defaultBudgetGuard.tryConsume(now),
  getBudgetStats: (now) => defaultBudgetGuard.getStats(now)
};

