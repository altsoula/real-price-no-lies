'use strict';

class QueueOverflowError extends Error {
  constructor(message = 'Analysis queue is currently at capacity. Please retry in a few seconds.') {
    super(message);
    this.name = 'QueueOverflowError';
    this.statusCode = 503;
    this.code = 'SERVER_BUSY';
  }
}

/**
 * Bounded concurrency semaphore & FIFO queue to protect memory and upstream APIs
 * when hundreds or thousands of uncached URLs arrive simultaneously.
 */
function createConcurrencyQueue({
  maxConcurrent = 15,
  maxQueueSize = 250,
  queueTimeoutMs = 18_000
} = {}) {
  let active = 0;
  /** @type {Array<{ fn: Function, resolve: Function, reject: Function, timer: NodeJS.Timeout }>} */
  const waiting = [];

  function drain() {
    while (active < maxConcurrent && waiting.length > 0) {
      const next = waiting.shift();
      clearTimeout(next.timer);
      active += 1;
      Promise.resolve()
        .then(() => next.fn())
        .then(next.resolve, next.reject)
        .finally(() => {
          active = Math.max(0, active - 1);
          drain();
        });
    }
  }

  function run(fn) {
    if (active < maxConcurrent) {
      active += 1;
      return Promise.resolve()
        .then(() => fn())
        .finally(() => {
          active = Math.max(0, active - 1);
          drain();
        });
    }

    if (waiting.length >= maxQueueSize) {
      return Promise.reject(new QueueOverflowError());
    }

    return new Promise((resolve, reject) => {
      const entry = {
        fn,
        resolve,
        reject,
        timer: null
      };
      entry.timer = setTimeout(() => {
        const idx = waiting.indexOf(entry);
        if (idx !== -1) {
          waiting.splice(idx, 1);
          reject(new QueueOverflowError('Timed out waiting for analysis slot. Please retry.'));
        }
      }, queueTimeoutMs);
      entry.timer.unref();
      waiting.push(entry);
    });
  }

  return {
    run,
    stats: () => ({
      active,
      queued: waiting.length,
      maxConcurrent,
      maxQueueSize
    })
  };
}

module.exports = {
  QueueOverflowError,
  createConcurrencyQueue
};

