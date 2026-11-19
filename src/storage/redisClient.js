'use strict';

const net = require('node:net');
const tls = require('node:tls');

/**
 * Encodes a Redis command array into a RESP2 wire buffer.
 * @param {Array<string | number>} args
 * @returns {Buffer}
 */
function encodeRespCommand(args) {
  const parts = [Buffer.from(`*${args.length}\r\n`, 'utf8')];
  for (const arg of args) {
    const str = String(arg);
    const byteLen = Buffer.byteLength(str, 'utf8');
    parts.push(Buffer.from(`$${byteLen}\r\n`, 'utf8'));
    parts.push(Buffer.from(str, 'utf8'));
    parts.push(Buffer.from('\r\n', 'utf8'));
  }
  return Buffer.concat(parts);
}

/**
 * Incrementally parses one complete RESP2 frame from `buf` starting at `offset`.
 * Returns null when more bytes are required from the TCP stream.
 * @param {Buffer} buf
 * @param {number} offset
 * @returns {{ value: any, nextOffset: number, isError?: boolean } | null}
 */
function tryParseRespFrame(buf, offset = 0) {
  if (offset >= buf.length) return null;
  const prefix = buf[offset];
  const crlf = buf.indexOf('\r\n', offset + 1);
  if (crlf === -1) return null;

  // '+' Simple String
  if (prefix === 43) {
    return { value: buf.toString('utf8', offset + 1, crlf), nextOffset: crlf + 2 };
  }
  // '-' Error
  if (prefix === 45) {
    return {
      value: buf.toString('utf8', offset + 1, crlf),
      nextOffset: crlf + 2,
      isError: true
    };
  }
  // ':' Integer
  if (prefix === 58) {
    const num = Number(buf.toString('utf8', offset + 1, crlf));
    return { value: num, nextOffset: crlf + 2 };
  }
  // '$' Bulk String
  if (prefix === 36) {
    const len = Number(buf.toString('utf8', offset + 1, crlf));
    if (len === -1) {
      return { value: null, nextOffset: crlf + 2 };
    }
    if (!Number.isInteger(len) || len < 0) {
      throw new Error('Invalid RESP bulk string length');
    }
    const end = crlf + 2 + len;
    if (end + 2 > buf.length) return null;
    return {
      value: buf.toString('utf8', crlf + 2, end),
      nextOffset: end + 2
    };
  }
  // '*' Array
  if (prefix === 42) {
    const count = Number(buf.toString('utf8', offset + 1, crlf));
    if (count === -1) {
      return { value: null, nextOffset: crlf + 2 };
    }
    if (!Number.isInteger(count) || count < 0) {
      throw new Error('Invalid RESP array count');
    }
    const items = [];
    let cursor = crlf + 2;
    for (let i = 0; i < count; i += 1) {
      const parsed = tryParseRespFrame(buf, cursor);
      if (!parsed) return null;
      items.push(parsed.isError ? new Error(String(parsed.value)) : parsed.value);
      cursor = parsed.nextOffset;
    }
    return { value: items, nextOffset: cursor };
  }

  throw new Error(`Unsupported RESP frame prefix byte: ${prefix}`);
}

/**
 * Parses `redis://` and `rediss://` connection URLs safely.
 * @param {string} rawUrl
 */
function parseRedisUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) return null;
  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return null;
  }
  if (parsed.protocol !== 'redis:' && parsed.protocol !== 'rediss:') {
    return null;
  }
  const dbSegment = parsed.pathname.replace(/^\/+/, '');
  const db = dbSegment && /^\d+$/.test(dbSegment) ? Number(dbSegment) : 0;
  return {
    useTls: parsed.protocol === 'rediss:',
    host: parsed.hostname,
    port: parsed.port ? Number(parsed.port) : 6379,
    username: parsed.username ? decodeURIComponent(parsed.username) : '',
    password: parsed.password ? decodeURIComponent(parsed.password) : '',
    db
  };
}

/**
 * Creates a lightweight, zero-dependency RESP2 Redis client with automatic reconnect
 * and non-fatal degradation when Redis is unavailable.
 */
function createRedisClient(redisUrl, options = {}) {
  const cfg = parseRedisUrl(redisUrl || '');
  const commandTimeoutMs = options.commandTimeoutMs || 2000;
  const connectTimeoutMs = options.connectTimeoutMs || 3000;

  let socket = null;
  let connected = false;
  let closing = false;
  let connectPromise = null;
  let reconnectTimer = null;
  let reconnectAttempt = 0;
  let rxBuffer = Buffer.alloc(0);

  /** @type {Array<{ resolve: Function, reject: Function, timer: NodeJS.Timeout }>} */
  const pending = [];

  function rejectAllPending(err) {
    while (pending.length > 0) {
      const entry = pending.shift();
      clearTimeout(entry.timer);
      entry.reject(err);
    }
  }

  function scheduleReconnect() {
    if (closing || !cfg || reconnectTimer) return;
    const delayMs = Math.min(30_000, 500 * Math.pow(2, reconnectAttempt));
    reconnectAttempt += 1;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      if (!closing) {
        ensureConnected().catch(() => {});
      }
    }, delayMs);
    if (typeof reconnectTimer.unref === 'function') {
      reconnectTimer.unref();
    }
  }

  function cleanupSocket(reasonErr) {
    connected = false;
    if (socket) {
      socket.removeAllListeners();
      socket.destroy();
      socket = null;
    }
    rxBuffer = Buffer.alloc(0);
    rejectAllPending(reasonErr || new Error('Redis connection closed'));
    scheduleReconnect();
  }

  function handleData(chunk) {
    rxBuffer = rxBuffer.length > 0 ? Buffer.concat([rxBuffer, chunk]) : chunk;
    while (rxBuffer.length > 0) {
      let frame;
      try {
        frame = tryParseRespFrame(rxBuffer, 0);
      } catch (err) {
        cleanupSocket(err);
        return;
      }
      if (!frame) break;
      rxBuffer = rxBuffer.subarray(frame.nextOffset);

      const nextWaiter = pending.shift();
      if (nextWaiter) {
        clearTimeout(nextWaiter.timer);
        if (frame.isError) {
          nextWaiter.reject(new Error(`Redis error: ${frame.value}`));
        } else {
          nextWaiter.resolve(frame.value);
        }
      }
    }
  }

  function sendRawOnSocket(targetSocket, args) {
    return new Promise((resolve, reject) => {
      if (!targetSocket || targetSocket.destroyed) {
        reject(new Error('Redis socket unavailable'));
        return;
      }
      const timer = setTimeout(() => {
        const idx = pending.findIndex((p) => p.resolve === resolve);
        if (idx !== -1) pending.splice(idx, 1);
        cleanupSocket(new Error('Redis command timeout'));
        reject(new Error('Redis command timeout'));
      }, commandTimeoutMs);
      if (typeof timer.unref === 'function') {
        timer.unref();
      }
      pending.push({ resolve, reject, timer });
      try {
        targetSocket.write(encodeRespCommand(args));
      } catch (err) {
        const idx = pending.findIndex((p) => p.resolve === resolve);
        if (idx !== -1) pending.splice(idx, 1);
        clearTimeout(timer);
        reject(err);
      }
    });
  }

  async function ensureConnected() {
    if (!cfg) throw new Error('Redis URL not configured');
    if (closing) throw new Error('Redis client closed');
    if (connected && socket && !socket.destroyed) return true;
    if (connectPromise) return connectPromise;

    connectPromise = (async () => {
      const sock = await new Promise((resolve, reject) => {
        const connectOpts = {
          host: cfg.host,
          port: cfg.port,
          family: 0,
          autoSelectFamily: true
        };
        if (cfg.useTls) {
          connectOpts.servername = cfg.host;
        }
        const s = cfg.useTls ? tls.connect(connectOpts) : net.createConnection(connectOpts);
        s.setNoDelay(true);

        const connectEvent = cfg.useTls ? 'secureConnect' : 'connect';
        const onTimeout = () => {
          s.destroy();
          reject(new Error('Redis connect timeout'));
        };
        const timer = setTimeout(onTimeout, connectTimeoutMs);
        if (typeof timer.unref === 'function') timer.unref();

        s.once(connectEvent, () => {
          clearTimeout(timer);
          resolve(s);
        });
        s.once('error', (err) => {
          clearTimeout(timer);
          s.destroy();
          reject(err);
        });
      });

      socket = sock;
      sock.on('data', handleData);
      sock.on('error', (err) => cleanupSocket(err));
      sock.on('close', () => cleanupSocket(new Error('Redis socket closed')));

      if (cfg.password) {
        if (cfg.username) {
          try {
            await sendRawOnSocket(sock, ['AUTH', cfg.username, cfg.password]);
          } catch (authErr) {
            if (/wrong number of arguments/i.test(authErr.message)) {
              await sendRawOnSocket(sock, ['AUTH', cfg.password]);
            } else {
              throw authErr;
            }
          }
        } else {
          await sendRawOnSocket(sock, ['AUTH', cfg.password]);
        }
      }

      if (cfg.db > 0) {
        await sendRawOnSocket(sock, ['SELECT', String(cfg.db)]);
      }

      connected = true;
      reconnectAttempt = 0;
      return true;
    })()
      .catch((err) => {
        cleanupSocket(err);
        throw err;
      })
      .finally(() => {
        connectPromise = null;
      });

    return connectPromise;
  }

  async function command(args) {
    await ensureConnected();
    return sendRawOnSocket(socket, args);
  }

  async function ping() {
    try {
      const res = await command(['PING']);
      return res === 'PONG';
    } catch {
      return false;
    }
  }

  async function get(key) {
    return command(['GET', key]);
  }

  async function setEx(key, ttlSeconds, value) {
    const ttl = Math.max(1, Math.floor(Number(ttlSeconds) || 1));
    return command(['SET', key, value, 'EX', String(ttl)]);
  }

  async function incr(key) {
    return Number(await command(['INCR', key]));
  }

  async function expire(key, seconds) {
    return Number(await command(['EXPIRE', key, String(Math.max(1, Math.floor(seconds)))]));
  }

  async function pexpire(key, ms) {
    return Number(await command(['PEXPIRE', key, String(Math.max(1, Math.floor(ms)))]));
  }

  async function hincrby(key, field, increment = 1) {
    return Number(await command(['HINCRBY', key, field, String(Math.trunc(increment))]));
  }

  async function hgetall(key) {
    const arr = await command(['HGETALL', key]);
    if (!Array.isArray(arr)) return {};
    const out = {};
    for (let i = 0; i + 1 < arr.length; i += 2) {
      out[String(arr[i])] = String(arr[i + 1]);
    }
    return out;
  }

  function close() {
    closing = true;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    connected = false;
    if (socket) {
      socket.removeAllListeners();
      socket.destroy();
      socket = null;
    }
    rejectAllPending(new Error('Redis client closed'));
  }

  // Initiate warm background connect if configured so initial health checks reflect true status
  if (cfg && options.autoConnect !== false) {
    ensureConnected().catch(() => {});
  }

  return {
    isConfigured: () => Boolean(cfg),
    isConnected: () => Boolean(connected && socket && !socket.destroyed),
    ensureConnected,
    command,
    ping,
    get,
    setEx,
    incr,
    expire,
    pexpire,
    hincrby,
    hgetall,
    close
  };
}

let sharedClient = null;

function getSharedRedisClient() {
  if (!sharedClient) {
    sharedClient = createRedisClient(process.env.REDIS_URL || '');
  }
  return sharedClient;
}

module.exports = {
  createRedisClient,
  encodeRespCommand,
  getSharedRedisClient,
  parseRedisUrl,
  tryParseRespFrame
};

