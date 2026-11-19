'use strict';

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { loadLocalEnv } = require('./config/env');
loadLocalEnv();

const { applySecurityHeaders } = require('./security/headers');
const { createRateLimiter, getClientIp } = require('./security/rateLimiter');
const { RequestValidationError, readSafeJsonBody } = require('./security/sanitizer');
const { UrlSecurityError } = require('./security/urlGuard');
const { QueueOverflowError } = require('./security/concurrencyQueue');
const { PRESET_BENCHMARKS } = require('./engine/retailerCatalog');
const { analysisCache, globalAnalysisQueue, runDeepDealAnalysis } = require('./engine/aiAgent');
const { getBudgetStats } = require('./engine/geminiBudgetGuard');

const PUBLIC_DIR = path.resolve(__dirname, '..', 'public');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8'
};

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    ...extraHeaders
  });
  res.end(body);
}

/**
 * Safely resolves a URL pathname into a file inside PUBLIC_DIR, preventing directory traversal.
 */
function resolveStaticFile(pathname) {
  let decodedPath;
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    return null;
  }

  if (decodedPath.includes('\0')) {
    return null;
  }

  const relativePath = decodedPath === '/' ? 'index.html' : decodedPath.replace(/^\/+/, '');
  if (!relativePath) {
    return path.join(PUBLIC_DIR, 'index.html');
  }

  const candidate = path.resolve(PUBLIC_DIR, relativePath);
  // Strict prefix boundary check prevents sibling-dir bypasses or `..` traversal
  if (candidate !== PUBLIC_DIR && !candidate.startsWith(PUBLIC_DIR + path.sep)) {
    return null;
  }
  return candidate;
}

/**
 * Creates the security-hardened HTTP server without binding immediately,
 * allowing both standalone execution and isolated test harnesses.
 */
function createAppServer(options = {}) {
  const defaultRateMax = Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 12;
  const rateLimiter = createRateLimiter({
    windowMs: options.rateLimitWindowMs || 60_000,
    maxRequests: options.rateLimitMaxRequests || defaultRateMax,
    maxTrackedIps: 5000
  });

  const server = http.createServer(async (req, res) => {
    const rawUrl = req.url || '/';
    // Reject obvious encoded/raw path traversal or backslash escapes before URL normalization
    if (/(?:\.\.|%2e|%5c|\\)/i.test(rawUrl.split('?')[0])) {
      applySecurityHeaders(req, res, { isApi: false });
      sendJson(res, 403, { error: 'FORBIDDEN_PATH', message: 'Forbidden path sequence.' });
      return;
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(rawUrl, 'http://localhost');
    } catch {
      applySecurityHeaders(req, res, { isApi: false });
      sendJson(res, 400, { error: 'MALFORMED_REQUEST_URI', message: 'Invalid request URL.' });
      return;
    }

    const pathname = parsedUrl.pathname;
    const isApiRoute = pathname.startsWith('/api/');
    applySecurityHeaders(req, res, { isApi: isApiRoute });

    try {
      // --- API: Health Check ---
      if (pathname === '/api/health') {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED', message: 'Use GET for /api/health.' });
          return;
        }
        sendJson(res, 200, {
          status: 'ok',
          service: 'realpricenolies',
          security: 'hardened',
          zeroPii: true,
          cache: {
            entries: analysisCache.size(),
            inFlight: analysisCache.inFlightSize()
          },
          concurrency: globalAnalysisQueue.stats(),
          geminiBudget: getBudgetStats(),
          timestamp: new Date().toISOString()
        });
        return;
      }

      // --- API: Instant Benchmark Presets ---
      if (pathname === '/api/presets') {
        if (req.method !== 'GET') {
          sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED', message: 'Use GET for /api/presets.' });
          return;
        }
        const presets = PRESET_BENCHMARKS.map((p) => ({
          id: p.id,
          label: p.label,
          retailerId: p.retailerId,
          url: p.url
        }));
        sendJson(res, 200, { presets });
        return;
      }

      // --- API: Deep Deal Price Analyzer ---
      if (pathname === '/api/analyze') {
        if (req.method !== 'POST') {
          sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED', message: 'Use POST for /api/analyze.' });
          return;
        }

        const ip = getClientIp(req);
        const quota = rateLimiter.consume(ip);
        res.setHeader('X-RateLimit-Limit', String(quota.limit));
        res.setHeader('X-RateLimit-Remaining', String(quota.remaining));
        res.setHeader('X-RateLimit-Reset', String(quota.resetEpochSec));

        if (!quota.allowed) {
          sendJson(
            res,
            429,
            {
              error: 'RATE_LIMIT_EXCEEDED',
              message: `Too many price checks. Please wait ${quota.retryAfterSec}s before trying again.`
            },
            { 'Retry-After': String(quota.retryAfterSec) }
          );
          return;
        }

        const body = await readSafeJsonBody(req, 4096);
        if (typeof body.url !== 'string') {
          sendJson(res, 400, {
            error: 'INVALID_INPUT',
            message: 'JSON body must include a string "url" field.'
          });
          return;
        }

        const analysis = await runDeepDealAnalysis(body.url);
        sendJson(res, 200, analysis);
        return;
      }

      if (isApiRoute) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'API endpoint not found.' });
        return;
      }

      // --- Static Assets ---
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Method Not Allowed');
        return;
      }

      const filePath = resolveStaticFile(pathname);
      if (!filePath) {
        res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Forbidden');
        return;
      }

      fs.stat(filePath, (statErr, stats) => {
        if (statErr || !stats.isFile()) {
          res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end('Not Found');
          return;
        }

        const ext = path.extname(filePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';
        const noCacheExt = ext === '.html' || ext === '.css' || ext === '.js';
        res.writeHead(200, {
          'Content-Type': contentType,
          'Content-Length': stats.size,
          'Cache-Control': noCacheExt ? 'no-cache, must-revalidate' : 'public, max-age=3600'
        });

        if (req.method === 'HEAD') {
          res.end();
          return;
        }

        const stream = fs.createReadStream(filePath);
        stream.on('error', () => {
          if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
          }
          res.end('Internal Server Error');
        });
        stream.pipe(res);
      });
    } catch (err) {
      if (err instanceof QueueOverflowError) {
        sendJson(
          res,
          err.statusCode,
          { error: err.code, message: err.message },
          { 'Retry-After': '5' }
        );
        return;
      }
      if (err instanceof RequestValidationError || err instanceof UrlSecurityError) {
        sendJson(res, err.statusCode, { error: err.code, message: err.message });
        return;
      }
      // Never leak stack traces or system paths to external clients
      sendJson(res, 500, {
        error: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred while analyzing the URL.'
      });
    }
  });

  // Harden socket timeouts against Slowloris while allowing grounded live search completion
  server.requestTimeout = 25_000;
  server.headersTimeout = 5_000;
  server.keepAliveTimeout = 5_000;

  return server;
}

if (require.main === module) {
  const isCloudEnv = Boolean(
    process.env.NODE_ENV === 'production' ||
      process.env.RENDER ||
      process.env.RAILWAY_ENVIRONMENT ||
      process.env.FLY_APP_NAME
  );
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || (isCloudEnv ? '0.0.0.0' : '127.0.0.1');
  const server = createAppServer();
  server.listen(port, host, () => {
    console.log(`RealPriceNoLies running securely at http://${host}:${port}`);
  });
}

module.exports = {
  PUBLIC_DIR,
  createAppServer,
  resolveStaticFile
};
