'use strict';

const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');
const { loadLocalEnv } = require('./config/env');
loadLocalEnv();

const { applySecurityHeaders } = require('./security/headers');
const { createRateLimiter, getClientIp } = require('./security/rateLimiter');
const { RequestValidationError, readSafeJsonBody, sanitizeText } = require('./security/sanitizer');
const { UrlSecurityError } = require('./security/urlGuard');
const { QueueOverflowError } = require('./security/concurrencyQueue');
const { PRESET_BENCHMARKS } = require('./engine/retailerCatalog');
const { analysisCache, globalAnalysisQueue, runDeepDealAnalysis } = require('./engine/aiAgent');
const { getBudgetStatsAsync } = require('./engine/geminiBudgetGuard');
const { hasActiveAffiliatePartners } = require('./engine/affiliateLinks');
const { getSharedRedisClient } = require('./storage/redisClient');
const { getPublicTrafficStats, recordPageView } = require('./storage/trafficMetrics');

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

function getValidAdsenseClientId() {
  const id = (process.env.ADSENSE_CLIENT_ID || '').trim();
  return /^ca-pub-\d{10,20}$/.test(id) ? id : '';
}

function parseDirectCampaignsEnv() {
  const raw = (process.env.DIRECT_CAMPAIGNS_JSON || '').trim();
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const cleaned = {};
    for (const slot of ['top-leaderboard', 'in-report-native', 'footer-leaderboard']) {
      const c = parsed[slot];
      if (!c || typeof c !== 'object' || !c.enabled) continue;
      let targetUrl = '';
      try {
        const u = new URL(String(c.targetUrl || '').trim());
        if (u.protocol === 'https:') targetUrl = u.toString();
      } catch {
        targetUrl = '';
      }
      if (!targetUrl) continue;
      cleaned[slot] = {
        enabled: true,
        sponsorName: sanitizeText(c.sponsorName || 'SPONSOR', 40),
        headline: sanitizeText(c.headline || '', 120),
        description: sanitizeText(c.description || '', 220),
        ctaText: sanitizeText(c.ctaText || 'Learn More', 32),
        targetUrl
      };
    }
    return Object.keys(cleaned).length > 0 ? cleaned : null;
  } catch {
    return null;
  }
}

function buildPublicConfigPayload() {
  const adsenseClientId = getValidAdsenseClientId();
  const directCampaigns = parseDirectCampaignsEnv();
  const cfSiteKey = (process.env.CF_TURNSTILE_SITE_KEY || '').trim();
  const cfSecretKey = (process.env.CF_TURNSTILE_SECRET_KEY || '').trim();

  return {
    adsenseClientId,
    adsenseSlots: {
      'top-leaderboard': (process.env.ADSENSE_SLOT_TOP || '').trim(),
      'in-report-native': (process.env.ADSENSE_SLOT_NATIVE || '').trim(),
      'footer-leaderboard': (process.env.ADSENSE_SLOT_FOOTER || '').trim()
    },
    directCampaigns,
    cfWebAnalyticsToken: (process.env.CF_WEB_ANALYTICS_TOKEN || '').trim(),
    plausibleDomain: (process.env.PLAUSIBLE_DOMAIN || '').trim(),
    turnstileSiteKey: cfSiteKey && cfSecretKey ? cfSiteKey : '',
    affiliateDisclosureActive: hasActiveAffiliatePartners()
  };
}

function buildAdsTxtBody() {
  const custom = (process.env.ADS_TXT_CONTENT || '').trim();
  if (custom) {
    return `${custom}\n`;
  }
  const clientId = getValidAdsenseClientId();
  if (clientId) {
    const pubId = clientId.replace(/^ca-/, '');
    return `google.com, ${pubId}, DIRECT, f08c47fec0942fa0\n`;
  }
  return '# realpricenolies.online ads.txt - configure ADSENSE_CLIENT_ID in environment variables to publish authorized sellers\n';
}

/**
 * Validates the decoded response payload returned by Cloudflare Turnstile /siteverify.
 * Checks success, expected action ('analyze'), and optional CF_TURNSTILE_HOSTNAMES allowlist.
 */
function validateTurnstilePayload(data) {
  if (!data || data.success !== true) return false;
  if (data.action !== 'analyze') return false;
  const allowedRaw = (process.env.CF_TURNSTILE_HOSTNAMES || '').trim();
  if (allowedRaw) {
    const allowedHostnames = new Set(
      allowedRaw
        .split(',')
        .map((h) => h.trim().toLowerCase())
        .filter(Boolean)
    );
    if (allowedHostnames.size > 0 && !allowedHostnames.has(String(data.hostname || '').toLowerCase())) {
      return false;
    }
  }
  return true;
}

/**
 * Verifies an optional Cloudflare Turnstile challenge token when Turnstile is enabled.
 */
function verifyTurnstileToken(token, remoteIp) {
  const secret = (process.env.CF_TURNSTILE_SECRET_KEY || '').trim();
  if (!secret) return Promise.resolve(true);
  if (typeof token !== 'string' || !token.trim() || token.length > 2048) {
    return Promise.resolve(false);
  }

  const form = new URLSearchParams({
    secret,
    response: token.trim(),
    remoteip: String(remoteIp || '')
  }).toString();

  return new Promise((resolve) => {
    const req = https.request(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        method: 'POST',
        timeout: 4000,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(form)
        }
      },
      (res) => {
        if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          resolve(false);
          return;
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            resolve(validateTurnstilePayload(data));
          } catch {
            resolve(false);
          }
        });
      }
    );
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.on('error', () => resolve(false));
    req.write(form);
    req.end();
  });
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
  const redisClient = options.redisClient !== undefined ? options.redisClient : getSharedRedisClient();
  const rateLimiter = createRateLimiter({
    windowMs: options.rateLimitWindowMs || 60_000,
    maxRequests: options.rateLimitMaxRequests || defaultRateMax,
    maxTrackedIps: 5000,
    redisClient
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
        const [geminiBudget, traffic] = await Promise.all([
          getBudgetStatsAsync(),
          getPublicTrafficStats()
        ]);
        sendJson(res, 200, {
          status: 'ok',
          service: 'realpricenolies',
          security: 'hardened',
          zeroPii: true,
          redis: {
            configured: Boolean(redisClient && redisClient.isConfigured()),
            connected: Boolean(redisClient && redisClient.isConnected())
          },
          cache: {
            entries: analysisCache.size(),
            inFlight: analysisCache.inFlightSize(),
            ttlHours: analysisCache.ttlHours
          },
          concurrency: globalAnalysisQueue.stats(),
          geminiBudget,
          traffic,
          timestamp: new Date().toISOString()
        });
        return;
      }

      // --- API: Aggregate Proof-of-Traffic Counters (Zero PII) ---
      if (pathname === '/api/stats') {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED', message: 'Use GET for /api/stats.' });
          return;
        }
        const stats = await getPublicTrafficStats();
        sendJson(res, 200, {
          status: 'ok',
          service: 'realpricenolies',
          zeroPii: true,
          ...stats
        });
        return;
      }

      // --- API: Safe Public Frontend Config (AdSense / Turnstile / Analytics / Affiliate Disclosure) ---
      if (pathname === '/api/public-config') {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED', message: 'Use GET for /api/public-config.' });
          return;
        }
        sendJson(res, 200, buildPublicConfigPayload());
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
        const quota = await rateLimiter.consumeAsync(ip);
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

        const cfSiteKey = (process.env.CF_TURNSTILE_SITE_KEY || '').trim();
        const cfSecretKey = (process.env.CF_TURNSTILE_SECRET_KEY || '').trim();
        if (cfSiteKey && cfSecretKey) {
          const okTurnstile = await verifyTurnstileToken(body.turnstileToken, ip);
          if (!okTurnstile) {
            sendJson(res, 403, {
              error: 'TURNSTILE_VERIFICATION_FAILED',
              message: 'Please complete the quick browser verification check before inspecting this URL.'
            });
            return;
          }
        }

        const analysis = await runDeepDealAnalysis(body.url);
        sendJson(res, 200, analysis);
        return;
      }

      if (isApiRoute) {
        sendJson(res, 404, { error: 'NOT_FOUND', message: 'API endpoint not found.' });
        return;
      }

      // --- AdSense / Programmatic Ads Authorization File ---
      if (pathname === '/ads.txt') {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end('Method Not Allowed');
          return;
        }
        const adsTxt = buildAdsTxtBody();
        res.writeHead(200, {
          'Content-Type': 'text/plain; charset=utf-8',
          'Content-Length': Buffer.byteLength(adsTxt),
          'Cache-Control': 'public, max-age=3600'
        });
        if (req.method === 'HEAD') {
          res.end();
          return;
        }
        res.end(adsTxt);
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

        if (ext === '.html' && req.method === 'GET') {
          recordPageView().catch(() => {});
        }

        const adsenseId = ext === '.html' ? getValidAdsenseClientId() : '';
        if (adsenseId) {
          fs.readFile(filePath, 'utf8', (readErr, html) => {
            if (readErr) {
              if (!res.headersSent) {
                res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
              }
              res.end('Internal Server Error');
              return;
            }
            const metaTag = `  <meta name="google-adsense-account" content="${adsenseId}">\n</head>`;
            const finalHtml = html.includes('</head>') ? html.replace('</head>', metaTag) : html;
            const buf = Buffer.from(finalHtml, 'utf8');
            res.writeHead(200, {
              'Content-Type': contentType,
              'Content-Length': buf.length,
              'Cache-Control': 'no-cache, must-revalidate'
            });
            if (req.method === 'HEAD') {
              res.end();
              return;
            }
            res.end(buf);
          });
          return;
        }

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

  // Harden socket timeouts against Slowloris while allowing multi-store live verification completion
  server.requestTimeout = 45_000;
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
  buildAdsTxtBody,
  buildPublicConfigPayload,
  createAppServer,
  resolveStaticFile,
  validateTurnstilePayload
};
