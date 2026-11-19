'use strict';

/**
 * Determines whether the incoming request arrived over TLS (or a trusted TLS-terminating proxy).
 * Used to avoid breaking local plain-HTTP development servers with `upgrade-insecure-requests`.
 */
function isHttpsRequest(req) {
  if (process.env.FORCE_HTTPS === 'true') {
    return true;
  }
  if (req && req.socket && req.socket.encrypted) {
    return true;
  }
  const forwardedProto = req && req.headers && req.headers['x-forwarded-proto'];
  if (typeof forwardedProto === 'string') {
    return forwardedProto.split(',')[0].trim().toLowerCase() === 'https';
  }
  return false;
}

/**
 * Builds the strict Content-Security-Policy header value.
 */
function buildCspHeader(isHttps) {
  const directives = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'"
  ];

  if (isHttps) {
    directives.push('upgrade-insecure-requests');
  }

  return directives.join('; ');
}

/**
 * Applies defense-in-depth HTTP security headers to every response.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {{ isApi?: boolean }} [options]
 */
function applySecurityHeaders(req, res, options = {}) {
  const isHttps = isHttpsRequest(req);

  res.setHeader('Content-Security-Policy', buildCspHeader(isHttps));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  // Strict no-referrer guarantees product URLs analyzed by users are never leaked externally.
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()'
  );
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('X-Download-Options', 'noopen');

  if (options.isApi) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
  }
}

module.exports = {
  applySecurityHeaders,
  buildCspHeader,
  isHttpsRequest
};

