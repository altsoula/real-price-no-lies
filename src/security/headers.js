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
 * Reads optional third-party monetization & traffic analytics configuration from env vars.
 * Returns false for everything by default so CSP remains maximally strict until activated.
 */
function getActiveCspIntegrations() {
  const adsenseId = (process.env.ADSENSE_CLIENT_ID || '').trim();
  const cfAnalyticsToken = (process.env.CF_WEB_ANALYTICS_TOKEN || '').trim();
  const plausibleDomain = (process.env.PLAUSIBLE_DOMAIN || '').trim();
  const turnstileSite = (process.env.CF_TURNSTILE_SITE_KEY || '').trim();
  const turnstileSecret = (process.env.CF_TURNSTILE_SECRET_KEY || '').trim();

  return {
    adsenseEnabled: /^ca-pub-\d{10,20}$/.test(adsenseId),
    cfAnalyticsEnabled: Boolean(cfAnalyticsToken),
    plausibleEnabled: Boolean(plausibleDomain),
    turnstileEnabled: Boolean(turnstileSite && turnstileSecret)
  };
}

/**
 * Builds the Content-Security-Policy header value.
 * Remains locked to `script-src 'self'` unless AdSense, Cloudflare Analytics/Turnstile,
 * or Plausible is explicitly configured via environment variables.
 */
function buildCspHeader(isHttps) {
  const integrations = getActiveCspIntegrations();

  const scriptSrc = ["'self'"];
  const imgSrc = ["'self'", 'data:'];
  const connectSrc = ["'self'"];
  const frameSrc = [];

  if (integrations.adsenseEnabled) {
    scriptSrc.push(
      "'unsafe-inline'",
      'https://pagead2.googlesyndication.com',
      'https://www.googletagservices.com',
      'https://adservice.google.com',
      'https://ep2.adtrafficquality.google',
      'https://fundingchoicesmessages.google.com'
    );
    imgSrc.push('https:');
    connectSrc.push(
      'https://pagead2.googlesyndication.com',
      'https://ep1.adtrafficquality.google',
      'https://csi.gstatic.com',
      'https://googleads.g.doubleclick.net'
    );
    frameSrc.push(
      'https://googleads.g.doubleclick.net',
      'https://tpc.googlesyndication.com',
      'https://ep2.adtrafficquality.google',
      'https://www.google.com'
    );
  }

  if (integrations.cfAnalyticsEnabled) {
    scriptSrc.push('https://static.cloudflareinsights.com');
    connectSrc.push('https://cloudflareinsights.com');
  }

  if (integrations.plausibleEnabled) {
    scriptSrc.push('https://plausible.io');
    connectSrc.push('https://plausible.io');
  }

  if (integrations.turnstileEnabled) {
    scriptSrc.push('https://challenges.cloudflare.com');
    connectSrc.push('https://challenges.cloudflare.com');
    frameSrc.push('https://challenges.cloudflare.com');
  }

  const directives = [
    "default-src 'self'",
    `script-src ${scriptSrc.join(' ')}`,
    "style-src 'self' 'unsafe-inline'",
    `img-src ${imgSrc.join(' ')}`,
    "font-src 'self'",
    `connect-src ${connectSrc.join(' ')}`,
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'"
  ];

  if (frameSrc.length > 0) {
    directives.push(`frame-src ${frameSrc.join(' ')}`);
  }

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
  const integrations = getActiveCspIntegrations();

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
  res.setHeader(
    'Cross-Origin-Resource-Policy',
    integrations.adsenseEnabled || integrations.turnstileEnabled ? 'cross-origin' : 'same-origin'
  );
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
  getActiveCspIntegrations,
  isHttpsRequest
};
