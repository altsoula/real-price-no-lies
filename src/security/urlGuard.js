'use strict';

const dns = require('node:dns/promises');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const zlib = require('node:zlib');
const { sanitizeText, stripControlChars } = require('./sanitizer');

const MAX_URL_LENGTH = 2048;
const ALLOWED_PORTS = new Set(['', '80', '443']);
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata.google.internal',
  'metadata',
  'instance-data'
]);
const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.localdomain', '.arpa', '.home', '.lan'];
const TRACKING_QUERY_PARAMS = new Set([
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'utm_id',
  'fbclid',
  'gclid',
  'dclid',
  'msclkid',
  'mc_cid',
  'mc_eid',
  'ref',
  'ref_',
  'tag',
  'affid',
  'affiliate',
  'yclid',
  '_ga',
  '_gl',
  'spm',
  'psc',
  // Amazon & major store search/session tracking params
  'crid',
  'dib',
  'dib_tag',
  'keywords',
  'qid',
  'sprefix',
  'sr',
  'ufe',
  'th',
  'pd_rd_i',
  'pd_rd_r',
  'pd_rd_w',
  'pd_rd_wg',
  'pf_rd_i',
  'pf_rd_m',
  'pf_rd_p',
  'pf_rd_r',
  'pf_rd_s',
  'pf_rd_t',
  'linkcode',
  'camp',
  'creative',
  'creativeasin',
  'ascsubtag',
  'smid',
  'ie',
  'node',
  'content-id',
  'sbo'
]);

class UrlSecurityError extends Error {
  /**
   * @param {number} statusCode
   * @param {string} code
   * @param {string} message
   */
  constructor(statusCode, code, message) {
    super(message);
    this.name = 'UrlSecurityError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

/**
 * Checks whether an IPv4 dotted quad falls within private, loopback, link-local,
 * CGNAT, multicast, documentation, or reserved ranges.
 * @param {string} ipv4
 * @returns {boolean}
 */
function isPrivateIPv4(ipv4) {
  const parts = ipv4.split('.');
  if (parts.length !== 4) {
    return true;
  }
  const octets = parts.map((p) => Number(p));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }

  const [a, b, c] = octets;
  if (a === 0) return true; // 0.0.0.0/8 ("this" network)
  if (a === 10) return true; // 10.0.0.0/8 (RFC1918)
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT)
  if (a === 127) return true; // 127.0.0.0/8 (Loopback)
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 (Link-local & Cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 (RFC1918)
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24 (IETF protocol)
  if (a === 192 && b === 0 && c === 2) return true; // 192.0.2.0/24 (TEST-NET-1)
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 (RFC1918)
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 (Benchmarking)
  if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24 (TEST-NET-2)
  if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24 (TEST-NET-3)
  if (a >= 224) return true; // 224.0.0.0/4 Multicast & 240.0.0.0/4 Reserved/Broadcast
  return false;
}

/**
 * Expands a valid IPv6 string (without zone id) into 8 16-bit integer hextets.
 * Returns null if malformed.
 * @param {string} ipv6
 * @returns {number[] | null}
 */
function parseIPv6Hextets(ipv6) {
  let addr = ipv6.toLowerCase();
  const lastColon = addr.lastIndexOf(':');
  // Convert trailing embedded IPv4 (e.g. ::ffff:127.0.0.1) into two hextets.
  if (lastColon !== -1 && addr.slice(lastColon + 1).includes('.')) {
    const ipv4Part = addr.slice(lastColon + 1);
    if (net.isIPv4(ipv4Part) === false) {
      return null;
    }
    const octets = ipv4Part.split('.').map(Number);
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    addr = `${addr.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const doubleColonCount = addr.split('::').length - 1;
  if (doubleColonCount > 1) {
    return null;
  }

  let parts;
  if (doubleColonCount === 1) {
    const [leftRaw, rightRaw] = addr.split('::');
    const left = leftRaw ? leftRaw.split(':') : [];
    const right = rightRaw ? rightRaw.split(':') : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 1) {
      return null;
    }
    parts = [...left, ...new Array(missing).fill('0'), ...right];
  } else {
    parts = addr.split(':');
  }

  if (parts.length !== 8) {
    return null;
  }

  const hextets = [];
  for (const part of parts) {
    if (!/^[0-9a-f]{1,4}$/.test(part)) {
      return null;
    }
    hextets.push(parseInt(part, 16));
  }
  return hextets;
}

/**
 * Checks whether an IPv4 or IPv6 address is private, loopback, link-local,
 * cloud metadata, multicast, or otherwise unsafe for outbound SSRF-protected requests.
 * Fail-closed: invalid IPs return true.
 * @param {string} rawIp
 * @returns {boolean}
 */
function isPrivateOrReservedIP(rawIp) {
  if (typeof rawIp !== 'string' || !rawIp.trim()) {
    return true;
  }
  const ip = rawIp.trim().replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  const family = net.isIP(ip);
  if (family === 4) {
    return isPrivateIPv4(ip);
  }
  if (family !== 6) {
    return true;
  }

  const h = parseIPv6Hextets(ip);
  if (!h) {
    return true;
  }

  const isAllZeroPrefix = h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0;
  // Unspecified :: and Loopback ::1
  if (isAllZeroPrefix && h[5] === 0 && h[6] === 0 && (h[7] === 0 || h[7] === 1)) {
    return true;
  }
  // IPv4-mapped (::ffff:0:0/96) and IPv4-compatible (::/96)
  if (isAllZeroPrefix && (h[5] === 0xffff || h[5] === 0)) {
    const ipv4 = `${(h[6] >> 8) & 0xff}.${h[6] & 0xff}.${(h[7] >> 8) & 0xff}.${h[7] & 0xff}`;
    return isPrivateIPv4(ipv4);
  }
  // NAT64 well-known prefix 64:ff9b::/96 and 64:ff9b:1::/48
  if (h[0] === 0x0064 && h[1] === 0xff9b) {
    const ipv4 = `${(h[6] >> 8) & 0xff}.${h[6] & 0xff}.${(h[7] >> 8) & 0xff}.${h[7] & 0xff}`;
    return isPrivateIPv4(ipv4);
  }
  // Unique Local Addresses fc00::/7
  if ((h[0] & 0xfe00) === 0xfc00) return true;
  // Link-Local fe80::/10
  if ((h[0] & 0xffc0) === 0xfe80) return true;
  // Site-Local (deprecated) fec0::/10
  if ((h[0] & 0xffc0) === 0xfec0) return true;
  // Multicast ff00::/8
  if ((h[0] & 0xff00) === 0xff00) return true;
  // Documentation 2001:db8::/32
  if (h[0] === 0x2001 && h[1] === 0x0db8) return true;
  // Teredo 2001::/32
  if (h[0] === 0x2001 && h[1] === 0x0000) return true;
  // 6to4 2002::/16 (can tunnel private IPv4 in h[1..2])
  if (h[0] === 0x2002) {
    const ipv4 = `${(h[1] >> 8) & 0xff}.${h[1] & 0xff}.${(h[2] >> 8) & 0xff}.${h[2] & 0xff}`;
    if (isPrivateIPv4(ipv4)) return true;
  }

  return false;
}

/**
 * Validates that a hostname looks like a real public domain with a valid TLD.
 * @param {string} hostname
 * @returns {boolean}
 */
function hasValidPublicTld(hostname) {
  if (!hostname || hostname.length > 253) {
    return false;
  }
  const labels = hostname.split('.');
  if (labels.length < 2) {
    return false;
  }
  for (const label of labels) {
    if (!label || label.length > 63 || !/^[a-z0-9-]+$/.test(label)) {
      return false;
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return false;
    }
  }
  const tld = labels[labels.length - 1];
  return /^(?:[a-z]{2,63}|xn--[a-z0-9]{2,59})$/.test(tld);
}

/**
 * Validates, anti-SSRF checks, and normalizes a product URL.
 * @param {string} rawUrl
 * @param {{ resolveDns?: boolean, dnsTimeoutMs?: number }} [options]
 */
async function validateAndNormalizeProductUrl(rawUrl, options = {}) {
  const { resolveDns = true, dnsTimeoutMs = 1500 } = options;

  if (typeof rawUrl !== 'string') {
    throw new UrlSecurityError(400, 'INVALID_URL_TYPE', 'Product URL must be a string.');
  }

  const trimmed = rawUrl.trim();
  if (!trimmed) {
    throw new UrlSecurityError(400, 'EMPTY_URL', 'Please paste a product URL to inspect.');
  }
  if (trimmed.length > MAX_URL_LENGTH) {
    throw new UrlSecurityError(
      400,
      'URL_TOO_LONG',
      `Product URL exceeds maximum allowed length (${MAX_URL_LENGTH} chars).`
    );
  }
  if (stripControlChars(trimmed) !== trimmed || /[\s\\]/.test(trimmed)) {
    throw new UrlSecurityError(
      400,
      'UNSAFE_URL_CHARS',
      'URL contains invalid whitespace, backslashes, or control characters.'
    );
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new UrlSecurityError(
      400,
      'MALFORMED_URL',
      'Invalid URL format. Include https:// followed by the shop domain and product path.'
    );
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new UrlSecurityError(
      400,
      'FORBIDDEN_PROTOCOL',
      'Only public http:// and https:// product URLs are permitted.'
    );
  }

  if (parsed.username || parsed.password) {
    throw new UrlSecurityError(
      400,
      'FORBIDDEN_CREDENTIALS',
      'URLs containing embedded username or password credentials are blocked.'
    );
  }

  if (!ALLOWED_PORTS.has(parsed.port)) {
    throw new UrlSecurityError(
      400,
      'FORBIDDEN_PORT',
      'Non-standard network ports are blocked for security.'
    );
  }

  const hostname = parsed.hostname.replace(/\.+$/, '').toLowerCase();
  if (!hostname) {
    throw new UrlSecurityError(400, 'MISSING_HOST', 'URL hostname is missing.');
  }

  if (
    BLOCKED_HOSTNAMES.has(hostname) ||
    BLOCKED_SUFFIXES.some((suffix) => hostname.endsWith(suffix))
  ) {
    throw new UrlSecurityError(
      400,
      'SSRF_BLOCKED_HOST',
      'Internal, loopback, and local network hostnames are strictly blocked.'
    );
  }

  const strippedHost = hostname.replace(/^\[|\]$/g, '');
  const ipFamily = net.isIP(strippedHost);
  if (ipFamily !== 0) {
    if (isPrivateOrReservedIP(strippedHost)) {
      throw new UrlSecurityError(
        400,
        'SSRF_BLOCKED_IP',
        'Private, loopback, link-local, or reserved IP addresses are strictly blocked.'
      );
    }
  } else if (!hasValidPublicTld(hostname)) {
    throw new UrlSecurityError(
      400,
      'INVALID_DOMAIN',
      'URL must point to a valid public online store domain.'
    );
  }

  // Strip known affiliate/tracking query parameters and `/ref=...` path segments.
  let strippedTrackers = 0;
  for (const key of Array.from(parsed.searchParams.keys())) {
    if (TRACKING_QUERY_PARAMS.has(key.toLowerCase())) {
      parsed.searchParams.delete(key);
      strippedTrackers += 1;
    }
  }
  const refPathRegex = /\/ref=[^/]*(?=\/|$)/gi;
  const refMatches = parsed.pathname.match(refPathRegex);
  if (refMatches) {
    parsed.pathname = parsed.pathname.replace(refPathRegex, '') || '/';
    strippedTrackers += refMatches.length;
  }
  parsed.hash = '';

  let dnsVerified = false;
  /** @type {Array<{ address: string, family: number }>} */
  let verifiedIps = [];

  if (ipFamily !== 0) {
    dnsVerified = true;
    verifiedIps = [{ address: strippedHost, family: ipFamily }];
  } else if (resolveDns) {
    try {
      const lookupPromise = dns.lookup(hostname, { all: true, verbatim: true });
      const timeoutPromise = new Promise((_, reject) => {
        const timer = setTimeout(() => reject(new Error('DNS_TIMEOUT')), dnsTimeoutMs);
        timer.unref();
      });
      const records = await Promise.race([lookupPromise, timeoutPromise]);
      if (Array.isArray(records) && records.length > 0) {
        for (const rec of records) {
          if (isPrivateOrReservedIP(rec.address)) {
            throw new UrlSecurityError(
              400,
              'SSRF_DNS_REBINDING_BLOCKED',
              'Target domain resolved to a private or reserved IP address and was blocked.'
            );
          }
        }
        dnsVerified = true;
        verifiedIps = records.map((r) => ({ address: r.address, family: r.family }));
      }
    } catch (err) {
      if (err instanceof UrlSecurityError) {
        throw err;
      }
      // DNS unreachable (e.g., offline sandbox or transient resolver timeout):
      // Fail closed for outbound fetch while still permitting deterministic offline URL audit.
      dnsVerified = false;
      verifiedIps = [];
    }
  }

  return {
    normalizedUrl: parsed.toString(),
    protocol: parsed.protocol,
    hostname,
    pathname: parsed.pathname,
    search: parsed.search,
    strippedTrackers,
    dnsVerified,
    verifiedIps
  };
}

const GENERIC_STORE_TITLE_PATTERNS = [
  /^amazon(\.[a-z.]+)?$/i,
  /^mediamarkt(\.[a-z.]+)?$/i,
  /^saturn(\.[a-z.]+)?$/i,
  /^otto(\.[a-z.]+)?$/i,
  /^zalando(\.[a-z.]+)?$/i,
  /^ikea(\.[a-z.]+)?$/i,
  /^h&m(\.[a-z.]+)?$/i,
  /^just a moment/i,
  /^robot check/i,
  /^access denied/i,
  /^attention required/i
];

/**
 * Parses localized price strings like "222,00 €", "1.149,00 €", "£185.68", "$329.99" into a finite number.
 * @param {string} rawStr
 * @returns {number | null}
 */
function parseLocalizedPrice(rawStr) {
  if (typeof rawStr !== 'string') return null;
  const match = rawStr.replace(/\s+/g, ' ').match(/(\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?|\d+(?:[.,]\d{1,2})?)/);
  if (!match) return null;
  let numStr = match[1];
  const lastComma = numStr.lastIndexOf(',');
  const lastDot = numStr.lastIndexOf('.');
  if (lastComma !== -1 && lastDot !== -1) {
    if (lastComma > lastDot) {
      // European format: 1.149,00
      numStr = numStr.replace(/\./g, '').replace(',', '.');
    } else {
      // US/UK format: 1,149.00
      numStr = numStr.replace(/,/g, '');
    }
  } else if (lastComma !== -1) {
    const decimals = numStr.length - lastComma - 1;
    numStr = decimals === 2 || decimals === 1 ? numStr.replace(',', '.') : numStr.replace(/,/g, '');
  } else if (lastDot !== -1) {
    const decimals = numStr.length - lastDot - 1;
    if (decimals === 3 && numStr.length > 4) {
      numStr = numStr.replace(/\./g, '');
    }
  }
  const parsed = Number(numStr);
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed >= 1_000_000) {
    return null;
  }
  return Number(parsed.toFixed(2));
}

function cleanExtractedTitle(rawTitle) {
  if (!rawTitle) return null;
  let cleaned = sanitizeText(
    rawTitle
      .replace(/&amp;/g, '&')
      .replace(/&quot;/g, '"')
      .replace(/&#x27;/g, "'")
      .replace(/&#39;/g, "'"),
    180
  );
  // Remove trailing retailer suffix like ": Amazon.de...", " | MediaMarkt", " bei MediaMarkt"
  cleaned = cleaned
    .replace(/\s*(?:[:|-]|\bbei\b|\bin\b)\s*(?:Amazon\.[a-z.]+|MediaMarkt|SATURN|OTTO|Zalando|IKEA|H&M).*$/i, '')
    .replace(/\s+(?:jetzt\s+)?online\s+kaufen.*$/i, '')
    .trim();

  if (!cleaned || cleaned.length < 4) return null;
  if (GENERIC_STORE_TITLE_PATTERNS.some((rx) => rx.test(cleaned))) {
    return null;
  }
  return cleaned;
}

function isBotChallengeHtml(html) {
  if (!html) return true;
  if (
    /api-services-support@amazon\.|validateCaptcha|Robot Check|cf-browser-verification|Just a moment\.\.\.|window\.KPSDK/i.test(
      html
    )
  ) {
    return true;
  }
  return false;
}

/**
 * Extracts bounded plain-text title, price, currency, and brand clues from raw HTML.
 * Never executes scripts or parses unsafe DOM trees.
 * @param {string} html
 */
function extractFromOfferNode(offer, result) {
  if (!offer || typeof offer !== 'object') return;
  const offerObj = Array.isArray(offer) ? offer[0] : offer;
  if (!offerObj || typeof offerObj !== 'object') return;

  // Standard Offer.price / Offer.lowPrice
  const directPrice = parseLocalizedPrice(String(offerObj.price ?? offerObj.lowPrice ?? ''));
  if (!result.price && directPrice) {
    result.price = directPrice;
  }
  if (!result.currency && typeof offerObj.priceCurrency === 'string') {
    result.currency = sanitizeText(offerObj.priceCurrency, 3).toUpperCase();
  }

  // IKEA & European Schema.org Offer.priceSpecification array
  if (offerObj.priceSpecification) {
    const specs = Array.isArray(offerObj.priceSpecification)
      ? offerObj.priceSpecification
      : [offerObj.priceSpecification];
    for (const spec of specs) {
      if (!spec || typeof spec !== 'object') continue;
      const specPrice = parseLocalizedPrice(String(spec.price ?? ''));
      if (!specPrice) continue;
      const priceType = String(spec.priceType || '').toLowerCase();
      if (priceType.includes('strikethrough') || priceType.includes('listprice')) {
        if (!result.referencePrice) {
          result.referencePrice = specPrice;
        }
      } else if (!result.price) {
        result.price = specPrice;
      }
      if (!result.currency && typeof spec.priceCurrency === 'string') {
        result.currency = sanitizeText(spec.priceCurrency, 3).toUpperCase();
      }
    }
  }
}

function extractSafeMetadataFromHtml(html) {
  const result = {
    title: null,
    price: null,
    referencePrice: null,
    currency: null,
    brand: null,
    isBotChallenge: false
  };

  if (isBotChallengeHtml(html)) {
    result.isBotChallenge = true;
    return result;
  }

  // Amazon dedicated product title selector (takes precedence over generic <title>)
  const amazonTitleMatch = html.match(/id=["']productTitle["'][^>]*>([\s\S]{3,320}?)<\/span>/i);
  const ogTitleMatch = html.match(
    /<meta[^>]+(?:property|name)=["'](?:og:title|twitter:title)["'][^>]+content=["']([^"']{2,260})["']/i
  );
  const titleTagMatch = html.match(/<title[^>]*>([\s\S]{2,320}?)<\/title>/i);
  const rawTitle =
    (amazonTitleMatch && amazonTitleMatch[1]) ||
    (ogTitleMatch && ogTitleMatch[1]) ||
    (titleTagMatch && titleTagMatch[1]);
  result.title = cleanExtractedTitle(rawTitle);

  const metaPriceMatch = html.match(
    /<meta[^>]+(?:property|name)=["'](?:product:price:amount|og:price:amount)["'][^>]+content=["']([0-9.,]{1,20})["']/i
  );
  if (metaPriceMatch) {
    result.price = parseLocalizedPrice(metaPriceMatch[1]);
  }

  // Amazon corePriceDisplay / priceToPay selectors
  if (!result.price) {
    const coreIdx = html.indexOf('corePriceDisplay_desktop_feature_div');
    const priceScope = coreIdx !== -1 ? html.slice(coreIdx, coreIdx + 5000) : html;
    const payMatch =
      priceScope.match(/priceToPay[\s\S]{0,600}?class=["']a-offscreen["'][^>]*>([^<]{1,32})<\/span>/i) ||
      priceScope.match(/apexPriceToPay[\s\S]{0,400}?class=["']a-offscreen["'][^>]*>([^<]{1,32})<\/span>/i) ||
      priceScope.match(/class=["']a-offscreen["'][^>]*>([^<]{1,32})<\/span>/i);
    if (payMatch) {
      result.price = parseLocalizedPrice(payMatch[1]);
      if (/£|GBP/i.test(payMatch[1])) result.currency = 'GBP';
      else if (/(&euro;|€|EUR)/i.test(payMatch[1])) result.currency = 'EUR';
      else if (/\$/i.test(payMatch[1])) result.currency = 'USD';
    }
    const basisMatch = priceScope.match(
      /basisPrice[\s\S]{0,600}?class=["']a-offscreen["'][^>]*>([^<]{1,32})<\/span>/i
    );
    if (basisMatch) {
      result.referencePrice = parseLocalizedPrice(basisMatch[1]);
    }
  }

  if (!result.price) {
    const jsonPriceMatch = html.match(/"priceAmount"\s*:\s*([0-9]+(?:\.[0-9]{1,2})?)/);
    if (jsonPriceMatch) {
      result.price = parseLocalizedPrice(jsonPriceMatch[1]);
    }
  }

  const metaCurrMatch = html.match(
    /<meta[^>]+(?:property|name)=["'](?:product:price:currency|og:price:currency)["'][^>]+content=["']([A-Za-z]{3})["']/i
  );
  if (metaCurrMatch && !result.currency) {
    result.currency = metaCurrMatch[1].toUpperCase();
  }

  // Safely inspect bounded JSON-LD Product / ProductGroup blocks without executing anything.
  const ldBlocks = html.match(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]{1,250000}?)<\/script>/gi);
  if (ldBlocks) {
    for (const block of ldBlocks.slice(0, 6)) {
      const innerMatch = block.match(/>([\s\S]*)<\/script>/i);
      if (!innerMatch) continue;
      try {
        const data = JSON.parse(innerMatch[1]);
        const candidates = Array.isArray(data) ? data : data['@graph'] ? data['@graph'] : [data];
        for (const item of candidates) {
          if (!item || typeof item !== 'object') continue;
          const typeStr = String(item['@type'] || '').toLowerCase();
          if (typeStr.includes('product')) {
            if (!result.title && typeof item.name === 'string') {
              result.title = cleanExtractedTitle(item.name);
            }
            if (!result.brand && item.brand) {
              const brandName = typeof item.brand === 'string' ? item.brand : item.brand.name;
              if (typeof brandName === 'string') {
                result.brand = sanitizeText(brandName, 80);
              }
            }
            extractFromOfferNode(item.offers, result);

            // Zalando ProductGroup hasVariant inspection (pick lowest in-stock variant or first variant)
            if (!result.price && Array.isArray(item.hasVariant) && item.hasVariant.length > 0) {
              let bestVariantPrice = null;
              let bestCurrency = null;
              for (const variant of item.hasVariant.slice(0, 25)) {
                if (!variant || typeof variant !== 'object' || !variant.offers) continue;
                const tmp = { price: null, referencePrice: null, currency: null };
                extractFromOfferNode(variant.offers, tmp);
                if (!tmp.price) continue;
                const avail = String(variant.offers.availability || '').toLowerCase();
                const inStock = !avail || avail.includes('instock');
                if (inStock && (bestVariantPrice === null || tmp.price < bestVariantPrice)) {
                  bestVariantPrice = tmp.price;
                  bestCurrency = tmp.currency;
                }
              }
              if (bestVariantPrice !== null) {
                result.price = bestVariantPrice;
                if (!result.currency && bestCurrency) result.currency = bestCurrency;
              } else {
                extractFromOfferNode(item.hasVariant[0].offers, result);
              }
            }
          }
        }
      } catch {
        // Ignore malformed JSON-LD blocks safely.
      }
    }
  }

  return result;
}

/**
 * Performs a single SSRF-pinned HTTP/HTTPS GET with strict timeout and byte limit.
 */
function fetchWithPinnedIps(targetUrl, verifiedIps, timeoutMs, maxBytes) {
  return new Promise((resolve) => {
    const parsed = new URL(targetUrl);
    const transport = parsed.protocol === 'https:' ? https : http;
    const pinned = verifiedIps[0];

    const req = transport.request(
      targetUrl,
      {
        method: 'GET',
        timeout: timeoutMs,
        headers: {
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
          'Accept-Language': 'de-DE,de;q=0.9,en-GB;q=0.8,en;q=0.7',
          'Accept-Encoding': 'gzip, deflate, br',
          'Sec-Ch-Ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
          'Sec-Ch-Ua-Mobile': '?0',
          'Sec-Ch-Ua-Platform': '"Windows"',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'none',
          'Sec-Fetch-User': '?1',
          'Upgrade-Insecure-Requests': '1'
        },
        // Pin DNS resolution to the pre-verified public IP to prevent TOCTOU DNS rebinding.
        lookup: (_hostname, opts, cb) => {
          if (typeof opts === 'function') {
            opts(null, pinned.address, pinned.family);
            return;
          }
          if (opts && opts.all) {
            cb(null, [{ address: pinned.address, family: pinned.family }]);
            return;
          }
          cb(null, pinned.address, pinned.family);
        }
      },
      (res) => {
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400 && res.headers.location) {
          res.resume();
          resolve({ redirectLocation: res.headers.location, statusCode: status });
          return;
        }
        if (status < 200 || status >= 300) {
          res.resume();
          resolve({ ok: false, statusCode: status, reason: `HTTP ${status}` });
          return;
        }
        const ctype = String(res.headers['content-type'] || '').toLowerCase();
        if (ctype && !ctype.includes('text/html') && !ctype.includes('application/xhtml')) {
          res.resume();
          resolve({ ok: false, statusCode: status, reason: 'Non-HTML response skipped' });
          return;
        }

        const encoding = String(res.headers['content-encoding'] || '').toLowerCase().trim();
        let bodyStream = res;
        if (encoding === 'gzip' || encoding === 'x-gzip') {
          bodyStream = res.pipe(zlib.createGunzip({ finishFlush: zlib.constants.Z_SYNC_FLUSH }));
        } else if (encoding === 'br') {
          bodyStream = res.pipe(zlib.createBrotliDecompress());
        } else if (encoding === 'deflate') {
          bodyStream = res.pipe(zlib.createInflate());
        }

        const chunks = [];
        let received = 0;
        let done = false;
        const finish = () => {
          if (done) return;
          done = true;
          resolve({
            ok: true,
            statusCode: status,
            html: Buffer.concat(chunks).toString('utf8')
          });
        };

        bodyStream.on('data', (chunk) => {
          if (done) return;
          const remaining = maxBytes - received;
          if (remaining <= 0) {
            if (bodyStream !== res && typeof bodyStream.destroy === 'function') bodyStream.destroy();
            res.destroy();
            finish();
            return;
          }
          if (chunk.length > remaining) {
            chunks.push(chunk.subarray(0, remaining));
            received += remaining;
            if (bodyStream !== res && typeof bodyStream.destroy === 'function') bodyStream.destroy();
            res.destroy();
            finish();
          } else {
            chunks.push(chunk);
            received += chunk.length;
          }
        });
        bodyStream.on('end', finish);
        bodyStream.on('error', () => {
          if (done) return;
          if (received > 0) {
            finish();
            return;
          }
          done = true;
          resolve({ ok: false, reason: 'Stream error during inspection' });
        });
        res.on('error', () => {
          if (!done && received === 0) {
            done = true;
            resolve({ ok: false, reason: 'Response stream error' });
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, reason: 'Connection timed out' });
    });
    req.on('error', () => {
      resolve({ ok: false, reason: 'Network request blocked or unreachable' });
    });
    req.end();
  });
}

/**
 * Safely attempts to inspect lightweight product metadata from a validated public URL.
 * Validates any redirect hops against SSRF guards (max 2 hops) and bounds size & time.
 * @param {Awaited<ReturnType<typeof validateAndNormalizeProductUrl>>} urlInfo
 */
async function safeFetchProductSignals(urlInfo) {
  if (!urlInfo.dnsVerified || !urlInfo.verifiedIps || urlInfo.verifiedIps.length === 0) {
    return {
      liveFetched: false,
      reason: 'DNS resolution unavailable; analyzed via structural & historical index.'
    };
  }

  let currentInfo = urlInfo;
  for (let hop = 0; hop < 3; hop += 1) {
    const res = await fetchWithPinnedIps(
      currentInfo.normalizedUrl,
      currentInfo.verifiedIps,
      4500,
      3.5 * 1024 * 1024
    );

    if (res.redirectLocation) {
      try {
        const nextRaw = new URL(res.redirectLocation, currentInfo.normalizedUrl).toString();
        currentInfo = await validateAndNormalizeProductUrl(nextRaw, { resolveDns: true });
        if (!currentInfo.dnsVerified || currentInfo.verifiedIps.length === 0) {
          return { liveFetched: false, reason: 'Redirect target DNS unverified.' };
        }
        continue;
      } catch {
        return { liveFetched: false, reason: 'Redirect target rejected by SSRF policy.' };
      }
    }

    if (!res.ok) {
      return {
        liveFetched: false,
        reason: `Store returned ${res.reason || 'shielded response'}; falling back to live web price search.`
      };
    }

    const metadata = extractSafeMetadataFromHtml(res.html || '');
    if (metadata.isBotChallenge) {
      return {
        liveFetched: false,
        reason: 'Store bot-protection stub detected; falling back to live web price search.'
      };
    }

    return {
      liveFetched: true,
      finalUrl: currentInfo.normalizedUrl,
      metadata
    };
  }

  return { liveFetched: false, reason: 'Redirect limit exceeded.' };
}

module.exports = {
  UrlSecurityError,
  extractSafeMetadataFromHtml,
  isPrivateOrReservedIP,
  parseLocalizedPrice,
  safeFetchProductSignals,
  validateAndNormalizeProductUrl
};

