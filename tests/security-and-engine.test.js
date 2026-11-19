'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');

const { createAppServer } = require('../src/server');
const {
  buildScraperProxyEndpoint,
  extractSafeMetadataFromHtml,
  isPrivateOrReservedIP,
  validateAndNormalizeProductUrl
} = require('../src/security/urlGuard');
const { escapeHtml, hasPrototypePollution } = require('../src/security/sanitizer');
const { buildCspHeader } = require('../src/security/headers');
const { getClientIp, createRateLimiter } = require('../src/security/rateLimiter');
const { PRESET_BENCHMARKS } = require('../src/engine/retailerCatalog');
const { extractJsonObject, normalizeGroundedData } = require('../src/engine/geminiGroundedSearch');
const { createConcurrencyQueue, QueueOverflowError } = require('../src/security/concurrencyQueue');
const { createGeminiBudgetGuard } = require('../src/engine/geminiBudgetGuard');
const { createAnalysisCache } = require('../src/engine/analysisCache');
const { analysisCache, runDeepDealAnalysis } = require('../src/engine/aiAgent');
const { analyzeProductPricing } = require('../src/engine/priceIntelligence');
const { buildMerchantOfferLink } = require('../src/engine/affiliateLinks');
const { createRedisClient } = require('../src/storage/redisClient');
const { createTrafficMetrics } = require('../src/storage/trafficMetrics');

function startTestServer(options = {}) {
  return new Promise((resolve, reject) => {
    const server = createAppServer(options);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        server,
        baseUrl: `http://127.0.0.1:${addr.port}`
      });
    });
    server.on('error', reject);
  });
}

function stopTestServer(server) {
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
}

function httpRequestRaw(baseUrl, method, pathStr, bodyStr = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(baseUrl);
    const req = http.request(
      {
        hostname: target.hostname,
        port: target.port,
        path: pathStr,
        method,
        headers: {
          ...(bodyStr !== null ? { 'Content-Length': Buffer.byteLength(bodyStr) } : {}),
          ...headers
        }
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8')
          });
        });
      }
    );
    req.on('error', reject);
    if (bodyStr !== null) {
      req.write(bodyStr);
    }
    req.end();
  });
}

test('Unit: IPv4/IPv6 SSRF private and reserved range detection', () => {
  const blockedIps = [
    '127.0.0.1',
    '127.255.0.1',
    '10.0.0.1',
    '172.16.0.1',
    '172.31.255.254',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '0.0.0.0',
    '224.0.0.1',
    '255.255.255.255',
    '::1',
    '::',
    '::ffff:127.0.0.1',
    '::ffff:169.254.169.254',
    'fe80::1',
    'fc00::1',
    'fd12:3456:789a::1',
    'not-an-ip'
  ];
  for (const ip of blockedIps) {
    assert.equal(isPrivateOrReservedIP(ip), true, `Expected ${ip} to be blocked`);
  }

  const publicIps = ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111'];
  for (const ip of publicIps) {
    assert.equal(isPrivateOrReservedIP(ip), false, `Expected ${ip} to be allowed as public`);
  }
});

test('Unit: Prototype pollution and HTML escaping sanitization', () => {
  const polluted = JSON.parse('{"__proto__": {"isAdmin": true}, "url": "https://example.com"}');
  assert.equal(hasPrototypePollution(polluted), true);

  const nestedPolluted = JSON.parse('{"nested": {"constructor": {"prototype": {"x": 1}}}}');
  assert.equal(hasPrototypePollution(nestedPolluted), true);

  assert.equal(hasPrototypePollution({ url: 'https://amazon.de/dp/B09Y2MYL5C' }), false);

  const escaped = escapeHtml('<script>alert("xss")</script>');
  assert.equal(escaped.includes('<'), false);
  assert.equal(escaped.includes('>'), false);

  const meta = extractSafeMetadataFromHtml(
    '<html><head><title>Sony Headphones\u0000\u0007</title><meta property="product:price:amount" content="279.00"></head></html>'
  );
  assert.equal(meta.title, 'Sony Headphones');
  assert.equal(meta.price, 279);
});

test('Unit: Tracker parameter stripping & URL normalization', async () => {
  const info = await validateAndNormalizeProductUrl(
    'https://www.amazon.de/dp/B09Y2MYL5C?utm_source=evil&fbclid=123&gclid=456&tag=bad-21&psc=1&keep=true',
    { resolveDns: false }
  );
  assert.equal(info.strippedTrackers, 5);
  assert.equal(info.normalizedUrl, 'https://www.amazon.de/dp/B09Y2MYL5C?keep=true');
});

test('HTTP Security: Strict headers, SSRF blocking, prototype pollution, oversized payloads, and path traversal', async () => {
  const { server, baseUrl } = await startTestServer({ rateLimitMaxRequests: 100 });
  try {
    // 1. Check homepage & security headers
    const home = await httpRequestRaw(baseUrl, 'GET', '/');
    assert.equal(home.statusCode, 200);
    assert.match(home.headers['content-security-policy'], /default-src 'self'/);
    assert.match(home.headers['content-security-policy'], /script-src 'self'/);
    assert.match(home.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal(home.headers['x-frame-options'], 'DENY');
    assert.equal(home.headers['x-content-type-options'], 'nosniff');
    assert.equal(home.headers['referrer-policy'], 'no-referrer');

    // 2. Check static assets load cleanly
    const appJs = await httpRequestRaw(baseUrl, 'GET', '/app.js');
    assert.equal(appJs.statusCode, 200);
    const cookieJs = await httpRequestRaw(baseUrl, 'GET', '/cookie-Consent.js');
    assert.equal(cookieJs.statusCode, 200);

    // 3. Path traversal rejection
    const traversal1 = await httpRequestRaw(baseUrl, 'GET', '/%2e%2e/package.json');
    assert.equal(traversal1.statusCode, 403);
    const traversal2 = await httpRequestRaw(baseUrl, 'GET', '/..%2fsrc%2fserver.js');
    assert.equal(traversal2.statusCode, 403);

    // 4. SSRF vectors must all be rejected with 400
    const ssrfVectors = [
      'http://127.0.0.1/admin',
      'http://localhost:8080/secret',
      'http://169.254.169.254/latest/meta-data/',
      'http://[::1]/',
      'http://10.0.0.5/',
      'http://192.168.1.1/',
      'http://[::ffff:127.0.0.1]/',
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://shop.internal/item',
      'file:///etc/passwd',
      'javascript:alert(1)',
      'https://admin:secret@www.amazon.de/dp/B09Y2MYL5C',
      'https://www.amazon.de:6379/dp/B09Y2MYL5C'
    ];

    for (const badUrl of ssrfVectors) {
      const res = await httpRequestRaw(
        baseUrl,
        'POST',
        '/api/analyze',
        JSON.stringify({ url: badUrl }),
        { 'Content-Type': 'application/json' }
      );
      assert.equal(res.statusCode, 400, `Expected SSRF/bad URL to be blocked (400): ${badUrl}`);
      assert.match(res.headers['cache-control'], /no-store/);
    }

    // 5. Prototype pollution rejection
    const protoRes = await httpRequestRaw(
      baseUrl,
      'POST',
      '/api/analyze',
      '{"__proto__":{"polluted":true},"url":"https://www.amazon.de/dp/B09Y2MYL5C"}',
      { 'Content-Type': 'application/json' }
    );
    assert.equal(protoRes.statusCode, 400);
    assert.match(protoRes.body, /PROTOTYPE_POLLUTION_BLOCKED/);

    // 6. Oversized payload rejection (> 4096 bytes)
    const bigBody = JSON.stringify({ url: `https://www.amazon.de/${'a'.repeat(4200)}` });
    const bigRes = await httpRequestRaw(baseUrl, 'POST', '/api/analyze', bigBody, {
      'Content-Type': 'application/json'
    });
    assert.equal(bigRes.statusCode, 413);

    // 7. Unsupported Content-Type rejection
    const wrongType = await httpRequestRaw(
      baseUrl,
      'POST',
      '/api/analyze',
      'url=https://www.amazon.de/dp/B09Y2MYL5C',
      { 'Content-Type': 'text/plain' }
    );
    assert.equal(wrongType.statusCode, 415);
  } finally {
    await stopTestServer(server);
  }
});

test('HTTP Rate Limiter blocks excessive burst requests with 429', async () => {
  const { server, baseUrl } = await startTestServer({ rateLimitMaxRequests: 2 });
  try {
    const payload = JSON.stringify({ url: 'https://www.ikea.com/de/de/p/markus-drehstuhl-70261150/' });
    const r1 = await httpRequestRaw(baseUrl, 'POST', '/api/analyze', payload, {
      'Content-Type': 'application/json'
    });
    const r2 = await httpRequestRaw(baseUrl, 'POST', '/api/analyze', payload, {
      'Content-Type': 'application/json'
    });
    const r3 = await httpRequestRaw(baseUrl, 'POST', '/api/analyze', payload, {
      'Content-Type': 'application/json'
    });

    assert.equal(r1.statusCode, 200);
    assert.equal(r2.statusCode, 200);
    assert.equal(r3.statusCode, 429);
    assert.ok(r3.headers['retry-after']);
  } finally {
    await stopTestServer(server);
  }
});

test('Deal Truth Engine: analyzes flagship retailers (Amazon, MediaMarkt, Saturn, IKEA, Otto, Zalando, H&M) & arbitrary shops', async () => {
  const { server, baseUrl } = await startTestServer({ rateLimitMaxRequests: 50 });
  try {
    const urlsToTest = [
      ...PRESET_BENCHMARKS.map((p) => p.url),
      'https://www.galaxus.de/de/s1/product/logitech-mx-master-3s-maus-21192499?utm_source=newsletter&fbclid=xyz123',
      'https://www.unknown-boutique-shop.com/products/mechanical-keyboard-pro-991122'
    ];

    for (const targetUrl of urlsToTest) {
      const res = await httpRequestRaw(
        baseUrl,
        'POST',
        '/api/analyze',
        JSON.stringify({ url: targetUrl }),
        { 'Content-Type': 'application/json' }
      );
      assert.equal(res.statusCode, 200, `Expected 200 for ${targetUrl}, got ${res.statusCode}: ${res.body}`);
      const data = JSON.parse(res.body);

      assert.equal(data.zeroPiiMode, true);
      assert.ok(typeof data.product.title === 'string' && data.product.title.length > 0);
      assert.ok(typeof data.product.retailerName === 'string' && data.product.retailerName.length > 0);

      // Score invariants
      assert.equal(typeof data.scoring.dealScore, 'number');
      assert.ok(data.scoring.dealScore >= 0 && data.scoring.dealScore <= 100);
      assert.equal(data.scoring.breakdown.length, 4);
      const sum = data.scoring.breakdown.reduce((acc, b) => acc + b.score, 0);
      assert.equal(sum, data.scoring.dealScore);

      // Chart series, 30/90/180-day comparisons & cross-retailer invariants
      assert.equal(data.priceHistory.length, 26);
      assert.ok(data.priceHistory.filter((p) => p.daysAgo <= 30).length >= 8);
      assert.ok(data.pricing.windowComparisons && data.pricing.windowComparisons.days30);
      assert.ok(data.pricing.windowComparisons.days90 && data.pricing.windowComparisons.days180);
      assert.ok(typeof data.pricing.windowComparisons.days30.ownSellerAvg === 'number');
      assert.ok(typeof data.pricing.windowComparisons.days30.competitorLow === 'number');
      assert.ok(Array.isArray(data.competitors) && data.competitors.length >= 1);
      assert.ok(Array.isArray(data.intelSources) && data.intelSources.length === 5);

      // Mandatory AI accuracy disclaimer
      assert.match(data.aiDisclaimer, /AI/i);
      assert.match(data.aiDisclaimer, /mistakes/i);
    }

    // Verify presets endpoint
    const presetsRes = await httpRequestRaw(baseUrl, 'GET', '/api/presets');
    assert.equal(presetsRes.statusCode, 200);
    const presetsData = JSON.parse(presetsRes.body);
    assert.equal(presetsData.presets.length, 7);

    // Verify .env is completely unreachable via HTTP
    const envAttempt1 = await httpRequestRaw(baseUrl, 'GET', '/.env');
    assert.equal(envAttempt1.statusCode, 404);
    const envAttempt2 = await httpRequestRaw(baseUrl, 'GET', '/%2e%2e/.env');
    assert.equal(envAttempt2.statusCode, 403);
  } finally {
    await stopTestServer(server);
  }
});

test('Real-world Amazon URL parsing, IKEA/Zalando/Otto extractors, bot-shield immunity & secret safety', async () => {
  const botStub =
    '<!DOCTYPE html><html><head><title dir="ltr">Amazon.de</title></head><body><!-- api-services-support@amazon.com --></body></html>';
  const botMeta = extractSafeMetadataFromHtml(botStub);
  assert.equal(botMeta.isBotChallenge, true);
  assert.equal(botMeta.title, null);

  // Kasada bot shield (Otto)
  const kasadaStub = '<!DOCTYPE html><html><body><script>window.KPSDK={};</script></body></html>';
  assert.equal(extractSafeMetadataFromHtml(kasadaStub).isBotChallenge, true);

  // IKEA UnitPriceSpecification JSON-LD extractor
  const ikeaHtml = `<html><head><script type="application/ld+json">${JSON.stringify({
    '@type': 'Product',
    name: 'KALLAX Regal',
    brand: { name: 'IKEA' },
    offers: {
      '@type': 'Offer',
      priceSpecification: [
        { '@type': 'UnitPriceSpecification', price: '49.99', priceCurrency: 'EUR' },
        { '@type': 'UnitPriceSpecification', price: '59.99', priceCurrency: 'EUR', priceType: 'https://schema.org/StrikethroughPrice' }
      ]
    }
  })}</script></head></html>`;
  const ikeaMeta = extractSafeMetadataFromHtml(ikeaHtml);
  assert.equal(ikeaMeta.price, 49.99);
  assert.equal(ikeaMeta.referencePrice, 59.99);
  assert.equal(ikeaMeta.currency, 'EUR');

  // Zalando ProductGroup hasVariant JSON-LD extractor
  const zalandoHtml = `<html><head><script type="application/ld+json">${JSON.stringify([
    {
      '@type': 'ProductGroup',
      name: 'AIR FORCE 1',
      brand: { name: 'Nike' },
      hasVariant: [
        { '@type': 'Product', offers: { price: '107.95', priceCurrency: 'EUR', availability: 'https://schema.org/InStock' } }
      ]
    }
  ])}</script></head></html>`;
  const zalandoMeta = extractSafeMetadataFromHtml(zalandoHtml);
  assert.equal(zalandoMeta.price, 107.95);
  assert.equal(zalandoMeta.currency, 'EUR');

  const { server, baseUrl } = await startTestServer({ rateLimitMaxRequests: 50 });
  try {
    const amazonRealUrl =
      'https://www.amazon.de/-/en/Sony-WF-1000XM6-Cancelling-Headphones-silver/dp/B0GFB2WX82/ref=sr_1_16?crid=K0HD1BTOYYT6&dib=eyJ2IjoiMSJ9.abc&dib_tag=se&keywords=sony+wh-1000xm5&qid=1794854735&sprefix=Sony&sr=8-16&ufe=app_do&th=1';
    const res = await httpRequestRaw(
      baseUrl,
      'POST',
      '/api/analyze',
      JSON.stringify({ url: amazonRealUrl }),
      { 'Content-Type': 'application/json' }
    );
    assert.equal(res.statusCode, 200);
    const data = JSON.parse(res.body);

    // Must never collapse product title to generic "Amazon"
    assert.match(data.product.title, /Sony.*WF-1000XM6/i);
    assert.notEqual(data.product.title.trim().toLowerCase(), 'amazon');
    assert.equal(data.product.sku, 'B0GFB2WX82');
    assert.equal(data.product.category, 'Consumer Electronics & Audio');
    assert.ok(data.product.strippedTrackers >= 9);
    assert.equal(
      data.product.normalizedUrl,
      'https://www.amazon.de/-/en/Sony-WF-1000XM6-Cancelling-Headphones-silver/dp/B0GFB2WX82'
    );

    // Must price realistically for earbuds/headphones (not €1000+ computing gear)
    assert.ok(
      data.pricing.currentPrice >= 120 && data.pricing.currentPrice <= 380,
      `Expected realistic earbuds price, got ${data.pricing.currentPrice}`
    );

    // Secret GEMINI_API_KEY must never leak in API responses
    if (process.env.GEMINI_API_KEY) {
      assert.equal(res.body.includes(process.env.GEMINI_API_KEY), false);
    }

    // Unit test for Gemini grounded response normalization + verified live price locking
    const parsedJson = extractJsonObject('```json\n{"title":"LLM Title Estimate","currentPrice":199,"average90d":235,"lowest180d":194,"highest180d":279,"competitors":[{"retailer":"MediaMarkt","price":199}]}\n```');
    assert.ok(parsedJson && parsedJson.currentPrice === 199);
    const normalized = normalizeGroundedData(parsedJson, {
      parsedTitle: 'Samsung Galaxy A18',
      liveTitle: 'SAMSUNG Galaxy A18 LTE 128 GB in Schwarz',
      brand: 'Samsung',
      category: 'Computing & Electronics',
      currency: 'EUR',
      retailerName: 'MediaMarkt',
      livePrice: 219.79
    });
    assert.equal(normalized.currentPrice, 219.79);
    assert.equal(normalized.title, 'SAMSUNG Galaxy A18 LTE 128 GB in Schwarz');
    assert.ok(normalized.competitors.some((c) => c.retailer === 'MediaMarkt' && c.price === 219.79));

    // Verify repeat call of the exact same URL returns 100% deterministic cached output
    const repeatRes1 = await httpRequestRaw(
      baseUrl,
      'POST',
      '/api/analyze',
      JSON.stringify({ url: 'https://www.amazon.de/Calvin-Klein-Boxer-Shorts-black/dp/B001BEAWZM?sbo=RZvfv%2F%2FHxDF&th=1&psc=1' }),
      { 'Content-Type': 'application/json' }
    );
    const repeatRes2 = await httpRequestRaw(
      baseUrl,
      'POST',
      '/api/analyze',
      JSON.stringify({ url: 'https://www.amazon.de/Calvin-Klein-Boxer-Shorts-black/dp/B001BEAWZM' }),
      { 'Content-Type': 'application/json' }
    );
    assert.equal(repeatRes1.statusCode, 200);
    assert.equal(repeatRes2.statusCode, 200);
    const d1 = JSON.parse(repeatRes1.body);
    const d2 = JSON.parse(repeatRes2.body);
    assert.equal(d1.product.normalizedUrl, 'https://www.amazon.de/Calvin-Klein-Boxer-Shorts-black/dp/B001BEAWZM');
    assert.equal(d2.meta.cachedResult, true);
    assert.equal(d1.pricing.currentPrice, d2.pricing.currentPrice);
    assert.equal(d1.scoring.dealScore, d2.scoring.dealScore);
    assert.equal(d1.product.title, d2.product.title);

    // Verify ad slots are hidden, sample URLs box is removed, and 30/90/180-day UI controls exist
    const htmlRes = await httpRequestRaw(baseUrl, 'GET', '/');
    assert.equal(htmlRes.statusCode, 200);
    assert.match(htmlRes.body, /class="ad-rail hidden"/);
    assert.match(htmlRes.body, /class="ad-rail-inline hidden"/);
    assert.match(htmlRes.body, /class="ad-rail ad-rail-footer hidden"/);
    assert.doesNotMatch(htmlRes.body, /SPONSORED AD SLOT/);
    assert.doesNotMatch(htmlRes.body, /preset-chips/);
    assert.doesNotMatch(htmlRes.body, /TEST LIVE SAMPLE URLS/);
    assert.match(htmlRes.body, /id="range-30-btn"/);
    assert.match(htmlRes.body, /id="res-window-comparison"/);
  } finally {
    await stopTestServer(server);
  }
});

test('High-traffic scaling: in-flight deduplication, concurrency queue overflow (503), and Gemini budget circuit breaker', async () => {
  // 1. Concurrency queue limits active executions and rejects overflow with QueueOverflowError (503)
  const queue = createConcurrencyQueue({ maxConcurrent: 2, maxQueueSize: 1, queueTimeoutMs: 2000 });
  let releaseGate;
  const gate = new Promise((r) => {
    releaseGate = r;
  });
  const p1 = queue.run(() => gate.then(() => 1));
  const p2 = queue.run(() => gate.then(() => 2));
  const p3 = queue.run(() => Promise.resolve(3));
  assert.equal(queue.stats().active, 2);
  assert.equal(queue.stats().queued, 1);
  await assert.rejects(
    () => queue.run(() => Promise.resolve(4)),
    (err) => err instanceof QueueOverflowError && err.statusCode === 503
  );
  releaseGate();
  assert.deepEqual(await Promise.all([p1, p2, p3]), [1, 2, 3]);

  // 2. Gemini budget guard enforces minute & daily circuit breakers and resets on UTC day rollover
  const guard = createGeminiBudgetGuard({
    maxDailyCalls: 3,
    maxMinuteCalls: 2,
    persistFilePath: null
  });
  const day1 = Date.UTC(2026, 10, 18, 12, 0, 0);
  assert.equal(guard.tryConsume(day1).allowed, true);
  assert.equal(guard.tryConsume(day1 + 1000).allowed, true);
  const minuteBlocked = guard.tryConsume(day1 + 2000);
  assert.equal(minuteBlocked.allowed, false);
  assert.equal(minuteBlocked.reason, 'MINUTE_BURST_CAP_REACHED');

  // Advance 61s: minute quota clears, 3rd daily call succeeds, 4th hits daily cap
  assert.equal(guard.tryConsume(day1 + 61_000).allowed, true);
  const dailyBlocked = guard.tryConsume(day1 + 62_000);
  assert.equal(dailyBlocked.allowed, false);
  assert.equal(dailyBlocked.reason, 'DAILY_BUDGET_CAP_REACHED');

  // Next UTC day resets daily counter
  const day2 = Date.UTC(2026, 10, 19, 0, 0, 5);
  assert.equal(guard.tryConsume(day2).allowed, true);

  // 3. In-flight deduplication shares 1 execution across 15 concurrent identical URL calls
  const dedupUrl = 'https://www.dedup-test-store.example/products/wireless-mouse-442211';
  let executions = 0;
  analysisCache.clear();
  const fakeWork = async () => {
    executions += 1;
    await new Promise((r) => setTimeout(r, 80));
    return {
      analyzedAt: new Date().toISOString(),
      zeroPiiMode: true,
      product: {
        title: 'Dedup Mouse',
        retailerName: 'DedupStore',
        strippedTrackers: 0
      },
      pricing: { currentPrice: 49.99 },
      scoring: { dealScore: 75 },
      meta: { cachedResult: false, deduplicatedInFlight: false }
    };
  };

  const results = await Promise.all(
    Array.from({ length: 15 }, () => runDeepDealAnalysis(dedupUrl, { workRunner: fakeWork }))
  );
  assert.equal(executions, 1);
  assert.equal(results.length, 15);
  assert.equal(results.filter((r) => !r.meta.deduplicatedInFlight).length, 1);
  assert.equal(results.filter((r) => r.meta.deduplicatedInFlight).length, 14);
});

function startMockRedisServer(expectedPassword = 'secretpw') {
  const kv = new Map();
  const hashes = new Map();
  const sockets = new Set();

  function parseIncomingCommands(buf) {
    const commands = [];
    let idx = 0;
    while (idx < buf.length && buf[idx] === 42) {
      const crlf = buf.indexOf('\r\n', idx);
      if (crlf === -1) break;
      const count = Number(buf.toString('utf8', idx + 1, crlf));
      let cur = crlf + 2;
      const args = [];
      let complete = true;
      for (let i = 0; i < count; i += 1) {
        if (buf[cur] !== 36) { complete = false; break; }
        const lenCrlf = buf.indexOf('\r\n', cur);
        if (lenCrlf === -1) { complete = false; break; }
        const len = Number(buf.toString('utf8', cur + 1, lenCrlf));
        const end = lenCrlf + 2 + len;
        if (end + 2 > buf.length) { complete = false; break; }
        args.push(buf.toString('utf8', lenCrlf + 2, end));
        cur = end + 2;
      }
      if (!complete) break;
      commands.push(args);
      idx = cur;
    }
    return { commands, rest: buf.subarray(idx) };
  }

  function encodeBulk(val) {
    if (val === null || val === undefined) return Buffer.from('$-1\r\n');
    const s = String(val);
    return Buffer.from(`$${Buffer.byteLength(s, 'utf8')}\r\n${s}\r\n`);
  }

  const server = net.createServer((sock) => {
    sockets.add(sock);
    let rx = Buffer.alloc(0);
    sock.on('close', () => sockets.delete(sock));
    sock.on('data', (chunk) => {
      rx = Buffer.concat([rx, chunk]);
      const parsed = parseIncomingCommands(rx);
      rx = parsed.rest;
      for (const cmdArgs of parsed.commands) {
        const op = String(cmdArgs[0] || '').toUpperCase();
        if (op === 'AUTH') {
          const pw = cmdArgs.length >= 3 ? cmdArgs[2] : cmdArgs[1];
          sock.write(pw === expectedPassword ? '+OK\r\n' : '-ERR invalid password\r\n');
        } else if (op === 'PING') {
          sock.write('+PONG\r\n');
        } else if (op === 'GET') {
          sock.write(encodeBulk(kv.has(cmdArgs[1]) ? kv.get(cmdArgs[1]) : null));
        } else if (op === 'SET') {
          kv.set(cmdArgs[1], cmdArgs[2]);
          sock.write('+OK\r\n');
        } else if (op === 'INCR') {
          const next = (Number(kv.get(cmdArgs[1])) || 0) + 1;
          kv.set(cmdArgs[1], String(next));
          sock.write(`:${next}\r\n`);
        } else if (op === 'EXPIRE' || op === 'PEXPIRE') {
          sock.write(':1\r\n');
        } else if (op === 'HINCRBY') {
          const map = hashes.get(cmdArgs[1]) || new Map();
          const next = (Number(map.get(cmdArgs[2])) || 0) + Number(cmdArgs[3] || 1);
          map.set(cmdArgs[2], String(next));
          hashes.set(cmdArgs[1], map);
          sock.write(`:${next}\r\n`);
        } else if (op === 'HGETALL') {
          const map = hashes.get(cmdArgs[1]) || new Map();
          const entries = Array.from(map.entries());
          const parts = [Buffer.from(`*${entries.length * 2}\r\n`)];
          for (const [k, v] of entries) {
            parts.push(encodeBulk(k), encodeBulk(v));
          }
          sock.write(Buffer.concat(parts));
        } else {
          sock.write('+OK\r\n');
        }
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        url: `redis://default:${expectedPassword}@127.0.0.1:${addr.port}`,
        close: () =>
          new Promise((res) => {
            for (const s of sockets) s.destroy();
            server.close(() => res());
          })
      });
    });
  });
}

test('Redis client, shared L2 cache, Cloudflare IP limiter, traffic metrics, and budget persistence', async () => {
  const mockRedis = await startMockRedisServer('secretpw');
  const redisClient = createRedisClient(mockRedis.url, { autoConnect: false });

  try {
    assert.equal(await redisClient.ping(), true);
    assert.equal(redisClient.isConnected(), true);

    // 1. Shared L2 cache persists across distinct cache instances
    const cacheWriter = createAnalysisCache({ maxEntries: 50, ttlMs: 3600_000, redisClient });
    const cacheReader = createAnalysisCache({ maxEntries: 50, ttlMs: 3600_000, redisClient });
    await cacheWriter.setAsync('https://www.amazon.de/dp/B001BEAWZM', { ok: true, price: 26.9 });
    const recovered = await cacheReader.getAsync('https://www.amazon.de/dp/B001BEAWZM');
    assert.deepEqual(recovered, { ok: true, price: 26.9 });

    // 2. Distributed rate limiter enforces shared limits across instances
    const rlA = createRateLimiter({ windowMs: 60_000, maxRequests: 2, redisClient });
    const rlB = createRateLimiter({ windowMs: 60_000, maxRequests: 2, redisClient });
    assert.equal((await rlA.consumeAsync('203.0.113.5', 1_700_000_000_000)).allowed, true);
    assert.equal((await rlB.consumeAsync('203.0.113.5', 1_700_000_001_000)).allowed, true);
    assert.equal((await rlA.consumeAsync('203.0.113.5', 1_700_000_002_000)).allowed, false);

    // 3. Budget guard coordinates via Redis
    const budget = createGeminiBudgetGuard({ maxDailyCalls: 2, maxMinuteCalls: 2, persistFilePath: null, redisClient });
    const ts = Date.UTC(2026, 10, 19, 12, 0, 0);
    assert.equal((await budget.tryConsumeAsync(ts)).allowed, true);
    assert.equal((await budget.tryConsumeAsync(ts + 1000)).allowed, true);
    assert.equal((await budget.tryConsumeAsync(ts + 2000)).reason, 'DAILY_BUDGET_CAP_REACHED');

    // 4. Proof-of-traffic telemetry
    const metrics = createTrafficMetrics({ redisClient });
    await metrics.recordPageView();
    await metrics.recordPageView();
    await metrics.recordAnalysis({ retailerName: 'Amazon', cached: false });
    await metrics.recordAnalysis({ retailerName: 'Amazon', cached: true });
    const stats = await metrics.getStats();
    assert.equal(stats.storage, 'redis');
    assert.equal(stats.totalPageViews, 2);
    assert.equal(stats.totalAnalyses, 2);
    assert.equal(stats.cacheHits, 1);
    assert.equal(stats.topRetailers[0].retailer, 'Amazon');

    // 5. Cloudflare CF-Connecting-IP handling respects TRUST_PROXY
    const prevTrust = process.env.TRUST_PROXY;
    process.env.TRUST_PROXY = 'true';
    assert.equal(
      getClientIp({ headers: { 'cf-connecting-ip': '198.51.100.77', 'x-forwarded-for': '10.0.0.1' }, socket: { remoteAddress: '127.0.0.1' } }),
      '198.51.100.77'
    );
    process.env.TRUST_PROXY = 'false';
    assert.equal(
      getClientIp({ headers: { 'cf-connecting-ip': '198.51.100.77' }, socket: { remoteAddress: '127.0.0.9' } }),
      '127.0.0.9'
    );
    if (prevTrust === undefined) delete process.env.TRUST_PROXY;
    else process.env.TRUST_PROXY = prevTrust;
  } finally {
    redisClient.close();
    await mockRedis.close();
  }
});

test('Affiliate links, dynamic AdSense/Cloudflare CSP, ads.txt, trust pages & proxy SSRF invariance', async () => {
  const savedEnv = { ...process.env };
  try {
    // 1. Default strict CSP remains 'self' only when monetization/analytics env vars unset
    delete process.env.ADSENSE_CLIENT_ID;
    delete process.env.CF_WEB_ANALYTICS_TOKEN;
    delete process.env.CF_TURNSTILE_SITE_KEY;
    delete process.env.CF_TURNSTILE_SECRET_KEY;
    const strictCsp = buildCspHeader(true);
    assert.match(strictCsp, /script-src 'self';/);

    // 2. Affiliate links preserve unbiased Deal Truth Score while generating clean HTTPS URLs
    const sampleUrl = await validateAndNormalizeProductUrl('https://www.amazon.de/dp/B0GFB2WX82', { resolveDns: false });
    const baseReport = analyzeProductPricing({ urlInfo: sampleUrl, liveSignals: null, webSearch: null, geminiGrounded: null });

    process.env.AFFILIATE_AMAZON_DE_TAG = 'rpnl-21';
    process.env.AFFILIATE_AWIN_PUBLISHER_ID = '999999';
    process.env.AFFILIATE_AWIN_MEDIAMARKT_MID = '14411';
    const taggedReport = analyzeProductPricing({ urlInfo: sampleUrl, liveSignals: null, webSearch: null, geminiGrounded: null });

    assert.equal(baseReport.scoring.dealScore, taggedReport.scoring.dealScore);
    const amazonComp = taggedReport.competitors.find((c) => c.retailer === 'Amazon');
    assert.ok(amazonComp && amazonComp.offerUrl.includes('tag=rpnl-21'));
    assert.equal(amazonComp.isAffiliate, true);

    const mmOffer = buildMerchantOfferLink({
      retailerName: 'MediaMarkt',
      title: 'Sony Headphones',
      sku: 'B0GFB2WX82',
      currency: 'EUR',
      isTargetStore: false
    });
    assert.match(mmOffer.offerUrl, /^https:\/\/www\.awin1\.com\/cread\.php\?awinmid=14411&awinaffid=999999&ued=/);
    assert.equal(mmOffer.isAffiliate, true);

    // 3. Scraper proxy endpoint enforces HTTPS templates and SSRF guards still run before any proxy fetch
    process.env.SCRAPER_PROXY_TEMPLATE = 'http://insecure.local/?url={url}';
    assert.equal(buildScraperProxyEndpoint('https://www.amazon.de/dp/B0GFB2WX82'), null);
    process.env.SCRAPER_PROXY_TEMPLATE = 'https://proxy.example.com/fetch?url={url}';
    assert.equal(
      buildScraperProxyEndpoint('https://www.amazon.de/dp/B0GFB2WX82'),
      'https://proxy.example.com/fetch?url=https%3A%2F%2Fwww.amazon.de%2Fdp%2FB0GFB2WX82'
    );
    process.env.SCRAPER_API_KEY = 'demo-scraper-key';
    await assert.rejects(
      () => validateAndNormalizeProductUrl('http://127.0.0.1/internal', { resolveDns: false }),
      (err) => err.code === 'SSRF_BLOCKED_IP'
    );

    // 4. Server routes: /ads.txt, /api/public-config, /api/stats, dynamic AdSense CSP + meta tag, and subpages
    process.env.ADSENSE_CLIENT_ID = 'ca-pub-1234567890123456';
    process.env.CF_WEB_ANALYTICS_TOKEN = 'cf-token-xyz';
    const adsenseCsp = buildCspHeader(true);
    assert.match(adsenseCsp, /https:\/\/pagead2\.googlesyndication\.com/);
    assert.match(adsenseCsp, /https:\/\/static\.cloudflareinsights\.com/);

    const { server, baseUrl } = await startTestServer({ rateLimitMaxRequests: 50 });
    try {
      const adsTxtRes = await httpRequestRaw(baseUrl, 'GET', '/ads.txt');
      assert.equal(adsTxtRes.statusCode, 200);
      assert.match(adsTxtRes.body, /google\.com, pub-1234567890123456, DIRECT, f08c47fec0942fa0/);

      const pubCfgRes = await httpRequestRaw(baseUrl, 'GET', '/api/public-config');
      assert.equal(pubCfgRes.statusCode, 200);
      const pubCfg = JSON.parse(pubCfgRes.body);
      assert.equal(pubCfg.adsenseClientId, 'ca-pub-1234567890123456');
      assert.equal(pubCfg.cfWebAnalyticsToken, 'cf-token-xyz');
      assert.equal(pubCfg.affiliateDisclosureActive, true);

      const statsRes = await httpRequestRaw(baseUrl, 'GET', '/api/stats');
      assert.equal(statsRes.statusCode, 200);
      assert.equal(JSON.parse(statsRes.body).zeroPii, true);

      for (const page of ['/', '/about.html', '/privacy.html', '/contact.html', '/guide-fake-discounts.html']) {
        const res = await httpRequestRaw(baseUrl, 'GET', page);
        assert.equal(res.statusCode, 200, `Expected HTTP 200 for ${page}`);
        assert.match(res.body, /<meta name="google-adsense-account" content="ca-pub-1234567890123456">/);
      }
    } finally {
      await stopTestServer(server);
    }
  } finally {
    for (const key of Object.keys(process.env)) {
      if (!(key in savedEnv)) delete process.env[key];
    }
    Object.assign(process.env, savedEnv);
  }
});


