'use strict';

const https = require('node:https');
const { sanitizeText } = require('../security/sanitizer');
const { defaultBudgetGuard } = require('./geminiBudgetGuard');

const GEMINI_MODELS = [
  { name: 'gemini-3.5-flash', supportsThinkingBudget: true },
  { name: 'gemini-3.8-flash', supportsThinkingBudget: true },
  { name: 'gemini-3.1-flash-lite', supportsThinkingBudget: false }
];

function extractJsonObject(rawText) {
  if (typeof rawText !== 'string') return null;
  let cleaned = rawText.trim();
  // Strip optional markdown code fences
  const fenceMatch = cleaned.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenceMatch) {
    cleaned = fenceMatch[1].trim();
  }
  const firstBrace = cleaned.indexOf('{');
  const lastBrace = cleaned.lastIndexOf('}');
  if (firstBrace === -1 || lastBrace <= firstBrace) {
    return null;
  }
  try {
    return JSON.parse(cleaned.slice(firstBrace, lastBrace + 1));
  } catch {
    return null;
  }
}

function toValidPrice(val) {
  const num = Number(val);
  if (!Number.isFinite(num) || num <= 0 || num >= 1_000_000) return null;
  return Math.round(num * 100) / 100;
}

function normalizeGroundedData(raw, defaults) {
  if (!raw || typeof raw !== 'object') return null;

  // Verified live page price scraped directly from the merchant ALWAYS takes precedence over LLM search estimates.
  const lockedLivePrice = toValidPrice(defaults.livePrice);
  const currentPrice = lockedLivePrice || toValidPrice(raw.currentPrice);
  if (!currentPrice) return null;

  const avgRaw = toValidPrice(raw.average90d) || currentPrice;
  const lowRaw = toValidPrice(raw.lowest180d) || Math.round(Math.min(currentPrice, avgRaw) * 0.9 * 100) / 100;
  const highRaw = toValidPrice(raw.highest180d) || Math.round(Math.max(currentPrice, avgRaw) * 1.1 * 100) / 100;
  const refRaw = toValidPrice(defaults.liveReferencePrice) || toValidPrice(raw.claimedReferencePrice);

  const lowest180d = Math.min(lowRaw, currentPrice, avgRaw);
  const highest180d = Math.max(highRaw, currentPrice, avgRaw);
  const average90d = Math.max(lowest180d, Math.min(highest180d, avgRaw));
  const claimedReferencePrice = refRaw && refRaw >= currentPrice ? refRaw : highest180d;

  const validDate =
    typeof raw.lowest180dDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(raw.lowest180dDate.trim())
      ? raw.lowest180dDate.trim()
      : new Date(Date.now() - 45 * 86_400_000).toISOString().slice(0, 10);

  const rawCurrency = typeof raw.currency === 'string' ? raw.currency.trim().toUpperCase() : '';
  const currency = ['EUR', 'USD', 'GBP', 'CHF'].includes(rawCurrency) ? rawCurrency : defaults.currency;

  const targetLower = defaults.retailerName.toLowerCase();
  const competitors = [];
  const seenStores = new Set();
  if (Array.isArray(raw.competitors)) {
    for (const item of raw.competitors.slice(0, 6)) {
      if (!item || typeof item !== 'object') continue;
      const storeName = sanitizeText(item.retailer || '', 48);
      const rawPrice = toValidPrice(item.price);
      if (!storeName || !rawPrice) continue;
      const key = storeName.toLowerCase();
      if (seenStores.has(key)) continue;
      seenStores.add(key);
      // Lock the target store's price to verified currentPrice so comparison row always matches Current Listed Price
      const finalCompPrice = key === targetLower || key.startsWith(`${targetLower}.`) ? currentPrice : rawPrice;
      competitors.push({
        retailer: key.startsWith(`${targetLower}.`) ? defaults.retailerName : storeName,
        price: finalCompPrice,
        shipping: sanitizeText(item.shipping || (finalCompPrice >= 49 ? 'Free Standard Shipping' : 'Standard Shipping'), 48),
        stock: sanitizeText(item.stock || 'In Stock', 24)
      });
    }
  }

  // Ensure the submitted target store is included at its exact current price
  if (!seenStores.has(targetLower)) {
    competitors.unshift({
      retailer: defaults.retailerName,
      price: currentPrice,
      shipping: currentPrice >= 49 ? 'Free Standard Shipping' : 'Standard Shipping',
      stock: 'In Stock'
    });
  }

  const lowestComp = competitors.reduce((best, c) => (c.price < best.price ? c : best), competitors[0]);
  const lowest180dRetailer = sanitizeText(raw.lowest180dRetailer || lowestComp.retailer, 48);

  const findings = Array.isArray(raw.findings)
    ? raw.findings
        .filter((f) => typeof f === 'string' && f.trim().length > 8)
        .slice(0, 4)
        .map((f) => sanitizeText(f, 260))
    : [];

  return {
    title: sanitizeText(defaults.liveTitle || raw.title || defaults.parsedTitle, 140),
    brand: sanitizeText(raw.brand || defaults.brand, 48),
    category: sanitizeText(raw.category || defaults.category, 64),
    currency,
    currentPrice,
    claimedReferencePrice,
    average90d,
    lowest180d,
    lowest180dDate: validDate,
    lowest180dRetailer,
    highest180d,
    prePromoHikeDetected: Boolean(raw.prePromoHikeDetected),
    competitors: competitors.slice(0, 6),
    headline: typeof raw.headline === 'string' && raw.headline.trim() ? sanitizeText(raw.headline, 240) : null,
    findings
  };
}

function extractGroundingSources(outerResponse) {
  const chunks = outerResponse?.candidates?.[0]?.groundingMetadata?.groundingChunks;
  if (!Array.isArray(chunks)) return [];
  const sources = [];
  const seen = new Set();
  for (const ch of chunks) {
    const title = ch?.web?.title;
    if (typeof title === 'string' && title.trim()) {
      const clean = sanitizeText(title, 60);
      if (!seen.has(clean.toLowerCase())) {
        seen.add(clean.toLowerCase());
        sources.push(clean);
      }
    }
    if (sources.length >= 5) break;
  }
  return sources;
}

function callGeminiModel({ apiKey, modelCfg, prompt, timeoutMs = 8500 }) {
  const generationConfig = {
    temperature: 0,
    maxOutputTokens: 900
  };
  if (modelCfg.supportsThinkingBudget) {
    generationConfig.thinkingConfig = { thinkingBudget: 0 };
  }

  const payload = JSON.stringify({
    contents: [{ parts: [{ text: prompt }] }],
    tools: [{ google_search: {} }],
    generationConfig
  });

  const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${modelCfg.name}:generateContent?key=${encodeURIComponent(apiKey)}`;

  return new Promise((resolve) => {
    const req = https.request(
      endpoint,
      {
        method: 'POST',
        timeout: timeoutMs,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        }
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const bodyStr = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode !== 200) {
            if (res.statusCode === 402 || /RESOURCE_EXHAUSTED|credits/i.test(bodyStr)) {
              resolve({ ok: false, status: 'CREDITS_DEPLETED_402' });
            } else if (res.statusCode === 401 || res.statusCode === 403) {
              resolve({ ok: false, status: 'AUTH_ERROR' });
            } else if (res.statusCode === 404) {
              resolve({ ok: false, status: 'MODEL_NOT_FOUND_404' });
            } else {
              resolve({ ok: false, status: `HTTP_${res.statusCode}` });
            }
            return;
          }

          try {
            const outer = JSON.parse(bodyStr);
            const parts = outer?.candidates?.[0]?.content?.parts || [];
            const text = parts.map((p) => p.text || '').join('\n');
            const parsed = extractJsonObject(text);
            if (!parsed) {
              resolve({ ok: false, status: 'INVALID_JSON' });
              return;
            }
            resolve({
              ok: true,
              status: 'ACTIVE',
              model: modelCfg.name,
              data: parsed,
              groundingSources: extractGroundingSources(outer)
            });
          } catch {
            resolve({ ok: false, status: 'PARSE_ERROR' });
          }
        });
      }
    );
    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, status: 'TIMEOUT' });
    });
    req.on('error', () => resolve({ ok: false, status: 'NETWORK_UNAVAILABLE' }));
    req.write(payload);
    req.end();
  });
}

/**
 * Runs live Google Search-grounded Gemini research for any product URL.
 * Returns verified title, current retail price, historical benchmarks, and competing offers.
 */
async function runGeminiGroundedProductResearch({
  normalizedUrl,
  retailerName,
  retailerDomain,
  parsedTitle,
  liveTitle,
  brand,
  sku,
  category,
  currency,
  livePrice,
  liveReferencePrice
}) {
  const apiKey = (process.env.GEMINI_API_KEY || '').trim();
  if (!apiKey) {
    return { found: false, status: 'UNCONFIGURED' };
  }

  const quota = await defaultBudgetGuard.tryConsumeAsync();
  if (!quota.allowed) {
    return { found: false, status: quota.reason };
  }

  const todayIso = new Date().toISOString().slice(0, 10);
  const prompt = [
    'You are RealPriceNoLies, a precise e-commerce price intelligence researcher.',
    `Today is ${todayIso}.`,
    'Use Google Search to investigate this exact product and return accurate real-world market prices:',
    `- Target Product URL: ${normalizedUrl}`,
    `- Target Retailer: ${retailerName} (${retailerDomain})`,
    `- Verified Product Name: ${liveTitle || parsedTitle}`,
    `- SKU / ASIN / Article Code: ${sku}`,
    `- Target Currency: ${currency}`,
    livePrice
      ? `- FIXED LIVE STORE PRICE (verified directly from store HTML — DO NOT change this currentPrice): ${livePrice} ${currency}`
      : '- Live Scraped Store Price: unavailable (store shielded; find exact current price via Google Search)',
    liveReferencePrice
      ? `- FIXED LIVE REFERENCE/WAS PRICE (from store HTML): ${liveReferencePrice} ${currency}`
      : '',
    '',
    livePrice
      ? `Treat ${livePrice} ${currency} as the exact verified currentPrice at ${retailerName}. Research the 90-day average, 180-day low/high, UVP, and 3 to 5 real competing retailer offers for this exact SKU/model.`
      : 'Search Google for the product page, exact SKU/model, price trackers (idealo, geizhals, keepa, camelcamelcamel), and 3 to 5 real competing stores.',
    'Return ONLY a single JSON object (no extra commentary) with these exact fields:',
    '{',
    '  "title": "Exact clean product name (no store suffix)",',
    '  "brand": "Manufacturer/brand name",',
    '  "category": "Product category",',
    `  "currency": "${currency}",`,
    `  "currentPrice": ${livePrice || 0.0},`,
    `  "claimedReferencePrice": ${liveReferencePrice || 0.0},`,
    '  "average90d": 0.00,',
    '  "lowest180d": 0.00,',
    '  "lowest180dDate": "YYYY-MM-DD",',
    '  "lowest180dRetailer": "Store name",',
    '  "highest180d": 0.00,',
    '  "prePromoHikeDetected": false,',
    '  "competitors": [',
    '    {"retailer": "Store Name", "price": 0.00, "shipping": "Free Delivery or €X.XX", "stock": "In Stock"}',
    '  ],',
    '  "headline": "Concise 1-sentence factual verdict",',
    '  "findings": ["Bullet 1 with real price figures", "Bullet 2 comparing UVP vs 90d avg", "Bullet 3 comparing cheapest alternative"]',
    '}',
    'All prices must be realistic numeric values in the target currency based on Google Search results.'
  ]
    .filter(Boolean)
    .join('\n');

  let lastStatus = 'UNAVAILABLE';
  for (const modelCfg of GEMINI_MODELS) {
    const res = await callGeminiModel({ apiKey, modelCfg, prompt, timeoutMs: 8500 });
    lastStatus = res.status;

    if (res.ok) {
      const normalized = normalizeGroundedData(res.data, {
        parsedTitle,
        liveTitle,
        brand,
        category,
        currency,
        retailerName,
        livePrice,
        liveReferencePrice
      });
      if (normalized) {
        return {
          found: true,
          status: 'ACTIVE',
          model: res.model,
          groundingSources: res.groundingSources,
          data: normalized
        };
      }
      lastStatus = 'NORMALIZATION_FAILED';
      continue;
    }

    if (res.status === 'CREDITS_DEPLETED_402' || res.status === 'AUTH_ERROR') {
      break;
    }
  }

  return { found: false, status: lastStatus };
}

module.exports = {
  extractJsonObject,
  normalizeGroundedData,
  runGeminiGroundedProductResearch
};

