'use strict';

const { parseLocalizedPrice } = require('../security/urlGuard');
const { sanitizeText } = require('../security/sanitizer');

const SEARCH_TIMEOUT_MS = 3200;

function decodeHtmlEntities(str) {
  return str
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&nbsp;/g, ' ');
}

function currencySymbolToCode(token) {
  const upper = token.toUpperCase();
  if (upper === '€' || upper === 'EUR') return 'EUR';
  if (upper === '£' || upper === 'GBP') return 'GBP';
  if (upper === '$' || upper === 'USD') return 'USD';
  if (upper === 'CHF') return 'CHF';
  return 'EUR';
}

function convertCurrencyApprox(amount, fromCurr, toCurr) {
  if (fromCurr === toCurr) return amount;
  const toEur = { EUR: 1, USD: 0.92, GBP: 1.18, CHF: 1.06 };
  const eurVal = amount * (toEur[fromCurr] || 1);
  return Number((eurVal / (toEur[toCurr] || 1)).toFixed(2));
}

/**
 * Extracts price mentions from search titles/snippets while filtering out
 * shipping fees, monthly installments, and cashback promos.
 */
function extractPricesFromText(text, targetCurrency) {
  const matches = [];
  const priceRx =
    /(?:(€|EUR|GBP|£|\$|CHF)\s*(\d{1,4}(?:[.,]\d{3})*(?:[.,]\d{2})?)|(\d{1,4}(?:[.,]\d{3})*(?:[.,]\d{2})?)\s*(€|EUR|GBP|£|CHF))/gi;

  let m;
  while ((m = priceRx.exec(text)) !== null) {
    const rawNum = m[2] || m[3];
    const currToken = m[1] || m[4];
    const price = parseLocalizedPrice(rawNum);
    if (!price || price < 3 || price > 50000) continue;

    const startIdx = Math.max(0, m.index - 32);
    const contextBefore = text.slice(startIdx, m.index).toLowerCase();
    const contextAfter = text.slice(m.index, m.index + m[0].length + 24).toLowerCase();

    // Skip shipping fees, monthly payment rates, cashback bonuses, and "free shipping over X" thresholds
    if (
      /(versand|shipping|delivery|porto|monat|monthly|rate|startgutschrift|gutschein|rabatt|bonus|spare|save|over|ab einem|mindestbestell)/.test(
        contextBefore
      ) ||
      /(\/\s*mo|pro monat|per month|x\s*\d+|shipping|versand)/.test(contextAfter)
    ) {
      continue;
    }

    const foundCurrency = currencySymbolToCode(currToken);
    matches.push({
      rawPrice: price,
      foundCurrency,
      normalizedPrice: convertCurrencyApprox(price, foundCurrency, targetCurrency),
      isSameCurrency: foundCurrency === targetCurrency
    });
  }

  return matches;
}

function extractModelToken(title) {
  const m = String(title || '').match(/\b([A-Z]{1,4}-?\d{2,5}[A-Z0-9-]*)\b/i);
  return m ? m[1] : null;
}

/**
 * Builds a concise, price-biased search query from product title & brand.
 */
function buildSearchQuery(title, brand, sku, currency = 'EUR') {
  const currHint =
    currency === 'GBP' ? '£ OR GBP' : currency === 'USD' ? '$ OR USD' : currency === 'CHF' ? 'CHF' : '€ OR EUR';

  // If URL had no descriptive slug (e.g. amazon.de/dp/B0CHWRXH8B), query directly by SKU/ASIN
  if (/catalog product/i.test(title) && sku && sku !== 'UNSPECIFIED') {
    return `"${sku}" price ${currHint}`;
  }

  const cleanTitle = sanitizeText(title, 90)
    .replace(/\b(Silver|Black|White|Schwarz|Weiss|Weiß|Blau|Blue|Red|Grey|Gray|Silber)\b/gi, '')
    .replace(/\s+/g, ' ')
    .trim();

  const modelToken = extractModelToken(cleanTitle);

  if (modelToken && brand) {
    const cleanBrand = brand.toLowerCase();
    const core = cleanBrand === modelToken.toLowerCase() ? modelToken : `${brand} "${modelToken}"`;
    return `${core} Preis OR price ${currHint}`;
  }

  const tokens = cleanTitle.split(' ').slice(0, 4).join(' ');
  if (sku && sku !== 'UNSPECIFIED' && !tokens.toUpperCase().includes(sku.toUpperCase())) {
    return `${tokens} ${sku} ${currHint}`;
  }
  return `${tokens} price ${currHint}`;
}

/**
 * Attempts to refine a raw URL slug title using clean search result headings.
 */
function pickRefinedTitle(titles, originalTitle, brand) {
  if (!Array.isArray(titles) || titles.length === 0) return null;
  const brandLower = (brand || '').toLowerCase();
  const modelToken = extractModelToken(originalTitle);

  for (const raw of titles) {
    let candidate = raw
      .replace(/^(?:Amazon\.[a-z.]+|MediaMarkt|SATURN|OTTO|Zalando|IKEA|H&M)\s*[:|-]\s*/i, '')
      .replace(/\s+ab\s+[€$£]?\s*\d+[.,]\d{2}.*$/i, '')
      .replace(/\s*\(\d{4}\).*$/i, '')
      .replace(/\s*[|–-]\s*(?:Preisvergleich|Vergleiche|Geizhals|idealo|guenstiger|MediaMarkt|SATURN|Amazon|OTTO|Zalando|IKEA).*$/i, '')
      .replace(/,\s*(?:In-ear|Over-ear).*$/i, '')
      .trim();

    if (candidate.length < 10 || candidate.length > 130) continue;
    if (/^(?:beste|top\s*\d+|test|review|free\s+amazon)/i.test(candidate)) continue;
    if (/(?:asin lookup|barcode lookup|ean search)/i.test(candidate)) continue;
    const lower = candidate.toLowerCase();
    if (brandLower && !lower.includes(brandLower)) continue;
    if (modelToken && !lower.includes(modelToken.toLowerCase())) continue;
    if (candidate.endsWith('...')) continue;
    return sanitizeText(candidate, 140);
  }
  return null;
}

function hasRelevantKeywordOverlap(combinedText, titleWords, modelToken, sku) {
  const lower = combinedText.toLowerCase();
  if (modelToken && lower.includes(modelToken.toLowerCase())) {
    return true;
  }
  if (sku && sku !== 'UNSPECIFIED' && lower.includes(sku.toLowerCase())) {
    return true;
  }
  let hits = 0;
  for (const w of titleWords) {
    if (lower.includes(w)) hits += 1;
  }
  return hits >= Math.min(2, titleWords.length);
}

async function runSingleDuckDuckGoQuery(query, currency, titleWords, modelToken, sku, brand, title) {
  const endpoint = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SEARCH_TIMEOUT_MS);
  timer.unref();

  try {
    const res = await fetch(endpoint, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept-Language': 'de-DE,de;q=0.9,en-GB;q=0.8,en;q=0.7'
      }
    });

    if (!res.ok) {
      return { ok: false, reason: `Web index HTTP ${res.status}`, extracted: [], refinedTitle: null };
    }

    const html = await res.text();
    const titles = [...html.matchAll(/class="result__a"[^>]*>([\s\S]*?)<\/a>/gi)].map((m) =>
      sanitizeText(decodeHtmlEntities(m[1].replace(/<[^>]+>/g, ' ')), 180)
    );
    const snippets = [...html.matchAll(/class="result__snippet"[^>]*>([\s\S]*?)<\/a>/gi)].map((m) =>
      sanitizeText(decodeHtmlEntities(m[1].replace(/<[^>]+>/g, ' ')), 350)
    );

    const extracted = [];
    const maxLen = Math.max(titles.length, snippets.length);
    for (let i = 0; i < maxLen; i += 1) {
      const t = titles[i] || '';
      const s = snippets[i] || '';
      const combined = `${t} ${s}`;
      if (!hasRelevantKeywordOverlap(combined, titleWords, modelToken, sku)) {
        continue;
      }
      extracted.push(...extractPricesFromText(combined, currency));
    }

    return {
      ok: true,
      extracted,
      refinedTitle: pickRefinedTitle(titles, title, brand)
    };
  } catch (err) {
    return {
      ok: false,
      extracted: [],
      refinedTitle: null,
      reason: err && err.name === 'AbortError' ? 'Web price search timed out.' : 'Web price search unavailable.'
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Performs a safe, time-bounded multi-stage web search on DuckDuckGo HTML to discover real-world
 * market prices and product names when Gemini or direct store scraping is unavailable.
 *
 * @param {{ title: string, brand: string, sku: string, retailerName?: string, currency: string, enableWebSearch?: boolean }} params
 */
async function searchWebForProductPrice({
  title,
  brand,
  sku,
  retailerName = '',
  currency = 'EUR',
  enableWebSearch = true
}) {
  if (!enableWebSearch) {
    return { found: false, reason: 'Web price search disabled.' };
  }

  const cleanWords = sanitizeText(title, 100)
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length >= 3 && !['the', 'and', 'for', 'with', 'silver', 'black', 'white'].includes(w));
  const titleWords = cleanWords.slice(0, 5);
  const modelToken = extractModelToken(title);

  const currHint =
    currency === 'GBP' ? '£ OR GBP' : currency === 'USD' ? '$ OR USD' : currency === 'CHF' ? 'CHF' : '€ OR EUR';
  const primaryQuery = buildSearchQuery(title, brand, sku, currency);
  const coreTerms = titleWords.slice(0, 4).join(' ');
  const fallbackQuery = `${brand ? `${brand} ` : ''}${coreTerms} ${retailerName || 'idealo OR geizhals OR amazon'} ${currHint}`.trim();

  const first = await runSingleDuckDuckGoQuery(primaryQuery, currency, titleWords, modelToken, sku, brand, title);
  let extracted = first.extracted;
  let refinedTitle = first.refinedTitle;
  let usedQuery = primaryQuery;

  if (extracted.length < 2 && fallbackQuery !== primaryQuery) {
    const second = await runSingleDuckDuckGoQuery(fallbackQuery, currency, titleWords, modelToken, sku, brand, title);
    if (second.extracted.length > 0) {
      extracted = [...extracted, ...second.extracted];
      usedQuery = `${primaryQuery} + fallback`;
    }
    if (!refinedTitle && second.refinedTitle) {
      refinedTitle = second.refinedTitle;
    }
  }

  if (extracted.length === 0) {
    return {
      found: false,
      refinedTitle,
      query: usedQuery,
      reason: first.reason || 'No explicit numeric retail price tags found in public search snippets.'
    };
  }

  const sameCurr = extracted.filter((e) => e.isSameCurrency);
  const pool = sameCurr.length > 0 ? sameCurr : extracted;

  const sortedPrices = pool.map((e) => e.normalizedPrice).sort((a, b) => a - b);
  const median = sortedPrices[Math.floor(sortedPrices.length / 2)];

  const coherent = sortedPrices.filter((p) => p >= median * 0.45 && p <= median * 2.2);
  const finalPrices = coherent.length > 0 ? coherent : sortedPrices;

  const lowestObserved = finalPrices[0];
  const highestObserved = finalPrices[finalPrices.length - 1];
  const typicalStreet = finalPrices[Math.floor(finalPrices.length / 2)];

  return {
    found: true,
    query: usedQuery,
    refinedTitle,
    currentPrice: Number(typicalStreet.toFixed(2)),
    lowestObserved: Number(lowestObserved.toFixed(2)),
    highestObserved: Number(highestObserved.toFixed(2)),
    sampleCount: finalPrices.length,
    samplePrices: finalPrices.slice(0, 8),
    sourceNote: `Discovered ${finalPrices.length} live web price point(s) via public search index (${finalPrices.slice(0, 4).map((p) => `${p.toFixed(2)} ${currency}`).join(', ')})`
  };
}

module.exports = {
  buildSearchQuery,
  extractPricesFromText,
  searchWebForProductPrice
};
