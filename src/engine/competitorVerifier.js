'use strict';

const { validateAndNormalizeProductUrl, safeFetchProductSignals } = require('../security/urlGuard');
const {
  identifyRetailer,
  isAggregatorOrNonRetailHost,
  isReputableRetailerHost
} = require('./retailerCatalog');

const ALWAYS_STANDALONE_ACCESSORY_KEYWORDS = [
  'silikonhülle',
  'schutzhülle',
  'hülle',
  'schutzfolie',
  'panzerglas',
  'screen protector',
  'ersatzteil',
  'ersatzteile',
  'zubehör',
  'ersatzklinge',
  'scherkopf',
  'ersatz',
  'replacement',
  'spare',
  'refurbished',
  'gebraucht',
  'b-ware',
  'used',
  'open box',
  'second chance',
  'generalüberholt',
  'retourenware'
];

const CONTEXTUAL_ACCESSORY_KEYWORDS = [
  'charging case',
  'ladecase',
  'case',
  'cover',
  'etui',
  'tasche',
  'ohrpolster',
  'ear tips',
  'eartips',
  'kabel',
  'cable',
  'adapter',
  'strap',
  'armband'
];

const NON_PRODUCT_PATH_PATTERNS = [
  /\/(?:page|testsieger|ratgeber|beratung|magazin|blog|news|review|reviews|test|im-test|vergleich|buying-guide|guide)\b/i,
  /\/(?:suche|search|katalog|kategorie|category|categories|marken|brands|collections|listing|filter|sortiment|produktwelt|themenwelt)\b/i,
  /\/c\//i,
  /[?&](?:marke|serie|s|k|q|query|search|filter)=/i,
  /^\/?$/
];

const MERCHANT_PRODUCT_PATH_GUARDS = [
  { hostRx: /(?:^|\.)otto\.de$/, pathRx: /\/p\//i },
  { hostRx: /(?:^|\.)kaufland\.de$/, pathRx: /\/product\//i },
  { hostRx: /(?:^|\.)aboutyou\.(?:de|com)$/, pathRx: /\/p\//i },
  { hostRx: /(?:^|\.)snipes\.com$/, pathRx: /\/p\//i },
  { hostRx: /(?:^|\.)(?:mediamarkt|saturn)\./, pathRx: /\/product\//i },
  { hostRx: /(?:^|\.)(?:galaxus|digitec)\./, pathRx: /\/product\//i },
  { hostRx: /(?:^|\.)coolblue\./, pathRx: /\/(?:product|produkt)\//i }
];

const CURRENCY_TO_EUR = {
  EUR: 1,
  USD: 0.92,
  GBP: 1.18,
  CHF: 1.06
};

function convertApproxCurrency(amount, fromCurr, toCurr) {
  if (!fromCurr || !toCurr || fromCurr === toCurr) return amount;
  const inEur = amount * (CURRENCY_TO_EUR[fromCurr] || 1);
  return Number((inEur / (CURRENCY_TO_EUR[toCurr] || 1)).toFixed(2));
}

function normalizeModelCode(token) {
  return String(token || '')
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

const RETAILER_INTERNAL_SKU_RX = /^(?:B0[A-Z0-9]{8}|[A-Z0-9]{4,12}-[A-Z]\d{2}|(?:S0|CS0)[A-Z0-9]{5,}|C\d{7,})$/i;

/**
 * Extracts manufacturer model identifiers (e.g., WF-1000XM6, E3040644, 51-B1000S, OLED55C4)
 * while ignoring retailer-internal SKUs like Amazon ASINs (B0...), Zalando SKUs (AD115O03M-A11), or Otto IDs (S0.../C199...).
 */
function extractModelTokens(text, extraSku = '') {
  const tokens = new Set();
  const rawText = String(text || '');
  const matches = rawText.match(/\b[A-Za-z]{1,5}-?\d{2,6}[A-Za-z0-9-]*\b/g) || [];
  for (const m of matches) {
    if (/^\d+$/.test(m)) continue;
    if (/^(?:100|240)v$|^\d+gb$|^\d+tb$|^\d+cm$|^\d+mm$|^\d+w$|^\d+hz$|^\d+mah$/i.test(m)) continue;
    const norm = normalizeModelCode(m);
    if (norm.length >= 3) tokens.add(norm);
  }
  const cleanSku = String(extraSku || '').trim();
  if (
    cleanSku &&
    cleanSku !== 'UNSPECIFIED' &&
    !RETAILER_INTERNAL_SKU_RX.test(cleanSku) &&
    /[A-Za-z]/.test(cleanSku) &&
    /\d/.test(cleanSku) &&
    (rawText.toLowerCase().includes(cleanSku.toLowerCase()) || /catalog product/i.test(rawText))
  ) {
    tokens.add(normalizeModelCode(cleanSku));
  }
  return Array.from(tokens);
}

function isNonProductUrl(urlStr) {
  try {
    const parsed = new URL(urlStr);
    const fullPath = `${parsed.pathname}${parsed.search}`;
    if (parsed.pathname === '/' || parsed.pathname === '') return true;
    const hostLower = parsed.hostname.toLowerCase();
    if (MERCHANT_PRODUCT_PATH_GUARDS.some((g) => g.hostRx.test(hostLower) && !g.pathRx.test(parsed.pathname))) {
      return true;
    }
    return NON_PRODUCT_PATH_PATTERNS.some((rx) => rx.test(fullPath));
  } catch {
    return true;
  }
}

function isAccessoryMismatch(targetText, candidateText) {
  const targetLower = String(targetText || '').toLowerCase();
  const candLower = String(candidateText || '').toLowerCase();

  for (const word of ALWAYS_STANDALONE_ACCESSORY_KEYWORDS) {
    const rx = new RegExp(`\\b${word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'i');
    if (rx.test(candLower) && !rx.test(targetLower)) {
      return true;
    }
  }

  for (const word of CONTEXTUAL_ACCESSORY_KEYWORDS) {
    const esc = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const rx = new RegExp(`\\b${esc}\\b`, 'i');
    if (rx.test(candLower) && !rx.test(targetLower)) {
      const standaloneRx = new RegExp(
        `\\b${esc}\\s+(?:für|fuer|for|passend|kompatibel)\\b|^(?:[\\w-]+\\s+){0,2}(?:silikon|silicone|silicon|protective|schutz|ersatz|replacement|hard|soft|travel|reise)?\\s*${esc}\\b`,
        'i'
      );
      if (standaloneRx.test(candLower)) {
        return true;
      }
      const includedRx = new RegExp(
        `\\b(?:mit|inkl\\.?|inklusive|with|incl\\.?|including)\\s+(?:[\\w-]+\\s+){0,2}${esc}\\b`,
        'i'
      );
      if (!includedRx.test(candLower)) {
        return true;
      }
    }
  }

  return false;
}

const BUNDLE_SET_RX = /\b(?:pfannenset|topfset|messerset|kochtopfset|set|bundle|kombi|2er|3er|4er|5er|[2-9]-tlg|[2-9]-teilig|[2-9]er-set|[2-9]er-pack|multi[- ]?pack|twin[- ]?pack|sparpack|vorratspack)\b/i;

function extractDimensionValues(text, pattern) {
  const values = [];
  let m;
  while ((m = pattern.exec(text)) !== null) {
    const num = Number(String(m[1]).replace(',', '.'));
    if (Number.isFinite(num) && num > 0) values.push(num);
  }
  return values;
}

function extractStorageValuesGb(text) {
  const values = [];
  const rx = /\b(\d+)\s*(gb|tb)\b/gi;
  let m;
  while ((m = rx.exec(text)) !== null) {
    const num = Number(m[1]);
    const unit = m[2].toLowerCase();
    const gb = unit === 'tb' ? num * 1024 : num;
    if (Number.isFinite(gb) && gb >= 64) values.push(gb);
  }
  return values;
}

function setsAreDisjoint(listA, listB) {
  if (listA.length === 0 || listB.length === 0) return false;
  return !listA.some((a) => listB.some((b) => Math.abs(a - b) <= 0.1));
}

function hasVariantOrBundleMismatch(targetText, candidateText) {
  const targetLower = String(targetText || '').toLowerCase();
  const candLower = String(candidateText || '').toLowerCase();

  if (BUNDLE_SET_RX.test(candLower) && !BUNDLE_SET_RX.test(targetLower)) {
    return true;
  }

  const tCm = extractDimensionValues(targetLower, /(\d+(?:[.,]\d+)?)\s*(?:x\s*\d+(?:[.,]\d+)?\s*)?cm\b/gi);
  const cCm = extractDimensionValues(candLower, /(\d+(?:[.,]\d+)?)\s*(?:x\s*\d+(?:[.,]\d+)?\s*)?cm\b/gi);
  if (setsAreDisjoint(tCm, cCm)) return true;

  const tInch = extractDimensionValues(targetLower, /(\d+(?:[.,]\d+)?)\s*(?:zoll|inch(?:es)?)\b/gi);
  const cInch = extractDimensionValues(candLower, /(\d+(?:[.,]\d+)?)\s*(?:zoll|inch(?:es)?)\b/gi);
  if (setsAreDisjoint(tInch, cInch)) return true;

  const tStorage = extractStorageValuesGb(targetLower);
  const cStorage = extractStorageValuesGb(candLower);
  if (setsAreDisjoint(tStorage, cStorage)) return true;

  return false;
}

const STOPWORDS = new Set([
  'with', 'and', 'for', 'the', 'der', 'die', 'das', 'und', 'mit', 'für', 'von',
  'in', 'on', 'pro', 'plus', 'edition', 'series', 'new', 'neu', 'online', 'kaufen',
  'black', 'schwarz', 'silver', 'silber', 'white', 'weiss', 'weiß', 'grey', 'gray', 'blue', 'blau'
]);

function extractSignificantWords(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/[^a-z0-9äöüß-]+/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length >= 3 && !STOPWORDS.has(w) && !/^\d+$/.test(w));
}

const NON_MANUFACTURER_BRAND_NAMES = new Set([
  'amazon', 'mediamarkt', 'saturn', 'otto', 'zalando', 'galaxus', 'digitec',
  'coolblue', 'kaufland', 'aboutyou', 'ebay', 'lidl', 'home24', 'wayfair',
  'best buy', 'walmart', 'target', 'currys', 'argos', 'online', 'unknown'
]);

/**
 * Verifies that a candidate retailer page actually sells the same product rather than
 * a previous generation, accessory, spare part, bundle, different dimension, or blog/category page.
 */
function isSameProductMatch({ targetTitle, targetBrand, targetSku, candidateTitle, candidateUrl }) {
  if (!candidateUrl || isNonProductUrl(candidateUrl)) {
    return false;
  }

  let urlPathText = '';
  try {
    urlPathText = decodeURIComponent(new URL(candidateUrl).pathname).replace(/[-_/]+/g, ' ');
  } catch {
    urlPathText = '';
  }

  const combinedCandidate = `${candidateTitle || ''} ${urlPathText}`.trim();
  if (!combinedCandidate || combinedCandidate.length < 4) return false;

  if (isAccessoryMismatch(targetTitle, combinedCandidate)) {
    return false;
  }

  if (hasVariantOrBundleMismatch(targetTitle, combinedCandidate)) {
    return false;
  }

  const candNormalized = combinedCandidate.toLowerCase().replace(/[^a-z0-9]/g, '');
  const targetModels = extractModelTokens(targetTitle, targetSku);
  const candModels = extractModelTokens(combinedCandidate);

  if (targetModels.length > 0) {
    // At least one primary manufacturer model token must match cleanly
    const matchedTargetModel = targetModels.some((m) => candNormalized.includes(m));
    if (!matchedTargetModel) {
      return false;
    }
    // Reject sibling model generation confusion (e.g. WH-1000XM6 vs WF-1000XM6)
    const primaryTarget = targetModels[0];
    for (const cm of candModels) {
      if (cm !== primaryTarget && primaryTarget.length >= 5 && cm.slice(-4) === primaryTarget.slice(-4) && cm[0] !== primaryTarget[0]) {
        return false;
      }
    }
  }

  const combinedLower = combinedCandidate.toLowerCase();
  let candHostLower = '';
  try {
    candHostLower = new URL(candidateUrl).hostname.toLowerCase();
  } catch {
    candHostLower = '';
  }

  const brandLower = String(targetBrand || '').toLowerCase().trim();
  if (brandLower && brandLower.length >= 3 && !NON_MANUFACTURER_BRAND_NAMES.has(brandLower)) {
    const brandRoot = brandLower.split(/\s+/)[0].replace(/[^a-z0-9äöüß]/g, '');
    const escRoot = brandRoot.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const brandMatched =
      combinedLower.includes(brandLower) ||
      (brandRoot.length >= 3 &&
        (new RegExp(`\\b${escRoot}\\b`, 'i').test(combinedLower) || candHostLower.includes(brandRoot)));
    if (!brandMatched) {
      return false;
    }
  }

  const targetWords = extractSignificantWords(targetTitle);
  let hits = 0;
  for (const w of targetWords) {
    if (combinedLower.includes(w)) hits += 1;
  }
  const minRequiredHits = targetModels.length > 0 ? 1 : Math.min(2, targetWords.length);
  return hits >= minRequiredHits;
}

function isPriceCoherent(targetPrice, candidatePrice) {
  if (!Number.isFinite(candidatePrice) || candidatePrice <= 0) return false;
  if (!Number.isFinite(targetPrice) || targetPrice <= 0) return true;
  return candidatePrice >= targetPrice * 0.52 && candidatePrice <= targetPrice * 2.15;
}

/**
 * Safely follows Gemini Vertex AI Search grounding redirect URLs to discover the
 * underlying merchant product URL before running full SSRF validation.
 */
async function resolveGroundingUrl(rawUri, timeoutMs = 3500) {
  if (typeof rawUri !== 'string' || !rawUri.trim()) return null;
  let current = rawUri.trim();

  for (let hop = 0; hop < 3; hop += 1) {
    let parsed;
    try {
      parsed = new URL(current);
    } catch {
      return null;
    }

    if (parsed.hostname !== 'vertexaisearch.cloud.google.com') {
      return parsed.toString();
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();

    try {
      const res = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; RealPriceNoLiesBot/1.0)'
        }
      });
      const loc = res.headers.get('location');
      if (res.body && typeof res.body.cancel === 'function') {
        res.body.cancel().catch(() => {});
      }
      if (!loc) return null;
      current = new URL(loc, current).toString();
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
  return null;
}

/**
 * Resolves candidate merchant URLs from Gemini grounding chunks, DuckDuckGo search hits,
 * and Gemini JSON links, fetches those actual product pages live, verifies exact product match
 * and live price/stock, and returns ONLY genuine verified competing offers.
 */
async function verifyCompetitorOffers({
  targetTitle,
  targetBrand,
  targetSku,
  targetRetailerName,
  targetHostname,
  targetPrice,
  currency = 'EUR',
  groundingChunks = [],
  geminiCompetitors = [],
  ddgCandidates = []
}) {
  const targetRetailerLower = String(targetRetailerName || '').toLowerCase();
  const targetHostRoot = String(targetHostname || '').toLowerCase().replace(/^www2?\./, '');

  const rawCandidates = [];

  // 1. Resolve Google Search grounding redirect URLs from Gemini in parallel
  const resolvedGrounding = await Promise.all(
    (Array.isArray(groundingChunks) ? groundingChunks : [])
      .slice(0, 22)
      .map(async (ch) => {
        const realUrl = await resolveGroundingUrl(ch && ch.uri);
        if (!realUrl) return null;
        return {
          rawUrl: realUrl,
          hintTitle: (ch && ch.title) || '',
          fromRealSearch: true,
          hintPrice: (ch && Number.isFinite(Number(ch.hintPrice)) && Number(ch.hintPrice) > 0) ? Number(ch.hintPrice) : null,
          hintOutOfStock: Boolean(ch && ch.hintOutOfStock)
        };
      })
  );
  for (const item of resolvedGrounding) {
    if (item) rawCandidates.push(item);
  }

  // 2. Direct merchant hits discovered by fallback web search
  for (const ddg of Array.isArray(ddgCandidates) ? ddgCandidates.slice(0, 10) : []) {
    if (!ddg || !ddg.url) continue;
    rawCandidates.push({
      rawUrl: ddg.url,
      hintTitle: ddg.title || '',
      fromRealSearch: true,
      hintPrice: ddg.hintPrice || null
    });
  }

  // 3. Explicit URLs/prices from Gemini (URLs kept ONLY if live fetch verifies HTTP 200 + exact product match!)
  const geminiPriceByRetailer = new Map();
  for (const gc of Array.isArray(geminiCompetitors) ? geminiCompetitors : []) {
    if (!gc || !gc.retailer) continue;
    if (Number.isFinite(Number(gc.price)) && Number(gc.price) > 0) {
      geminiPriceByRetailer.set(String(gc.retailer).toLowerCase(), Number(gc.price));
    }
    if (typeof gc.url === 'string' && gc.url.startsWith('https://')) {
      rawCandidates.push({
        rawUrl: gc.url,
        hintTitle: gc.retailer,
        fromRealSearch: false,
        hintPrice: Number(gc.price) || null
      });
    }
  }

  // Deduplicate and filter strictly to reputable external retail product URLs
  const seenUrls = new Set();
  const filteredCandidates = [];

  for (const cand of rawCandidates) {
    let urlInfo;
    try {
      urlInfo = await validateAndNormalizeProductUrl(cand.rawUrl, { resolveDns: true });
    } catch {
      continue;
    }

    if (isAggregatorOrNonRetailHost(urlInfo.hostname) || !isReputableRetailerHost(urlInfo.hostname)) {
      continue;
    }

    const candHostRoot = urlInfo.hostname.toLowerCase().replace(/^www2?\./, '');
    const retailerProfile = identifyRetailer(urlInfo.hostname);
    if (
      candHostRoot === targetHostRoot ||
      retailerProfile.name.toLowerCase() === targetRetailerLower
    ) {
      continue;
    }

    if (isNonProductUrl(urlInfo.normalizedUrl)) {
      continue;
    }

    const dedupeKey = urlInfo.normalizedUrl.toLowerCase();
    if (seenUrls.has(dedupeKey)) continue;
    seenUrls.add(dedupeKey);

    filteredCandidates.push({
      ...cand,
      urlInfo,
      retailerName: retailerProfile.name
    });
  }

  // Prioritize real search URLs ahead of unverified JSON URLs, and select up to 2 per retailer for store diversity
  filteredCandidates.sort((a, b) => Number(b.fromRealSearch) - Number(a.fromRealSearch));
  const candidatesToFetch = [];
  const chosenSet = new Set();
  const perStoreCount = new Map();
  for (let pass = 1; pass <= 2 && candidatesToFetch.length < 12; pass += 1) {
    for (const cand of filteredCandidates) {
      if (candidatesToFetch.length >= 12) break;
      if (chosenSet.has(cand)) continue;
      const storeKey = cand.retailerName.toLowerCase();
      const count = perStoreCount.get(storeKey) || 0;
      if (count < pass) {
        candidatesToFetch.push(cand);
        chosenSet.add(cand);
        perStoreCount.set(storeKey, count + 1);
      }
    }
  }

  const fetchedResults = await Promise.allSettled(
    candidatesToFetch.map(async (cand) => {
      const sig = await safeFetchProductSignals(cand.urlInfo);
      const finalUrl = (sig && sig.finalUrl) || cand.urlInfo.normalizedUrl;

      // Immediately discard dead product pages (HTTP 404 / 410)
      if (sig && (sig.httpStatus === 404 || sig.httpStatus === 410)) {
        return null;
      }

      if (sig && sig.liveFetched && sig.metadata && sig.metadata.price > 0) {
        if (sig.metadata.inStock === false) return null;

        const pageTitle = sig.metadata.title || cand.hintTitle || '';
        if (
          !isSameProductMatch({
            targetTitle,
            targetBrand,
            targetSku,
            candidateTitle: pageTitle,
            candidateUrl: finalUrl
          })
        ) {
          return null;
        }

        const rawCurr = sig.metadata.currency || currency;
        const normalizedPrice = convertApproxCurrency(sig.metadata.price, rawCurr, currency);
        if (!isPriceCoherent(targetPrice, normalizedPrice)) {
          return null;
        }

        return {
          retailer: cand.retailerName,
          price: normalizedPrice,
          shipping: normalizedPrice >= 49 ? 'Free Standard Shipping' : 'Standard Shipping',
          stock: 'In Stock',
          directProductUrl: finalUrl,
          verifiedLive: true,
          verificationLabel: 'VERIFIED LIVE'
        };
      }

      // Tier 2: Direct reputable store page from real search grounding hit store bot-protection (not 404/410)
      if (cand.fromRealSearch && !cand.hintOutOfStock) {
        const slugOk = isSameProductMatch({
          targetTitle,
          targetBrand,
          targetSku,
          candidateTitle: cand.hintTitle || '',
          candidateUrl: finalUrl
        });
        if (!slugOk) return null;

        const storeLower = cand.retailerName.toLowerCase();
        const geminiMatchPrice =
          cand.hintPrice ||
          geminiPriceByRetailer.get(storeLower) ||
          geminiPriceByRetailer.get(`${storeLower}.de`) ||
          null;

        if (geminiMatchPrice && isPriceCoherent(targetPrice, geminiMatchPrice)) {
          return {
            retailer: cand.retailerName,
            price: Number(geminiMatchPrice.toFixed(2)),
            shipping: geminiMatchPrice >= 49 ? 'Free Standard Shipping' : 'Standard Shipping',
            stock: 'In Stock (Store Bot-Shielded)',
            directProductUrl: finalUrl,
            verifiedLive: false,
            verificationLabel: 'DIRECT STORE (SHIELDED)'
          };
        }
      }

      return null;
    })
  );

  // Deduplicate by canonical retailer name, preferring LIVE_VERIFIED and lowest price
  const bestByStore = new Map();
  for (const res of fetchedResults) {
    if (res.status !== 'fulfilled' || !res.value) continue;
    const offer = res.value;
    const key = offer.retailer.toLowerCase();
    const prev = bestByStore.get(key);
    if (!prev) {
      bestByStore.set(key, offer);
      continue;
    }
    if (offer.verifiedLive && !prev.verifiedLive) {
      bestByStore.set(key, offer);
    } else if (offer.verifiedLive === prev.verifiedLive && offer.price < prev.price) {
      bestByStore.set(key, offer);
    }
  }

  return Array.from(bestByStore.values())
    .sort((a, b) => a.price - b.price)
    .slice(0, 6);
}

module.exports = {
  extractModelTokens,
  hasVariantOrBundleMismatch,
  isAccessoryMismatch,
  isNonProductUrl,
  isPriceCoherent,
  isSameProductMatch,
  resolveGroundingUrl,
  verifyCompetitorOffers
};

