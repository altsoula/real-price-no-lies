'use strict';

const https = require('node:https');
const { sanitizeText } = require('../security/sanitizer');
const { parseLocalizedPrice } = require('../security/urlGuard');
const { defaultBudgetGuard } = require('./geminiBudgetGuard');
const {
  identifyRetailer,
  isAggregatorOrNonRetailHost,
  isReputableRetailerHost,
  resolveReputableRetailerName
} = require('./retailerCatalog');

const GEMINI_MODELS = [
  { name: 'gemini-3.5-flash', supportsThinkingBudget: true },
  { name: 'gemini-3.8-flash', supportsThinkingBudget: true },
  { name: 'gemini-3.1-flash-lite', supportsThinkingBudget: false }
];

const BLOCKED_SELLER_NAME_RX = /(idealo|geizhals|billiger|guenstiger|günstiger|check24|keepa|camelcamelcamel|pricerunner|kelkoo|preissuchmaschine|preisvergleich|google\s*shopping|mydealz|dealabs|hotukdeals|kleinanzeigen|temu|aliexpress|wish|dhgate|youtube|reddit|trustpilot)/i;

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

  const avg90Raw = toValidPrice(raw.average90d) || currentPrice;
  const low180Raw = toValidPrice(raw.lowest180d) || Math.round(Math.min(currentPrice, avg90Raw) * 0.9 * 100) / 100;
  const high180Raw = toValidPrice(raw.highest180d) || Math.round(Math.max(currentPrice, avg90Raw) * 1.1 * 100) / 100;
  const refRaw = toValidPrice(defaults.liveReferencePrice) || toValidPrice(raw.claimedReferencePrice);

  const lowest180d = Math.min(low180Raw, currentPrice, avg90Raw);
  const highest180d = Math.max(high180Raw, currentPrice, avg90Raw);
  const average90d = Math.max(lowest180d, Math.min(highest180d, avg90Raw));

  const avg30Raw = toValidPrice(raw.average30d);
  const average30d = avg30Raw
    ? Math.max(lowest180d, Math.min(highest180d, avg30Raw))
    : Math.round(((currentPrice * 0.45 + average90d * 0.55) * 100)) / 100;

  const low90Raw = toValidPrice(raw.lowest90d);
  const lowest90d = low90Raw
    ? Math.max(lowest180d, Math.min(currentPrice, low90Raw))
    : Math.max(lowest180d, Math.round(Math.min(currentPrice, average90d) * 0.95 * 100) / 100);

  const low30Raw = toValidPrice(raw.lowest30d);
  const lowest30d = low30Raw
    ? Math.max(lowest90d, Math.min(currentPrice, low30Raw))
    : Math.max(lowest90d, Math.round(Math.min(currentPrice, average30d) * 0.97 * 100) / 100);

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
    for (const item of raw.competitors.slice(0, 8)) {
      if (!item || typeof item !== 'object') continue;
      const storeName = sanitizeText(item.retailer || '', 48);
      const rawPrice = toValidPrice(item.price);
      if (!storeName || !rawPrice) continue;
      if (BLOCKED_SELLER_NAME_RX.test(storeName)) continue;

      let cleanUrl = null;
      let canonicalFromUrl = null;
      if (typeof item.url === 'string' && item.url.trim()) {
        if (!item.url.trim().startsWith('https://')) continue;
        try {
          const parsedUrl = new URL(item.url.trim());
          if (isAggregatorOrNonRetailHost(parsedUrl.hostname) || !isReputableRetailerHost(parsedUrl.hostname)) {
            continue;
          }
          cleanUrl = parsedUrl.toString();
          canonicalFromUrl = identifyRetailer(parsedUrl.hostname).name;
        } catch {
          continue;
        }
      }

      const canonicalFromName = resolveReputableRetailerName(storeName);
      const isTargetAlias = storeName.toLowerCase() === targetLower || storeName.toLowerCase().startsWith(`${targetLower}.`);

      // Reject unknown domain-like or unverified store names (e.g. jarvin.lv, lavar.jn)
      if (!canonicalFromUrl && !canonicalFromName && !isTargetAlias) {
        continue;
      }

      const finalRetailerName = isTargetAlias
        ? defaults.retailerName
        : canonicalFromUrl || canonicalFromName || storeName;
      const key = finalRetailerName.toLowerCase();
      if (seenStores.has(key)) continue;
      seenStores.add(key);
      // Lock the target store's price to verified currentPrice so comparison row always matches Current Listed Price
      const finalCompPrice = key === targetLower ? currentPrice : rawPrice;
      competitors.push({
        retailer: finalRetailerName,
        price: finalCompPrice,
        url: cleanUrl,
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
      url: null,
      shipping: currentPrice >= 49 ? 'Free Standard Shipping' : 'Standard Shipping',
      stock: 'In Stock'
    });
  }

  const lowestComp = competitors.reduce((best, c) => (c.price < best.price ? c : best), competitors[0]);
  const rawLowestRetailer = sanitizeText(raw.lowest180dRetailer || lowestComp.retailer, 48);
  const lowest180dRetailer = BLOCKED_SELLER_NAME_RX.test(rawLowestRetailer)
    ? lowestComp.retailer
    : rawLowestRetailer;

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
    average30d,
    lowest30d,
    average90d,
    lowest90d,
    lowest180d,
    lowest180dDate: validDate,
    lowest180dRetailer,
    highest180d,
    prePromoHikeDetected: Boolean(raw.prePromoHikeDetected),
    competitors: competitors.slice(0, 8),
    headline: typeof raw.headline === 'string' && raw.headline.trim() ? sanitizeText(raw.headline, 240) : null,
    findings
  };
}

function extractGroundingMetadata(outerResponse) {
  const meta = outerResponse?.candidates?.[0]?.groundingMetadata;
  const chunks = meta?.groundingChunks;
  if (!Array.isArray(chunks)) return { sources: [], chunkUrls: [] };

  const supports = Array.isArray(meta?.groundingSupports) ? meta.groundingSupports : [];
  const supportByChunkIdx = new Map();
  for (const sup of supports) {
    const segText = typeof sup?.segment?.text === 'string' ? sup.segment.text.trim() : '';
    const indices = Array.isArray(sup?.groundingChunkIndices) ? sup.groundingChunkIndices : [];
    if (!segText || indices.length === 0) continue;

    const variantMatch = segText.match(/\bvariant\s*:\s*([^|\n]+)/i);
    const priceMatch = segText.match(/\bprice\s*:\s*([^|\n]+)/i);
    const isOutOfStock = OUT_OF_STOCK_PROSE_RX.test(segText);
    const parsedHintTitle = variantMatch ? sanitizeText(variantMatch[1], 140) : sanitizeText(segText, 140);
    const parsedHintPrice = !isOutOfStock && priceMatch ? extractOfferPriceFromSegment(priceMatch[1]) : null;

    for (const idx of indices) {
      if (Number.isInteger(idx) && !supportByChunkIdx.has(idx)) {
        supportByChunkIdx.set(idx, {
          hintTitle: parsedHintTitle,
          hintPrice: parsedHintPrice,
          hintOutOfStock: isOutOfStock
        });
      }
    }
  }

  const sources = [];
  const seenSources = new Set();
  const chunkUrls = [];
  const seenUris = new Set();

  for (let i = 0; i < chunks.length; i += 1) {
    const ch = chunks[i];
    const uri = ch?.web?.uri;
    const rawTitle = ch?.web?.title;
    if (typeof rawTitle === 'string' && rawTitle.trim()) {
      const clean = sanitizeText(rawTitle, 60);
      if (!seenSources.has(clean.toLowerCase())) {
        seenSources.add(clean.toLowerCase());
        sources.push(clean);
      }
    }
    if (typeof uri === 'string' && uri.startsWith('https://') && !seenUris.has(uri)) {
      seenUris.add(uri);
      const supInfo = supportByChunkIdx.get(i);
      const fallbackTitle = typeof rawTitle === 'string' ? sanitizeText(rawTitle, 80) : '';
      chunkUrls.push({
        uri,
        title: (supInfo && supInfo.hintTitle) || fallbackTitle,
        hintPrice: (supInfo && supInfo.hintPrice) || null,
        hintOutOfStock: Boolean(supInfo && supInfo.hintOutOfStock)
      });
    }
  }
  return {
    sources: sources.slice(0, 8),
    chunkUrls: chunkUrls.slice(0, 22)
  };
}

function callGeminiModel({ apiKey, modelCfg, prompt, timeoutMs = 16000, maxOutputTokens = 1200, expectJson = true }) {
  const generationConfig = {
    temperature: 0,
    maxOutputTokens
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
            const groundingMeta = extractGroundingMetadata(outer);
            if (!expectJson) {
              resolve({
                ok: true,
                status: 'ACTIVE',
                model: modelCfg.name,
                text,
                groundingSources: groundingMeta.sources,
                groundingChunks: groundingMeta.chunkUrls
              });
              return;
            }
            const parsed = extractJsonObject(text);
            if (!parsed) {
              resolve({ ok: false, status: 'INVALID_JSON', groundingChunks: groundingMeta.chunkUrls });
              return;
            }
            resolve({
              ok: true,
              status: 'ACTIVE',
              model: modelCfg.name,
              data: parsed,
              groundingSources: groundingMeta.sources,
              groundingChunks: groundingMeta.chunkUrls
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

function extractOfferPriceFromSegment(segment) {
  if (typeof segment !== 'string' || !segment.trim()) return null;
  const cleaned = segment
    .replace(/[*`]/g, '')
    .split(/(?:\(|;\s|\b(?:uvp|regular|msrp|rrp|statt|was|third[- ]party|marketplace)\b)/i)[0]
    .trim();
  const currMatch = cleaned.match(
    /(?:€|EUR|£|GBP|\$|USD|CHF)\s*(\d[\d.,]*)|(\d[\d.,]*)\s*(?:€|EUR|£|GBP|\$|USD|CHF)/i
  );
  const rawNum = currMatch ? (currMatch[1] || currMatch[2]) : (cleaned.match(/(\d{1,5}(?:[.,]\d{2}))/) || [])[1];
  if (!rawNum) return null;
  const parsed = parseLocalizedPrice(rawNum);
  return toValidPrice(parsed);
}

function stripMarkdownTokens(str) {
  return String(str || '')
    .replace(/^#{1,6}\s*/, '')
    .replace(/^\d+[.)]\s*/, '')
    .replace(/^[-*•]\s*/, '')
    .replace(/[*_`[\]]+/g, ' ')
    .replace(/\([^)]*\)/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

const OUT_OF_STOCK_PROSE_RX = /\b(?:out of stock|not available|unavailable|nicht verfügbar|nicht auf lager|ausverkauft|derzeit nicht)\b/i;

/**
 * Extracts structured reputable retailer prices from Gemini's grounded retail search prose.
 */
function extractStorePricesFromProse(text, currency = 'EUR') {
  if (typeof text !== 'string' || !text.trim()) return [];
  const resultsByStore = new Map();
  let activeStore = null;
  let activeOutOfStock = false;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || /^-{3,}$/.test(line)) {
      if (/^-{3,}$/.test(line)) {
        activeStore = null;
        activeOutOfStock = false;
      }
      continue;
    }

    // 1. Structured bullet format: - Store: MediaMarkt | Price: 49.99 EUR | Stock: In Stock | Variant: ...
    if (/\bstore\s*:/i.test(line) && /\bprice\s*:/i.test(line)) {
      const storeMatch = line.match(/\bstore\s*:\s*([^|]+)/i);
      const priceMatch = line.match(/\bprice\s*:\s*([^|]+)/i);
      const stockMatch = line.match(/\bstock\s*:\s*([^|]+)/i);
      const rawStore = storeMatch ? stripMarkdownTokens(storeMatch[1]) : '';
      const canonical = rawStore && !BLOCKED_SELLER_NAME_RX.test(rawStore) ? resolveReputableRetailerName(rawStore) : null;
      const stockText = stockMatch ? stockMatch[1] : line;
      const parsedPrice = priceMatch ? extractOfferPriceFromSegment(priceMatch[1]) : null;
      if (canonical && parsedPrice && !OUT_OF_STOCK_PROSE_RX.test(stockText) && !OUT_OF_STOCK_PROSE_RX.test(line)) {
        const key = canonical.toLowerCase();
        if (!resultsByStore.has(key)) {
          resultsByStore.set(key, {
            retailer: canonical,
            price: parsedPrice,
            url: null,
            shipping: parsedPrice >= 49 ? 'Free Standard Shipping' : 'Standard Shipping',
            stock: 'In Stock'
          });
        }
      }
      continue;
    }

    // 2. Markdown heading per retailer (e.g. ### 1. **OTTO** or ### **1. MediaMarkt**)
    if (/^(?:#{1,4}\s|\*\*\d+[.)]|\d+\.\s*\*\*)/.test(line) && !/\b(?:price|preis|product page|url|link)\s*:/i.test(line)) {
      const cleanedHeading = stripMarkdownTokens(line).replace(/^\d+[.)]\s*/, '').split(/[:–-]/)[0].trim();
      const canonical =
        cleanedHeading && !BLOCKED_SELLER_NAME_RX.test(cleanedHeading)
          ? resolveReputableRetailerName(cleanedHeading)
          : null;
      activeStore = canonical;
      activeOutOfStock = OUT_OF_STOCK_PROSE_RX.test(line);
      if (activeStore && activeOutOfStock) {
        resultsByStore.delete(activeStore.toLowerCase());
      }
      continue;
    }

    if (activeStore && OUT_OF_STOCK_PROSE_RX.test(line)) {
      activeOutOfStock = true;
      resultsByStore.delete(activeStore.toLowerCase());
      continue;
    }

    // 3. Price line under an active heading (e.g. * **Price:** **€222.00**)
    if (activeStore && !activeOutOfStock && /\b(?:price|preis|aktueller preis)\s*[:*]/i.test(line)) {
      const afterLabel = line.replace(/^.*?\b(?:price|preis|aktueller preis)\s*[:*]+\s*/i, '');
      const parsedPrice = extractOfferPriceFromSegment(afterLabel);
      if (parsedPrice && !resultsByStore.has(activeStore.toLowerCase())) {
        resultsByStore.set(activeStore.toLowerCase(), {
          retailer: activeStore,
          price: parsedPrice,
          url: null,
          shipping: parsedPrice >= 49 ? 'Free Standard Shipping' : 'Standard Shipping',
          stock: 'In Stock'
        });
      }
      continue;
    }

    // 4. Inline bullet: - MediaMarkt: €49.99 (In Stock)
    const inlineMatch = line.match(/^[-*•]?\s*\*{0,2}([A-Za-z0-9& .-]{2,32}?)\*{0,2}\s*[:–-]\s*(.+)$/);
    if (inlineMatch) {
      const rawName = stripMarkdownTokens(inlineMatch[1]);
      if (rawName && !/^(?:price|preis|stock|variant|product|url|link|note|source)/i.test(rawName) && !BLOCKED_SELLER_NAME_RX.test(rawName)) {
        const canonical = resolveReputableRetailerName(rawName);
        if (canonical && !OUT_OF_STOCK_PROSE_RX.test(line)) {
          const parsedPrice = extractOfferPriceFromSegment(inlineMatch[2]);
          if (parsedPrice && !resultsByStore.has(canonical.toLowerCase())) {
            resultsByStore.set(canonical.toLowerCase(), {
              retailer: canonical,
              price: parsedPrice,
              url: null,
              shipping: parsedPrice >= 49 ? 'Free Standard Shipping' : 'Standard Shipping',
              stock: 'In Stock'
            });
          }
        }
      }
    }
  }

  return Array.from(resultsByStore.values());
}

const NOISE_MODIFIER_WORDS_RX = /\b(?:unisex|herren|damen|men|women|kinder|kids|flaggschiff|kabellos(?:e|er)?)\b/gi;
const PAREN_MATERIAL_OR_COLOR_RX = /^(?:edelstahl|stainless|aluminium|aluminum|titanium|schwarz|black|silber|silver|white|weiss|weiß|grey|gray|blue|blau|red|rot|beschichtung|induktion|induction|1-tlg)/i;

/**
 * Normalizes messy store titles into a concise, retail-neutral search name
 * (removing colorway suffixes, gender/boast modifiers, and marketing tail fluff while preserving key units and models).
 */
function buildCleanSearchProductName(rawTitle, brand = '') {
  let text = sanitizeText(rawTitle || '', 160);
  if (!text) return sanitizeText(brand || '', 80);

  // Simplify "28 x 5 cm" dimensions to primary "28 cm"
  text = text.replace(/(\d+(?:[.,]\d+)?)\s*x\s*\d+(?:[.,]\d+)?\s*cm\b/gi, '$1 cm');

  // Preserve key product noun + dimension/model from parentheticals while dropping specs/materials
  text = text.replace(/\(([^)]+)\)/g, (_full, inner, offset, fullStr) => {
    const beforeLower = fullStr.slice(0, offset).toLowerCase();
    const parts = inner.split(/[,;/]+/).map((s) => s.trim()).filter(Boolean);
    const kept = [];
    const hasUnit = parts.some((p) => /\b\d+(?:[.,]\d+)?\s*(?:cm|mm|zoll|inch|gb|tb|l)\b/i.test(p));
    for (let i = 0; i < parts.length; i += 1) {
      const part = parts[i];
      const unitOrModel =
        /\b\d+(?:[.,]\d+)?\s*(?:cm|zoll|inch|gb|tb)\b/i.test(part) ||
        /\b[A-Za-z]{1,5}-?\d{2,6}[A-Za-z0-9-]*\b/.test(part);
      if (unitOrModel) {
        kept.push(part);
      } else if (
        i === 0 &&
        hasUnit &&
        part.split(/\s+/).length <= 2 &&
        !PAREN_MATERIAL_OR_COLOR_RX.test(part) &&
        !beforeLower.includes(part.toLowerCase())
      ) {
        kept.push(part);
      }
    }
    return kept.length > 0 ? ` ${kept.join(' ')} ` : ' ';
  });

  // Drop colorway / sub-description dash segments (e.g. "SAMBA OG UNISEX - Low-Top-Sneaker - footwear white...")
  const dashSegments = text.split(/\s+-\s+/).map((s) => s.trim()).filter(Boolean);
  if (dashSegments.length >= 2) {
    const keptSegs = [dashSegments[0]];
    for (let i = 1; i < dashSegments.length; i += 1) {
      if (/\b[A-Za-z]{1,5}-?\d{2,6}[A-Za-z0-9-]*\b/.test(dashSegments[i]) && !/\b(?:footwear|weiss|weiß|white|black|schwarz)\b/i.test(dashSegments[i])) {
        keptSegs.push(dashSegments[i]);
      }
    }
    text = keptSegs.join(' ');
  }

  // Strip noisy boilerplate modifiers when enough meaningful words remain
  const withoutNoise = text.replace(NOISE_MODIFIER_WORDS_RX, ' ').replace(/\s+/g, ' ').trim();
  if (withoutNoise.split(/\s+/).length >= 2) {
    text = withoutNoise;
  }

  // Drop marketing comma tail clauses unless they carry a model code or key dimension
  const commaParts = text.split(/\s*,\s*/).map((s) => s.trim()).filter(Boolean);
  if (commaParts.length >= 2 && commaParts[0].split(/\s+/).length >= 4) {
    const keptComma = [commaParts[0]];
    for (let i = 1; i < commaParts.length; i += 1) {
      const part = commaParts[i];
      if (
        /\b\d+(?:[.,]\d+)?\s*(?:cm|zoll|inch|gb|tb)\b/i.test(part) ||
        /\b[A-Za-z0-9-]*\d+[A-Za-z][A-Za-z0-9-]*\b|\b[A-Za-z]+\d{2,}[A-Za-z0-9-]*\b/.test(part)
      ) {
        keptComma.push(part);
      }
    }
    text = keptComma.join(' ');
  }

  text = text.replace(/\s+/g, ' ').trim();

const MULTI_BRAND_RETAILERS = new Set([
  'amazon', 'mediamarkt', 'saturn', 'otto', 'zalando', 'galaxus', 'digitec',
  'coolblue', 'kaufland', 'ebay', 'cyberport', 'notebooksbilliger', 'alternate',
  'aboutyou', 'asos', 'breuninger', 'snipes', 'home24', 'wayfair', 'best buy',
  'walmart', 'target', 'currys', 'argos', 'john lewis', 'fnac', 'darty',
  'bol.com', 'proshop', 'alza', 'lidl', 'online', 'unknown'
]);

  // Prepend manufacturer brand root if absent (never prepend multi-brand store names like "Amazon")
  const cleanBrand = sanitizeText(brand || '', 48);
  const cleanBrandLower = cleanBrand.toLowerCase();
  if (cleanBrand && !MULTI_BRAND_RETAILERS.has(cleanBrandLower)) {
    const brandRoot = cleanBrandLower.split(/\s+/)[0];
    if (brandRoot && brandRoot.length >= 2 && !text.toLowerCase().includes(brandRoot)) {
      text = `${cleanBrand} ${text}`.trim();
    }
  }

  if (text.length > 82) {
    const truncated = text.slice(0, 82);
    const lastSpace = truncated.lastIndexOf(' ');
    text = (lastSpace > 30 ? truncated.slice(0, lastSpace) : truncated).trim();
  }
  return text;
}

function buildCompetitorStoreTargets(retailerName, retailerDomain, category, searchName, brand, currency) {
  const targetDomainRoot = String(retailerDomain || '').toLowerCase().replace(/^www2?\./, '');
  const targetNameKey = String(retailerName || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const haystack = `${category || ''} ${searchName || ''} ${brand || ''}`.toLowerCase();
  const brandLower = String(brand || '').toLowerCase();

  let candidates;
  if (currency === 'USD') {
    candidates = ['amazon.com', 'bestbuy.com', 'walmart.com', 'target.com', 'apple.com'];
  } else if (currency === 'GBP') {
    candidates = ['amazon.co.uk', 'currys.co.uk', 'argos.co.uk', 'johnlewis.com', 'asos.com', 'decathlon.co.uk'];
  } else if (/(apparel|footwear|fashion|sneaker|shoe|clothing|bekleidung|schuh|jacke|hoodie|jeans|shirt)/.test(haystack)) {
    candidates = [];
    if (brandLower.includes('adidas') || haystack.includes('samba')) candidates.push('adidas.de');
    if (brandLower.includes('nike')) candidates.push('nike.com');
    candidates.push('zalando.de', 'aboutyou.de', 'otto.de', 'snipes.com', 'asos.com', 'breuninger.com', 'amazon.de', 'decathlon.de');
  } else if (currency === 'CHF') {
    candidates = ['digitec.ch', 'galaxus.ch', 'mediamarkt.ch', 'amazon.de', 'zalando.ch', 'otto.de', 'ikea.com'];
  } else if (/(furniture|stuhl|drehstuhl|sofa|tisch|bett|schrank|möbel|lamp|rug|chair|desk|regal|kommode)/.test(haystack)) {
    candidates = ['ikea.com', 'home24.de', 'otto.de', 'wayfair.de', 'amazon.de', 'kaufland.de', 'galaxus.de'];
  } else if (/(cookware|kitchen|appliance|personal care|beauty|pfanne|bratpfanne|topf|kaffee|staubsauger|rasierer|shaver|küche|haushalt)/.test(haystack)) {
    candidates = ['amazon.de', 'mediamarkt.de', 'saturn.de', 'galaxus.de', 'otto.de', 'kaufland.de', 'lidl.de'];
  } else {
    candidates = ['amazon.de', 'mediamarkt.de', 'saturn.de', 'coolblue.de', 'galaxus.de', 'otto.de', 'cyberport.de', 'notebooksbilliger.de', 'alternate.de'];
  }

  const targetDomains = candidates.filter((dom) => {
    const cleanDom = dom.toLowerCase();
    if (cleanDom === targetDomainRoot) return false;
    const domBase = cleanDom.split('.')[0].replace(/[^a-z0-9]/g, '');
    if (targetNameKey && (domBase === targetNameKey || (targetNameKey === 'applestore' && domBase === 'apple'))) {
      return false;
    }
    return true;
  });

  return Array.from(new Set(targetDomains)).slice(0, 7);
}

async function discoverCompetitorStoresWithGemini({
  apiKey,
  searchName,
  brand,
  sku,
  category,
  retailerName,
  retailerDomain,
  currency,
  todayIso,
  preferredModelIndex = 0
}) {
  if (!searchName || /catalog product/i.test(searchName)) {
    return { ok: false, groundingChunks: [], groundingSources: [], competitors: [] };
  }

  const cleanSearchName = buildCleanSearchProductName(searchName, brand);
  const targetDomains = buildCompetitorStoreTargets(
    retailerName,
    retailerDomain,
    category,
    cleanSearchName,
    brand,
    currency
  );
  if (targetDomains.length === 0) {
    return { ok: false, groundingChunks: [], groundingSources: [], competitors: [] };
  }

  const skuNote =
    sku && sku !== 'UNSPECIFIED' && !/^B0[A-Z0-9]{8}$/i.test(sku) && !cleanSearchName.toLowerCase().includes(sku.toLowerCase())
      ? ` (model/SKU: ${sku})`
      : '';

  const priorityDomains = targetDomains.slice(0, 5).join(', ');
  const promptB = [
    `Today is ${todayIso}. Run Google Searches using site: queries to find live direct product pages selling ${cleanSearchName}${skuNote} in ${currency} on these retail websites: ${targetDomains.join(', ')}.`,
    `Make sure to search at least these priority stores directly: ${priorityDomains} (do NOT search idealo, geizhals, billiger, check24, or keepa).`,
    'For every matching live retail product page you find, output one bullet line:',
    `- Store: <Store Name> | Price: <numeric price> ${currency} | Stock: <In Stock or Out of Stock> | Variant: <exact product title>`,
    'Exclude accessories, spare parts, category pages, and multi-item bundles.'
  ].join('\n');

  const orderedModels =
    preferredModelIndex > 0 && preferredModelIndex < GEMINI_MODELS.length
      ? [GEMINI_MODELS[preferredModelIndex], ...GEMINI_MODELS.filter((_, i) => i !== preferredModelIndex)]
      : GEMINI_MODELS.slice(0, 2);

  for (const modelCfg of orderedModels) {
    const res = await callGeminiModel({
      apiKey,
      modelCfg,
      prompt: promptB,
      timeoutMs: 16000,
      maxOutputTokens: 900,
      expectJson: false
    });
    if (res.ok) {
      return {
        ok: true,
        groundingChunks: res.groundingChunks || [],
        groundingSources: res.groundingSources || [],
        competitors: extractStorePricesFromProse(res.text, currency)
      };
    }
    if (res.status === 'CREDITS_DEPLETED_402' || res.status === 'AUTH_ERROR') {
      break;
    }
  }

  return { ok: false, groundingChunks: [], groundingSources: [], competitors: [] };
}

function mergeUniqueChunks(primaryChunks = [], secondaryChunks = [], cap = 24) {
  const seen = new Set();
  const out = [];
  for (const ch of [...primaryChunks, ...secondaryChunks]) {
    if (!ch || typeof ch.uri !== 'string' || !ch.uri.startsWith('https://')) continue;
    if (seen.has(ch.uri)) continue;
    seen.add(ch.uri);
    out.push(ch);
    if (out.length >= cap) break;
  }
  return out;
}

function mergeUniqueSources(primarySources = [], secondarySources = [], cap = 8) {
  const seen = new Set();
  const out = [];
  for (const src of [...primarySources, ...secondarySources]) {
    if (typeof src !== 'string' || !src.trim()) continue;
    const key = src.trim().toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(src.trim());
    if (out.length >= cap) break;
  }
  return out;
}

function mergeProseCompetitors(baseCompetitors = [], proseCompetitors = [], targetRetailerName = '') {
  const targetLower = String(targetRetailerName || '').toLowerCase();
  const byStore = new Map();
  for (const c of baseCompetitors) {
    if (!c || !c.retailer) continue;
    byStore.set(c.retailer.toLowerCase(), { ...c });
  }
  for (const pc of proseCompetitors) {
    if (!pc || !pc.retailer) continue;
    const key = pc.retailer.toLowerCase();
    if (key === targetLower) continue;
    const existing = byStore.get(key);
    if (!existing) {
      byStore.set(key, pc);
    } else if (!existing.url) {
      // Prefer live-searched prose store price over Call A JSON estimate for shielded stores
      byStore.set(key, { ...existing, price: pc.price, stock: pc.stock || existing.stock });
    }
  }
  return Array.from(byStore.values()).slice(0, 10);
}

/**
 * Runs dual-focus live Google Search-grounded Gemini research for any product URL:
 * - Call A: 30/90/180-day market price history + structured synthesis
 * - Call B: Prose-first direct reputable retail product page discovery
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
  const initialName = liveTitle || parsedTitle;
  const hasRealInitialTitle = Boolean(initialName && !/catalog product/i.test(initialName));

  const promptA = [
    'You are RealPriceNoLies, a precise e-commerce price intelligence researcher.',
    `Today is ${todayIso}.`,
    'Use Google Search right now to research the real 30-day, 90-day, and 180-day price history (via idealo, geizhals, keepa, camelcamelcamel, and major stores) for this exact product:',
    `- Target Product URL: ${normalizedUrl}`,
    `- Target Retailer: ${retailerName} (${retailerDomain})`,
    `- Product Name: ${initialName}`,
    `- Brand / SKU / ASIN: ${brand || 'Unknown'} / ${sku}`,
    `- Target Currency: ${currency}`,
    livePrice
      ? `- Observed Store Listing Price: ${livePrice} ${currency}${liveReferencePrice ? ` (Reference/UVP: ${liveReferencePrice} ${currency})` : ''}`
      : `- Find the current listing price at ${retailerName} (${retailerDomain}) via Google Search.`,
    'First write 2 short factual sentences summarizing the real price history and market offers you found from Google Search.',
    'Then output a fenced ```json code block with these exact fields:',
    '{',
    '  "title": "Exact clean product name (no store suffix)",',
    '  "brand": "Manufacturer/brand name",',
    '  "category": "Product category",',
    `  "currency": "${currency}",`,
    `  "currentPrice": ${livePrice || 0.0},`,
    `  "claimedReferencePrice": ${liveReferencePrice || 0.0},`,
    '  "average30d": 0.00,',
    '  "lowest30d": 0.00,',
    '  "average90d": 0.00,',
    '  "lowest90d": 0.00,',
    '  "lowest180d": 0.00,',
    '  "lowest180dDate": "YYYY-MM-DD",',
    '  "lowest180dRetailer": "Reputable store name",',
    '  "highest180d": 0.00,',
    '  "prePromoHikeDetected": false,',
    '  "competitors": [',
    '    {"retailer": "Reputable Store Name", "price": 0.00, "shipping": "Free Delivery or €X.XX", "stock": "In Stock"}',
    '  ],',
    '  "headline": "Concise 1-sentence factual verdict",',
    '  "findings": ["Bullet 1 with real price figures", "Bullet 2 comparing UVP vs 90d avg", "Bullet 3 comparing cheapest verified retailer"]',
    '}',
    'Note: NEVER include aggregators (idealo, geizhals, billiger.de, check24, keepa) or unknown/blog domains inside "competitors".'
  ].join('\n');

  async function runCallAWithFallback() {
    let lastStatus = 'UNAVAILABLE';
    for (let i = 0; i < GEMINI_MODELS.length; i += 1) {
      const modelCfg = GEMINI_MODELS[i];
      const res = await callGeminiModel({ apiKey, modelCfg, prompt: promptA, timeoutMs: 16000, maxOutputTokens: 1200, expectJson: true });
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
          return { ok: true, modelIndex: i, res, normalized };
        }
        lastStatus = 'NORMALIZATION_FAILED';
        continue;
      }

      if (res.status === 'CREDITS_DEPLETED_402' || res.status === 'AUTH_ERROR') {
        break;
      }
    }
    return { ok: false, status: lastStatus };
  }

  let callAResult;
  let callBResult;

  if (hasRealInitialTitle) {
    [callAResult, callBResult] = await Promise.all([
      runCallAWithFallback(),
      discoverCompetitorStoresWithGemini({
        apiKey,
        searchName: initialName,
        brand,
        sku,
        category,
        retailerName,
        retailerDomain,
        currency,
        todayIso
      })
    ]);
  } else {
    callAResult = await runCallAWithFallback();
    if (callAResult.ok) {
      callBResult = await discoverCompetitorStoresWithGemini({
        apiKey,
        searchName: callAResult.normalized.title,
        brand: callAResult.normalized.brand || brand,
        sku,
        category: callAResult.normalized.category || category,
        retailerName,
        retailerDomain,
        currency: callAResult.normalized.currency || currency,
        todayIso,
        preferredModelIndex: callAResult.modelIndex
      });
    } else {
      callBResult = { ok: false, groundingChunks: [], groundingSources: [], competitors: [] };
    }
  }

  if (!callAResult.ok) {
    return {
      found: false,
      status: callAResult.status,
      groundingChunks: callBResult.groundingChunks || []
    };
  }

  const mergedChunks = mergeUniqueChunks(
    callBResult.groundingChunks || [],
    callAResult.res.groundingChunks || [],
    24
  );
  const mergedSources = mergeUniqueSources(
    callAResult.res.groundingSources || [],
    callBResult.groundingSources || [],
    8
  );
  const mergedCompetitors = mergeProseCompetitors(
    callAResult.normalized.competitors,
    callBResult.competitors || [],
    retailerName
  );

  return {
    found: true,
    status: 'ACTIVE',
    model: callAResult.res.model,
    groundingSources: mergedSources,
    groundingChunks: mergedChunks,
    data: {
      ...callAResult.normalized,
      competitors: mergedCompetitors
    }
  };
}

module.exports = {
  buildCleanSearchProductName,
  extractJsonObject,
  extractStorePricesFromProse,
  normalizeGroundedData,
  runGeminiGroundedProductResearch
};

