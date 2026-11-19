'use strict';

const { loadLocalEnv } = require('../config/env');
const { validateAndNormalizeProductUrl, safeFetchProductSignals } = require('../security/urlGuard');
const { identifyRetailer, inferCategory, inferCurrency, parseProductFromPath } = require('./retailerCatalog');
const { searchWebForProductPrice } = require('./webPriceSearch');
const { runGeminiGroundedProductResearch } = require('./geminiGroundedSearch');
const { analyzeProductPricing } = require('./priceIntelligence');
const { createAnalysisCache } = require('./analysisCache');
const { createConcurrencyQueue } = require('../security/concurrencyQueue');
const { getSharedRedisClient } = require('../storage/redisClient');
const { recordAnalysis } = require('../storage/trafficMetrics');

loadLocalEnv();

const analysisCache = createAnalysisCache({
  maxEntries: 5000,
  redisClient: getSharedRedisClient()
});
const globalAnalysisQueue = createConcurrencyQueue({
  maxConcurrent: Number(process.env.MAX_CONCURRENT_ANALYSES) || 15,
  maxQueueSize: 250,
  queueTimeoutMs: 18_000
});

const AI_ACCURACY_DISCLAIMER =
  'AI & DATA TRANSPARENCY NOTICE: RealPriceNoLies uses automated AI reasoning and multi-source retail heuristics to estimate historical pricing and deal quality. AI systems can make mistakes, misread dynamic merchant pages, or lag behind flash coupons, shipping fees, and third-party marketplace seller differences. Always verify the final checkout total, seller authenticity, and return terms directly on the retailer website before purchasing.';

/**
 * Formats currency amounts cleanly for analyst prose.
 */
function fmtMoney(amount, currency) {
  const symbol = currency === 'USD' ? '$' : currency === 'GBP' ? '£' : currency === 'CHF' ? 'CHF ' : '€';
  return `${symbol}${Number(amount).toFixed(2)}`;
}

/**
 * Generates sharp, monotone-truth forensic reasoning bullets deterministically.
 */
function buildDeterministicAnalysisNarrative(report) {
  const { product, pricing, scoring, bestAlternative } = report;
  const c = pricing.currency;
  const findings = [];

  const diffAvg = pricing.average90d - pricing.currentPrice;
  if (diffAvg > 0.5) {
    findings.push(
      `True market discount check: At ${fmtMoney(pricing.currentPrice, c)}, this listing trades ${fmtMoney(diffAvg, c)} (${scoring.realSavingsPct}%) below its true 90-day average of ${fmtMoney(pricing.average90d, c)}.`
    );
  } else if (diffAvg < -0.5) {
    findings.push(
      `Overpay warning: The current ${product.retailerName} price (${fmtMoney(pricing.currentPrice, c)}) is ${fmtMoney(Math.abs(diffAvg), c)} ABOVE the 90-day average of ${fmtMoney(pricing.average90d, c)}.`
    );
  } else {
    findings.push(
      `Baseline parity: Listed right on its 90-day rolling average of ${fmtMoney(pricing.average90d, c)} with no significant discount or surge.`
    );
  }

  if (scoring.fakeDiscountGapPct > 10 || pricing.prePromoHikeDetected) {
    findings.push(
      `UVP / anchor manipulation flag: The store references ${fmtMoney(pricing.claimedReferencePrice, c)} (-${scoring.claimedDiscountPct}% claimed), inflating perceived savings by ~${scoring.fakeDiscountGapPct.toFixed(1)} percentage points over actual historical street prices.`
    );
  } else if (pricing.claimedReferencePrice > pricing.currentPrice) {
    findings.push(
      `Honest reference price: The ${fmtMoney(pricing.claimedReferencePrice, c)} reference price aligns closely with historical launch/retail ranges without deceptive pre-promo spiking.`
    );
  } else {
    findings.push(
      `Transparent pricing: No inflated strike-through MSRP/UVP badge is distorting this listing.`
    );
  }

  if (bestAlternative && !bestAlternative.isTargetStore && bestAlternative.deltaVsTarget < -1) {
    findings.push(
      `Cross-shop arbitrage opportunity: ${bestAlternative.retailer} currently lists this item at ${fmtMoney(bestAlternative.price, c)} (${fmtMoney(Math.abs(bestAlternative.deltaVsTarget), c)} cheaper than ${product.retailerName}).`
    );
  } else {
    findings.push(
      `Cross-market leader: ${product.retailerName} is currently tied or leading all tracked competitors (${fmtMoney(pricing.lowest180d, c)} 180-day low recorded on ${pricing.lowest180dDate} at ${pricing.lowest180dRetailer}).`
    );
  }

  return {
    headline: scoring.verdictAction,
    findings,
    engineMode: 'Deterministic Forensic AI Price Engine v1.0'
  };
}

/**
 * Optionally enriches the verdict narrative with Google Gemini if GEMINI_API_KEY is configured.
 * Strictly bounded by a 3.5s timeout and falls back cleanly without failing the request.
 */
/**
 * Builds the transparent "Where We Got The Intel" provenance table.
 */
function buildIntelSources(urlInfo, report, engineMode) {
  const groundingList = report.meta.geminiGroundingSources || [];
  let webSourceText;
  let webStatus;
  if (report.meta.geminiGroundedUsed) {
    webSourceText =
      groundingList.length > 0
        ? `Live Google Search grounding cited: ${groundingList.join(', ')}.`
        : 'Verified via live Google Search grounding across active retail listings.';
    webStatus = 'LIVE WEB GROUNDED';
  } else if (report.meta.webSearchUsed) {
    webSourceText = report.meta.webSearchNote;
    webStatus = 'WEB VERIFIED';
  } else if (report.meta.matchedBenchmarkPreset) {
    webSourceText = 'Curated flagship benchmark database.';
    webStatus = 'PRESET INDEX';
  } else {
    webSourceText = report.meta.webSearchNote || 'Analyzed via structural subtype model.';
    webStatus = 'MODELLED INDEX';
  }

  return [
    {
      source: '1. URL Structural & SKU Forensic Parser',
      method: `Extracted store domain (${urlInfo.hostname}), SKU/ASIN (${report.product.sku}), and stripped ${urlInfo.strippedTrackers} tracking parameter(s).`,
      status: 'VERIFIED',
      weight: 'Identity & Privacy'
    },
    {
      source: '2. SSRF-Pinned Live Store Inspector',
      method: report.meta.liveFetchNote,
      status: report.meta.liveFetched ? 'LIVE FETCHED' : 'SHIELDED / FALLBACK',
      weight: 'Direct Offer'
    },
    {
      source: '3. Live Web & Search Grounding Research',
      method: webSourceText,
      status: webStatus,
      weight: 'Street Price Anchor'
    },
    {
      source: '4. 180-Day Historical Curve & Cross-Retailer Matrix',
      method: `Evaluated 26 weekly checkpoints (${report.priceHistory[0].date} to ${report.priceHistory[report.priceHistory.length - 1].date}) across ${report.competitors.length} retailers (${report.competitors.map((c) => c.retailer).join(', ')}).`,
      status: report.meta.matchedBenchmarkPreset ? 'CURATED BENCHMARK' : report.meta.geminiGroundedUsed ? 'GROUNDED MATRIX' : 'ANCHORED CURVE',
      weight: '85% of Score'
    },
    {
      source: '5. AI Deal Truth Synthesis Agent',
      method: `${engineMode} — evaluated price delta, UVP inflation gap, and timing recommendation.`,
      status: 'AI GENERATED',
      weight: 'Narrative & 15% Honesty Audit'
    }
  ];
}

/**
 * Main AI Agent entrypoint: validates URL against SSRF/injection attacks,
 * inspects safe public signals, runs live Google-Search-grounded Gemini research (with DuckDuckGo fallback),
 * computes 0-100 Deal Truth Score, and attaches transparent provenance + AI disclaimer.
 *
 * @param {string} rawUrl
 * @param {{ enableWebSearch?: boolean, enableGemini?: boolean }} [options]
 */
async function executeUncachedAnalysis(urlInfo, options) {
  const liveSignals = await safeFetchProductSignals(urlInfo);

  const retailer = identifyRetailer(urlInfo.hostname);
  const parsedPath = parseProductFromPath(urlInfo.pathname, retailer.id, retailer.name);
  const currency =
    (liveSignals.metadata && liveSignals.metadata.currency) ||
    inferCurrency(urlInfo.hostname, urlInfo.pathname);
  const liveTitle = liveSignals.metadata && liveSignals.metadata.title;
  const prelimTitle = liveTitle || parsedPath.title;
  const prelimBrand = (liveSignals.metadata && liveSignals.metadata.brand) || parsedPath.brand;
  const prelimCategory = inferCategory(prelimTitle, urlInfo.pathname, retailer);

  let geminiGrounded = { found: false, status: 'SKIPPED' };
  if (options.enableGemini !== false) {
    geminiGrounded = await runGeminiGroundedProductResearch({
      normalizedUrl: urlInfo.normalizedUrl,
      retailerName: retailer.name,
      retailerDomain: urlInfo.hostname,
      parsedTitle: parsedPath.title,
      liveTitle,
      brand: prelimBrand,
      sku: parsedPath.sku,
      category: prelimCategory,
      currency,
      livePrice: liveSignals.metadata && liveSignals.metadata.price,
      liveReferencePrice: liveSignals.metadata && liveSignals.metadata.referencePrice
    });
  }

  let webSearch = null;
  const needDuckDuckGoFallback =
    !geminiGrounded.found &&
    options.enableWebSearch !== false &&
    (!liveSignals.liveFetched || !liveSignals.metadata || !liveSignals.metadata.price);

  if (needDuckDuckGoFallback) {
    webSearch = await searchWebForProductPrice({
      title: prelimTitle,
      brand: prelimBrand,
      sku: parsedPath.sku,
      retailerName: retailer.name,
      currency,
      enableWebSearch: options.enableWebSearch !== false
    });
  }

  const report = analyzeProductPricing({ urlInfo, liveSignals, webSearch, geminiGrounded });

  const narrative =
    geminiGrounded.found && geminiGrounded.data.findings.length >= 2
      ? {
          headline: geminiGrounded.data.headline || report.scoring.verdictAction,
          findings: geminiGrounded.data.findings,
          engineMode: `Google Gemini (${geminiGrounded.model}) + Live Google Search Grounding`
        }
      : buildDeterministicAnalysisNarrative(report);

  report.meta.geminiStatus = geminiGrounded.status;
  report.meta.cachedResult = false;
  report.meta.deduplicatedInFlight = false;

  const intelSources = buildIntelSources(urlInfo, report, narrative.engineMode);

  return {
    analyzedAt: new Date().toISOString(),
    zeroPiiMode: true,
    ...report,
    aiAnalysis: narrative,
    intelSources,
    aiDisclaimer: AI_ACCURACY_DISCLAIMER
  };
}

/**
 * Main AI Agent entrypoint: validates URL against SSRF/injection attacks,
 * serves cached or deduplicated in-flight analyses under viral traffic spikes,
 * bounds concurrent scrapes via semaphore queue, and attaches provenance + AI disclaimer.
 *
 * @param {string} rawUrl
 * @param {{ enableWebSearch?: boolean, enableGemini?: boolean, bypassCache?: boolean, queue?: ReturnType<typeof createConcurrencyQueue>, workRunner?: Function }} [options]
 */
async function runDeepDealAnalysis(rawUrl, options = {}) {
  const urlInfo = await validateAndNormalizeProductUrl(rawUrl, { resolveDns: true });
  const cacheKey = urlInfo.normalizedUrl.toLowerCase();

  if (!options.bypassCache) {
    const cached = await analysisCache.getAsync(cacheKey);
    if (cached) {
      cached.product.strippedTrackers = urlInfo.strippedTrackers;
      cached.meta.cachedResult = true;
      cached.meta.deduplicatedInFlight = false;
      recordAnalysis({ retailerName: cached.product.retailerName, cached: true }).catch(() => {});
      return cached;
    }

    const existingPromise = analysisCache.getInFlight(cacheKey);
    if (existingPromise) {
      const shared = structuredClone(await existingPromise);
      shared.product.strippedTrackers = urlInfo.strippedTrackers;
      shared.meta.cachedResult = true;
      shared.meta.deduplicatedInFlight = true;
      recordAnalysis({ retailerName: shared.product.retailerName, cached: true }).catch(() => {});
      return shared;
    }
  }

  const queue = options.queue || globalAnalysisQueue;
  const runner = options.workRunner || (() => executeUncachedAnalysis(urlInfo, options));
  const workPromise = queue.run(runner);

  if (!options.bypassCache) {
    analysisCache.setInFlight(cacheKey, workPromise);
  }

  const finalResult = await workPromise;
  if (!options.bypassCache && finalResult) {
    await analysisCache.setAsync(cacheKey, finalResult);
  }
  if (finalResult && finalResult.product) {
    recordAnalysis({ retailerName: finalResult.product.retailerName, cached: false }).catch(() => {});
  }
  return structuredClone(finalResult);
}

module.exports = {
  AI_ACCURACY_DISCLAIMER,
  analysisCache,
  globalAnalysisQueue,
  runDeepDealAnalysis
};

