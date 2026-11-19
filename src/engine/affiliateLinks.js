'use strict';

const { isAggregatorOrNonRetailHost, isReputableRetailerHost } = require('./retailerCatalog');

function cleanQueryTerm(title, sku) {
  const cleaned = String(title || '')
    .replace(/[|•()[\]]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const baseWords = cleaned.split(' ').slice(0, 6).join(' ');
  if (sku && sku !== 'UNSPECIFIED' && !baseWords.toUpperCase().includes(String(sku).toUpperCase())) {
    return `${baseWords} ${sku}`.trim();
  }
  return baseWords || String(sku || 'product');
}

function resolveAmazonBaseDomain(currency, targetHostname) {
  const hostLower = String(targetHostname || '').toLowerCase();
  if (hostLower.includes('amazon.co.uk') || currency === 'GBP') return 'www.amazon.co.uk';
  if (hostLower.includes('amazon.com') || currency === 'USD') return 'www.amazon.com';
  if (hostLower.includes('amazon.fr')) return 'www.amazon.fr';
  return 'www.amazon.de';
}

function getAmazonTagForHost(hostname) {
  const hostLower = String(hostname || '').toLowerCase();
  if (hostLower.includes('amazon.co.uk')) {
    return (process.env.AFFILIATE_AMAZON_UK_TAG || '').trim();
  }
  if (hostLower.includes('amazon.com')) {
    return (process.env.AFFILIATE_AMAZON_COM_TAG || '').trim();
  }
  return (process.env.AFFILIATE_AMAZON_DE_TAG || '').trim();
}

function getAwinMerchantId(retailerKey) {
  const envMap = {
    mediamarkt: 'AFFILIATE_AWIN_MEDIAMARKT_MID',
    saturn: 'AFFILIATE_AWIN_SATURN_MID',
    otto: 'AFFILIATE_AWIN_OTTO_MID',
    zalando: 'AFFILIATE_AWIN_ZALANDO_MID',
    coolblue: 'AFFILIATE_AWIN_COOLBLUE_MID',
    cyberport: 'AFFILIATE_AWIN_CYBERPORT_MID',
    aboutyou: 'AFFILIATE_AWIN_ABOUTYOU_MID',
    home24: 'AFFILIATE_AWIN_HOME24_MID',
    wayfair: 'AFFILIATE_AWIN_WAYFAIR_MID',
    asos: 'AFFILIATE_AWIN_ASOS_MID',
    ikea: 'AFFILIATE_AWIN_IKEA_MID',
    hm: 'AFFILIATE_AWIN_HM_MID'
  };
  const envName = envMap[retailerKey];
  return envName ? (process.env[envName] || '').trim() : '';
}

function normalizeStoreKey(name) {
  return String(name || '')
    .toLowerCase()
    .replace(/&/g, '')
    .replace(/[^a-z0-9]/g, '');
}

/**
 * Returns ONLY a reputable merchant's own direct product/search URL — never Google Shopping or aggregators.
 */
function buildDirectStoreSearchUrl({
  retailerName,
  title,
  sku,
  currency,
  normalizedUrl,
  retailerDomain,
  isTargetStore,
  directProductUrl
}) {
  if (typeof directProductUrl === 'string' && directProductUrl.startsWith('https://')) {
    try {
      const parsed = new URL(directProductUrl);
      if (!isAggregatorOrNonRetailHost(parsed.hostname) && isReputableRetailerHost(parsed.hostname)) {
        return parsed.toString();
      }
      if (isTargetStore) {
        return parsed.toString();
      }
    } catch {
      // Fall through to store lookup
    }
  }

  if (isTargetStore && typeof normalizedUrl === 'string' && normalizedUrl.startsWith('https://')) {
    return normalizedUrl;
  }

  const key = normalizeStoreKey(retailerName);
  const queryText = cleanQueryTerm(title, sku);
  const q = encodeURIComponent(queryText);

  if (key.includes('amazon')) {
    const dom = resolveAmazonBaseDomain(currency, retailerDomain);
    return `https://${dom}/s?k=${q}`;
  }
  if (key === 'mediamarkt') return `https://www.mediamarkt.de/de/search.html?query=${q}`;
  if (key === 'saturn') return `https://www.saturn.de/de/search.html?query=${q}`;
  if (key === 'ikea') return `https://www.ikea.com/de/en/search/?q=${q}`;
  if (key === 'otto') return `https://www.otto.de/suche/${encodeURIComponent(queryText.replace(/\s+/g, '-').toLowerCase())}/`;
  if (key === 'zalando') return `https://www.zalando.de/katalog/?q=${q}`;
  if (key === 'hm') return `https://www2.hm.com/de_de/search-results.html?q=${q}`;
  if (key === 'galaxus') return `https://www.galaxus.de/en/search?q=${q}`;
  if (key === 'digitec') return `https://www.digitec.ch/en/search?q=${q}`;
  if (key === 'coolblue') return `https://www.coolblue.de/suchen?query=${q}`;
  if (key === 'cyberport') return `https://www.cyberport.de/tools/search-results.html?autosuggest=false&q=${q}`;
  if (key === 'notebooksbilliger') return `https://www.notebooksbilliger.de/suche?search=${q}`;
  if (key === 'alternate') return `https://www.alternate.de/listing.xhtml?q=${q}`;
  if (key === 'proshop') return `https://www.proshop.de/?s=${q}`;
  if (key === 'alza') return `https://www.alza.de/search.htm?exps=${q}`;
  if (key === 'expert') return `https://www.expert.de/shop/suche?q=${q}`;
  if (key === 'euronics') return `https://www.euronics.de/search?search=${q}`;
  if (key === 'conrad') return `https://www.conrad.de/de/search.html?search=${q}`;
  if (key === 'thomann') return `https://www.thomann.de/de/search_dir.html?sw=${q}`;
  if (key === 'kaufland') return `https://www.kaufland.de/s/?search_value=${q}`;
  if (key === 'aboutyou') return `https://www.aboutyou.de/suche?term=${q}`;
  if (key === 'home24') return `https://www.home24.de/search?query=${q}`;
  if (key === 'wayfair') return `https://www.wayfair.de/keyword.php?keyword=${q}`;
  if (key === 'asos') return `https://www.asos.com/de/search/?q=${q}`;
  if (key === 'apple' || key === 'applestore') return `https://www.apple.com/de/search/${q}`;

  return null;
}

/**
 * Generates an HTTPS merchant link for any verified competitor offer and applies configured
 * Amazon Associates / Awin / Sovrn affiliate tracking without influencing deal scores.
 */
function buildMerchantOfferLink(context) {
  const baseUrl = buildDirectStoreSearchUrl(context);
  if (!baseUrl) return { offerUrl: null, isAffiliate: false };

  let parsedBase;
  try {
    parsedBase = new URL(baseUrl);
    if (parsedBase.protocol !== 'https:') return { offerUrl: null, isAffiliate: false };
  } catch {
    return { offerUrl: null, isAffiliate: false };
  }

  const key = normalizeStoreKey(context.retailerName);

  // 1. Amazon Associates Tagging
  if (key.includes('amazon') || parsedBase.hostname.includes('amazon.')) {
    const tag = getAmazonTagForHost(parsedBase.hostname);
    if (tag) {
      parsedBase.searchParams.set('tag', tag);
      return { offerUrl: parsedBase.toString(), isAffiliate: true };
    }
    return { offerUrl: parsedBase.toString(), isAffiliate: false };
  }

  // 2. Awin Partner Deeplink Wrapping
  const awinPubId = (process.env.AFFILIATE_AWIN_PUBLISHER_ID || '').trim();
  const awinMid = getAwinMerchantId(key);
  if (awinPubId && awinMid) {
    const awinUrl = `https://www.awin1.com/cread.php?awinmid=${encodeURIComponent(awinMid)}&awinaffid=${encodeURIComponent(awinPubId)}&ued=${encodeURIComponent(parsedBase.toString())}`;
    return { offerUrl: awinUrl, isAffiliate: true };
  }

  // 3. Sovrn Commerce Universal Fallback
  const sovrnKey = (process.env.AFFILIATE_SOVRN_KEY || '').trim();
  if (sovrnKey) {
    const sovrnUrl = `https://redirect.viglink.com?key=${encodeURIComponent(sovrnKey)}&u=${encodeURIComponent(parsedBase.toString())}`;
    return { offerUrl: sovrnUrl, isAffiliate: true };
  }

  return { offerUrl: parsedBase.toString(), isAffiliate: false };
}

function hasActiveAffiliatePartners() {
  return Boolean(
    (process.env.AFFILIATE_AMAZON_DE_TAG || '').trim() ||
      (process.env.AFFILIATE_AMAZON_COM_TAG || '').trim() ||
      (process.env.AFFILIATE_AMAZON_UK_TAG || '').trim() ||
      (process.env.AFFILIATE_AWIN_PUBLISHER_ID || '').trim() ||
      (process.env.AFFILIATE_SOVRN_KEY || '').trim()
  );
}

function enrichCompetitorsWithLinks(competitors, { title, sku, currency, normalizedUrl, retailerDomain }) {
  return competitors.map((comp) => {
    const linkInfo = buildMerchantOfferLink({
      retailerName: comp.retailer,
      title,
      sku,
      currency,
      normalizedUrl,
      retailerDomain,
      isTargetStore: Boolean(comp.isTargetStore),
      directProductUrl: comp.directProductUrl || null
    });
    return {
      ...comp,
      offerUrl: linkInfo.offerUrl,
      isAffiliate: linkInfo.isAffiliate
    };
  });
}

module.exports = {
  buildDirectStoreSearchUrl,
  buildMerchantOfferLink,
  enrichCompetitorsWithLinks,
  hasActiveAffiliatePartners
};
