'use strict';

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

function buildDirectStoreSearchUrl({ retailerName, title, sku, currency, normalizedUrl, retailerDomain, isTargetStore }) {
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
  if (key === 'coolblue') return `https://www.coolblue.de/suchen?query=${q}`;
  if (key === 'cyberport') return `https://www.cyberport.de/tools/search-results.html?autosuggest=false&q=${q}`;
  if (key === 'aboutyou') return `https://www.aboutyou.de/suche?term=${q}`;
  if (key === 'home24') return `https://www.home24.de/search?query=${q}`;
  if (key === 'wayfair') return `https://www.wayfair.de/keyword.php?keyword=${q}`;
  if (key === 'asos') return `https://www.asos.com/de/search/?q=${q}`;

  return `https://www.google.com/search?tbm=shop&q=${encodeURIComponent(`${retailerName} ${queryText}`)}`;
}

/**
 * Generates an HTTPS merchant link for any competitor offer and applies configured
 * Amazon Associates / Awin / Sovrn affiliate tracking without influencing deal scores.
 */
function buildMerchantOfferLink(context) {
  const baseUrl = buildDirectStoreSearchUrl(context);
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
      isTargetStore: Boolean(comp.isTargetStore)
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

