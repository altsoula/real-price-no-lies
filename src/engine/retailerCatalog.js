'use strict';

const { sanitizeText } = require('../security/sanitizer');

/**
 * Known retailer definitions covering major European & global e-commerce providers.
 */
const RETAILER_PROFILES = [
  {
    id: 'amazon',
    name: 'Amazon',
    hosts: ['amazon.de', 'amazon.com', 'amazon.co.uk', 'amazon.fr', 'amazon.es', 'amazon.it', 'amazon.nl'],
    defaultCategory: 'Consumer Electronics & General Retail',
    tactics: ['Frequent algorithmic intraday repricing', 'Third-party marketplace vs. direct Amazon fulfillment splits', 'Reference UVP anchoring']
  },
  {
    id: 'mediamarkt',
    name: 'MediaMarkt',
    hosts: ['mediamarkt.de', 'mediamarkt.at', 'mediamarkt.nl', 'mediamarkt.es', 'mediamarkt.ch', 'mediamarkt.be'],
    defaultCategory: 'Consumer Electronics & Appliances',
    tactics: ['Weekend promotional flyers vs. online dynamic pricing', 'UVP strike-through anchoring', 'Club-only coupon bundles']
  },
  {
    id: 'saturn',
    name: 'Saturn',
    hosts: ['saturn.de', 'saturn.at'],
    defaultCategory: 'Consumer Electronics & Appliances',
    tactics: ['Shared MediaMarktSaturn inventory pricing parity', 'Flash weekend campaigns', 'MSRP anchor comparison']
  },
  {
    id: 'ikea',
    name: 'IKEA',
    hosts: ['ikea.com'],
    defaultCategory: 'Home & Furniture',
    tactics: ['High price stability across seasons', 'IKEA Family member markdowns', 'Regional store-stock price variance']
  },
  {
    id: 'otto',
    name: 'Otto',
    hosts: ['otto.de'],
    defaultCategory: 'Home, Electronics & Apparel Marketplace',
    tactics: ['Inflated UVP strike-through badges', 'Marketplace third-party vs. OTTO direct pricing', 'Installment-highlighted promo pricing']
  },
  {
    id: 'zalando',
    name: 'Zalando',
    hosts: ['zalando.de', 'zalando.co.uk', 'zalando.com', 'zalando.fr', 'zalando.nl', 'zalando.es', 'zalando.it', 'zalando.at'],
    defaultCategory: 'Apparel & Footwear',
    tactics: ['Size-dependent price fragmentation', 'Mid-season / end-of-season markdown waves', 'Dynamic demand repricing']
  },
  {
    id: 'hm',
    name: 'H&M',
    hosts: ['hm.com', 'www2.hm.com'],
    defaultCategory: 'Apparel & Fast Fashion',
    tactics: ['Frequent seasonal clearance drops', 'Member-tier 10-20% temporary windows', 'Colorway-specific markdowns']
  },
  {
    id: 'cyberport',
    name: 'Cyberport',
    hosts: ['cyberport.de', 'cyberport.at'],
    defaultCategory: 'Computing & Consumer Electronics',
    tactics: ['B2B/tech-focused transparent street pricing', 'Weekend Cyberdeals']
  },
  {
    id: 'galaxus',
    name: 'Galaxus',
    hosts: ['galaxus.de', 'galaxus.ch', 'galaxus.at'],
    defaultCategory: 'Consumer Electronics & General Retail',
    tactics: ['Publicly visible multi-month price graphs', 'Low-margin automated competitor matching']
  },
  {
    id: 'notebooksbilliger',
    name: 'Notebooksbilliger',
    hosts: ['notebooksbilliger.de'],
    defaultCategory: 'Computing & Gaming',
    tactics: ['Hardware bundle discounts', 'Flash tech deals']
  },
  {
    id: 'aboutyou',
    name: 'AboutYou',
    hosts: ['aboutyou.de', 'aboutyou.com'],
    defaultCategory: 'Apparel & Footwear',
    tactics: ['High-frequency promotional coupon codes', 'Inflated initial season RRP']
  },
  {
    id: 'asos',
    name: 'ASOS',
    hosts: ['asos.com'],
    defaultCategory: 'Apparel & Footwear',
    tactics: ['Rotating 20% sitewide promo codes', 'Outlet vs. full-price split']
  },
  {
    id: 'coolblue',
    name: 'Coolblue',
    hosts: ['coolblue.de', 'coolblue.nl', 'coolblue.be'],
    defaultCategory: 'Consumer Electronics & Appliances',
    tactics: ['Consistent street pricing with next-day delivery', 'Second-chance open-box offers']
  },
  {
    id: 'thomann',
    name: 'Thomann',
    hosts: ['thomann.de'],
    defaultCategory: 'Pro Audio & Musical Instruments',
    tactics: ['Strict European MAP price matching', '3-year warranty street baseline']
  },
  {
    id: 'ebay',
    name: 'eBay',
    hosts: ['ebay.de', 'ebay.com', 'ebay.co.uk'],
    defaultCategory: 'Marketplace & Refurbished Retail',
    tactics: ['Cross-seller condition variance', 'Coupon-driven net price drops']
  },
  {
    id: 'apple',
    name: 'Apple Store',
    hosts: ['apple.com'],
    defaultCategory: 'Computing & Consumer Electronics',
    tactics: ['Zero direct retail discounts (strict MSRP)', 'Typically 10-18% pricier than authorized third-party street prices']
  }
];

/**
 * Curated benchmark product presets across the 7 flagship stores so users can
 * test the platform with 1 click or inspect real-world pricing patterns.
 */
const PRESET_BENCHMARKS = [
  {
    id: 'amazon-sony-wh1000xm5',
    retailerId: 'amazon',
    label: 'Amazon · Sony WH-1000XM5',
    url: 'https://www.amazon.de/Sony-WH-1000XM5-Cancelling-Kopfh%C3%B6rer-Akkulaufzeit-Schwarz/dp/B09Y2MYL5C',
    title: 'Sony WH-1000XM5 Wireless Noise Cancelling Headphones (Black)',
    brand: 'Sony',
    sku: 'B09Y2MYL5C',
    category: 'Consumer Electronics & Audio',
    currency: 'EUR',
    currentPrice: 279.00,
    claimedReferencePrice: 419.00,
    average90d: 329.00,
    lowest180d: 269.00,
    lowest180dDate: '2026-09-14',
    lowest180dRetailer: 'Galaxus',
    highest180d: 389.00,
    prePromoHikeDetected: false,
    scenario: 'genuine_deal',
    competitors: [
      { retailer: 'Amazon', price: 279.00, shipping: 'Free Prime Delivery', stock: 'In Stock' },
      { retailer: 'Galaxus', price: 284.00, shipping: 'Free Shipping', stock: 'In Stock' },
      { retailer: 'MediaMarkt', price: 299.00, shipping: 'Free Pickup / €4.99', stock: 'In Stock' },
      { retailer: 'Saturn', price: 299.00, shipping: 'Free Pickup / €4.99', stock: 'In Stock' },
      { retailer: 'Cyberport', price: 309.00, shipping: '€5.99 Shipping', stock: 'In Stock' },
      { retailer: 'Otto', price: 329.00, shipping: '€2.95 Shipping', stock: 'In Stock' }
    ]
  },
  {
    id: 'mediamarkt-lg-oled',
    retailerId: 'mediamarkt',
    label: 'MediaMarkt · LG OLED55C4 55"',
    url: 'https://www.mediamarkt.de/de/product/_lg-oled55c47la-oled-tv-55-zoll-4k-uhd-2924511.html',
    title: 'LG OLED55C47LA 55" 4K UHD evo Smart TV',
    brand: 'LG',
    sku: '2924511',
    category: 'Home Entertainment & TVs',
    currency: 'EUR',
    currentPrice: 1149.00,
    claimedReferencePrice: 2399.00,
    average90d: 1269.00,
    lowest180d: 1099.00,
    lowest180dDate: '2026-10-08',
    lowest180dRetailer: 'Coolblue',
    highest180d: 1599.00,
    prePromoHikeDetected: false,
    scenario: 'solid_buy',
    competitors: [
      { retailer: 'MediaMarkt', price: 1149.00, shipping: '€29.90 Freight / Free Store Pickup', stock: 'In Stock' },
      { retailer: 'Saturn', price: 1149.00, shipping: '€29.90 Freight / Free Store Pickup', stock: 'In Stock' },
      { retailer: 'Coolblue', price: 1159.00, shipping: 'Free Delivery', stock: 'In Stock' },
      { retailer: 'Amazon', price: 1189.00, shipping: 'Free Delivery', stock: 'In Stock' },
      { retailer: 'Otto', price: 1299.00, shipping: '€29.95 Freight', stock: 'Limited' }
    ]
  },
  {
    id: 'saturn-dyson-v15',
    retailerId: 'saturn',
    label: 'Saturn · Dyson V15 Detect (Price Trap)',
    url: 'https://www.saturn.de/de/product/_dyson-v15-detect-absolute-stielsauger-2874190.html',
    title: 'Dyson V15 Detect Absolute Cordless Vacuum Cleaner',
    brand: 'Dyson',
    sku: '2874190',
    category: 'Home Appliances',
    currency: 'EUR',
    currentPrice: 749.00,
    claimedReferencePrice: 799.00,
    average90d: 629.00,
    lowest180d: 559.00,
    lowest180dDate: '2026-08-22',
    lowest180dRetailer: 'Amazon',
    highest180d: 779.00,
    prePromoHikeDetected: true,
    scenario: 'price_trap',
    competitors: [
      { retailer: 'Amazon', price: 589.00, shipping: 'Free Delivery', stock: 'In Stock' },
      { retailer: 'Coolblue', price: 599.00, shipping: 'Free Delivery', stock: 'In Stock' },
      { retailer: 'Galaxus', price: 615.00, shipping: 'Free Shipping', stock: 'In Stock' },
      { retailer: 'Otto', price: 669.00, shipping: '€2.95 Shipping', stock: 'In Stock' },
      { retailer: 'Saturn', price: 749.00, shipping: 'Free Pickup', stock: 'In Stock' }
    ]
  },
  {
    id: 'ikea-markus-chair',
    retailerId: 'ikea',
    label: 'IKEA · MARKUS Office Chair',
    url: 'https://www.ikea.com/de/de/p/markus-drehstuhl-vissle-dunkelgrau-70261150/',
    title: 'IKEA MARKUS Swivel Ergonomic Office Chair (Vissle Dark Grey)',
    brand: 'IKEA',
    sku: '70261150',
    category: 'Home & Office Furniture',
    currency: 'EUR',
    currentPrice: 179.00,
    claimedReferencePrice: 179.00,
    average90d: 179.00,
    lowest180d: 149.00,
    lowest180dDate: '2026-07-19',
    lowest180dRetailer: 'IKEA (IKEA Family Promo)',
    highest180d: 199.00,
    prePromoHikeDetected: false,
    scenario: 'standard_retail',
    competitors: [
      { retailer: 'IKEA', price: 179.00, shipping: 'Free Click & Collect / €19 Delivery', stock: 'In Stock' },
      { retailer: 'Otto (Marketplace)', price: 219.00, shipping: 'Free Delivery', stock: 'In Stock' },
      { retailer: 'Amazon (3rd Party)', price: 229.00, shipping: 'Free Delivery', stock: 'Low Stock' }
    ]
  },
  {
    id: 'otto-bosch-espresso',
    retailerId: 'otto',
    label: 'Otto · Bosch Espresso Machine (Pseudo-Discount)',
    url: 'https://www.otto.de/p/bosch-tie9032de-vero-bar-kaffeevollautomat-1748293012/',
    title: 'Bosch VeroBar TIE9032DE Fully Automatic Espresso Machine',
    brand: 'Bosch',
    sku: '1748293012',
    category: 'Kitchen & Home Appliances',
    currency: 'EUR',
    currentPrice: 699.00,
    claimedReferencePrice: 1149.00,
    average90d: 619.00,
    lowest180d: 549.00,
    lowest180dDate: '2026-09-02',
    lowest180dRetailer: 'Cyberport',
    highest180d: 739.00,
    prePromoHikeDetected: true,
    scenario: 'pseudo_discount',
    competitors: [
      { retailer: 'Cyberport', price: 579.00, shipping: 'Free Shipping', stock: 'In Stock' },
      { retailer: 'Amazon', price: 589.00, shipping: 'Free Delivery', stock: 'In Stock' },
      { retailer: 'MediaMarkt', price: 619.00, shipping: 'Free Pickup', stock: 'In Stock' },
      { retailer: 'Galaxus', price: 625.00, shipping: 'Free Shipping', stock: 'In Stock' },
      { retailer: 'Otto', price: 699.00, shipping: '€2.95 Shipping', stock: 'In Stock' }
    ]
  },
  {
    id: 'zalando-nike-pegasus',
    retailerId: 'zalando',
    label: 'Zalando · Nike Pegasus 41 Running Shoes',
    url: 'https://www.zalando.de/nike-performance-air-zoom-pegasus-41-laufschuh-neutral-n1242a2n0-q11.html',
    title: 'Nike Performance Air Zoom Pegasus 41 Neutral Running Shoes',
    brand: 'Nike',
    sku: 'N1242A2N0-Q11',
    category: 'Apparel & Footwear',
    currency: 'EUR',
    currentPrice: 89.95,
    claimedReferencePrice: 139.95,
    average90d: 114.50,
    lowest180d: 87.90,
    lowest180dDate: '2026-10-28',
    lowest180dRetailer: 'AboutYou',
    highest180d: 139.95,
    prePromoHikeDetected: false,
    scenario: 'genuine_deal',
    competitors: [
      { retailer: 'Zalando', price: 89.95, shipping: 'Free Delivery & Returns', stock: 'In Stock' },
      { retailer: 'AboutYou', price: 94.90, shipping: 'Free Delivery', stock: 'In Stock' },
      { retailer: 'ASOS', price: 104.99, shipping: 'Free over €45', stock: 'In Stock' },
      { retailer: 'Nike Official', price: 139.99, shipping: 'Free Member Delivery', stock: 'In Stock' },
      { retailer: 'Otto', price: 119.00, shipping: '€2.95 Shipping', stock: 'Limited Sizes' }
    ]
  },
  {
    id: 'hm-wool-coat',
    retailerId: 'hm',
    label: 'H&M · Wool-Blend Tailored Coat',
    url: 'https://www2.hm.com/de_de/productpage.1248912001.html',
    title: 'H&M Wool-Blend Double-Breasted Tailored Coat',
    brand: 'H&M',
    sku: '1248912001',
    category: 'Apparel & Fast Fashion',
    currency: 'EUR',
    currentPrice: 99.00,
    claimedReferencePrice: 119.00,
    average90d: 99.00,
    lowest180d: 69.99,
    lowest180dDate: '2026-07-29',
    lowest180dRetailer: 'H&M Seasonal Sale',
    highest180d: 119.00,
    prePromoHikeDetected: false,
    scenario: 'standard_retail',
    competitors: [
      { retailer: 'H&M', price: 99.00, shipping: 'Free Member over €30', stock: 'In Stock' },
      { retailer: 'AboutYou (Similar Tier)', price: 109.00, shipping: 'Free Delivery', stock: 'In Stock' },
      { retailer: 'ASOS', price: 112.50, shipping: 'Free Standard', stock: 'In Stock' },
      { retailer: 'Zalando', price: 105.00, shipping: 'Free Delivery', stock: 'In Stock' }
    ]
  }
];

function stripWww(hostname) {
  return hostname.replace(/^(?:www2?|shop|store|m|de|en)\./, '');
}

/**
 * Matches a hostname against known online retailer profiles or creates a clean generic profile.
 * @param {string} hostname
 */
function identifyRetailer(hostname) {
  const lower = hostname.toLowerCase();
  for (const profile of RETAILER_PROFILES) {
    for (const host of profile.hosts) {
      if (lower === host || lower.endsWith(`.${host}`)) {
        return {
          ...profile,
          matchedHost: lower,
          isKnownPartnerTier: true
        };
      }
    }
  }

  const root = stripWww(lower);
  const labelPart = root.split('.')[0] || 'retailer';
  const displayName = labelPart.charAt(0).toUpperCase() + labelPart.slice(1);
  return {
    id: labelPart,
    name: displayName,
    hosts: [lower],
    defaultCategory: 'General E-Commerce Retail',
    tactics: [
      'Dynamic marketplace pricing adjustments',
      'Standard manufacturer MSRP vs. street price variance'
    ],
    matchedHost: lower,
    isKnownPartnerTier: false
  };
}

/**
 * Determines expected retail currency based on domain TLD and store region.
 * @param {string} hostname
 * @param {string} pathname
 */
function inferCurrency(hostname, pathname) {
  const lowerHost = hostname.toLowerCase();
  const lowerPath = pathname.toLowerCase();
  if (lowerHost.endsWith('.co.uk') || lowerPath.startsWith('/uk/') || lowerPath.startsWith('/en_gb/')) {
    return 'GBP';
  }
  if (lowerHost.endsWith('.ch') || lowerPath.startsWith('/ch/')) {
    return 'CHF';
  }
  if (
    lowerHost.endsWith('.de') ||
    lowerHost.endsWith('.at') ||
    lowerHost.endsWith('.nl') ||
    lowerHost.endsWith('.fr') ||
    lowerHost.endsWith('.es') ||
    lowerHost.endsWith('.it') ||
    lowerHost.endsWith('.be') ||
    lowerHost.endsWith('.eu') ||
    lowerPath.startsWith('/de/') ||
    lowerPath.startsWith('/de_de/')
  ) {
    return 'EUR';
  }
  if (['mediamarkt', 'saturn', 'otto', 'zalando', 'thomann', 'galaxus', 'cyberport'].some((k) => lowerHost.includes(k))) {
    return 'EUR';
  }
  return 'USD';
}

/**
 * Extracts SKU/ASIN/article identifier and human-readable product title from URL path segments.
 * @param {string} pathname
 * @param {string} retailerId
 * @param {string} retailerName
 */
function parseProductFromPath(pathname, retailerId, retailerName) {
  let sku = null;

  // Amazon ASIN pattern (/dp/B09... or /gp/product/B09...)
  const asinMatch = pathname.match(/\/(?:dp|gp\/product)\/([A-Z0-9]{10})(?:[/?]|$)/i);
  if (asinMatch) {
    sku = asinMatch[1].toUpperCase();
  }

  // IKEA 8-digit article ID
  if (!sku && retailerId === 'ikea') {
    const ikeaMatch = pathname.match(/(\d{8})(?:\/|$)/);
    if (ikeaMatch) sku = ikeaMatch[1];
  }

  // H&M productpage.<id>.html
  if (!sku && retailerId === 'hm') {
    const hmMatch = pathname.match(/productpage\.(\d+)\.html/i);
    if (hmMatch) sku = hmMatch[1];
  }

  // Generic numeric/alphanumeric product ID near end of slug
  if (!sku) {
    const numIdMatch = pathname.match(/[-_](\d{6,12})(?:\.html|\/|$)/);
    if (numIdMatch) {
      sku = numIdMatch[1];
    } else {
      const codeMatch = pathname.match(/([a-z0-9]{2,6}-[a-z0-9]{2,6})(?:\.html|\/|$)/i);
      if (codeMatch) sku = codeMatch[1].toUpperCase();
    }
  }

  const segments = pathname
    .split('/')
    .map((s) => {
      try {
        return decodeURIComponent(s);
      } catch {
        return s;
      }
    })
    .filter((seg) => {
      if (!seg) return false;
      const clean = seg.toLowerCase();
      if (['-', 'dp', 'gp', 'product', 'p', 'de', 'en', 'us', 'uk', 'fr', 'es', 'it', 'nl', 'at', 'ch', 'de_de', 'en_us', 'en_gb', 'item', 'shop'].includes(clean)) {
        return false;
      }
      if (/^ref=/.test(clean)) return false;
      if (/^[a-z0-9]{10}$/i.test(clean) && retailerId === 'amazon') return false;
      if (/^productpage\.\d+\.html$/i.test(clean)) return false;
      return true;
    });

  // Choose the most descriptive slug segment
  let bestSlug = '';
  for (const seg of segments) {
    const stripped = seg.replace(/\.(html|htm|php|aspx)$/i, '');
    if (stripped.length > bestSlug.length) {
      bestSlug = stripped;
    }
  }

  let title = '';
  if (bestSlug) {
    title = bestSlug
      .replace(/^_/, '')
      // Preserve hyphens inside alphanumeric model codes such as WF-1000XM6, WH-1000XM5, RTX-4080
      .replace(/\b([A-Za-z]{1,5})-(\d[A-Za-z0-9]{1,10})\b/g, '$1\u0001$2')
      .replace(/[-_]+/g, ' ')
      .replace(/\u0001/g, '-')
      .replace(/\b\d{7,12}\b/g, '')
      .replace(/\s+/g, ' ')
      .trim();

    // Title-case cleanly while preserving short uppercase model acronyms and hyphenated codes
    title = title
      .split(' ')
      .filter(Boolean)
      .map((word) => {
        if (word.includes('-')) return word.toUpperCase();
        if (/^[A-Z0-9]{2,6}$/.test(word)) return word;
        if (/^\d/.test(word)) return word.toUpperCase();
        return word.charAt(0).toUpperCase() + word.slice(1);
      })
      .join(' ');
  }

  if (!title || title.length < 4) {
    title = `${retailerName} Catalog Product${sku ? ` #${sku}` : ''}`;
  }

  const words = title.split(' ');
  const probableBrand =
    words[0] && words[0].length >= 2 && !/^\d+$/.test(words[0]) ? words[0] : retailerName;

  return {
    title: sanitizeText(title, 140),
    brand: sanitizeText(probableBrand, 48),
    sku: sku ? sanitizeText(sku, 32) : 'UNSPECIFIED'
  };
}

/**
 * Infers product category from URL slug / title and retailer defaults.
 */
function inferCategory(title, pathname, retailer) {
  const haystack = `${title} ${pathname}`.toLowerCase();
  if (/(headphone|earphone|earbud|in-ear|over-ear|airpods|wf-\d|wh-\d|speaker|soundbar|kopfhörer|audio|bose|sennheiser)/.test(haystack)) {
    return 'Consumer Electronics & Audio';
  }
  if (/(boxer|trunk|unterwäsche|underwear|calvin klein|socks|shoe|sneaker|coat|jacket|shirt|dress|jeans|hoodie|laufschuh|jacke|kleid|pullover|apparel|fashion)/.test(haystack)) {
    return 'Apparel & Footwear';
  }
  if (/(sofa|chair|desk|table|bed|wardrobe|drehstuhl|tisch|regal|schrank|lamp|mattress|furniture)/.test(haystack)) {
    return 'Home & Furniture';
  }
  if (/(rasierer|shaver|braun|epilierer|toothbrush|zahnbürste|airwrap|haarstyler|hairstyler|vacuum|espresso|coffee|washer|dryer|fridge|kaffee|sauger|kitchen|dyson|bosch|pfanne|bratpfanne|topf|tefal|cookware|frying pan|airfryer|heißluftfritteuse)/.test(haystack)) {
    return 'Home & Kitchen Appliances';
  }
  if (/\b(oled|tv|monitor|laptop|notebook|macbook|gpu|rtx|ssd|cpu|keyboard|mouse|maus|phone|smartphone|iphone|galaxy|tablet|ipad)\b/.test(haystack)) {
    return 'Computing & Electronics';
  }
  return retailer.defaultCategory;
}

/**
 * Attempts to match the submitted normalized URL against curated flagship presets.
 */
function findMatchingPreset(normalizedUrl) {
  const cleanTarget = normalizedUrl.toLowerCase();
  for (const preset of PRESET_BENCHMARKS) {
    if (cleanTarget === preset.url.toLowerCase()) {
      return preset;
    }
    if (preset.sku && cleanTarget.includes(preset.sku.toLowerCase())) {
      return preset;
    }
  }
  return null;
}

module.exports = {
  PRESET_BENCHMARKS,
  RETAILER_PROFILES,
  findMatchingPreset,
  identifyRetailer,
  inferCategory,
  inferCurrency,
  parseProductFromPath
};

