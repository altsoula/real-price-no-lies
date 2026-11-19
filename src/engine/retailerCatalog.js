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
  },
  {
    id: 'digitec',
    name: 'Digitec',
    hosts: ['digitec.ch'],
    defaultCategory: 'Computing & Consumer Electronics',
    tactics: ['Transparent Swiss market pricing', 'Daily dynamic competitor repricing']
  },
  {
    id: 'alternate',
    name: 'Alternate',
    hosts: ['alternate.de', 'alternate.nl', 'alternate.at', 'alternate.be'],
    defaultCategory: 'Computing & Gaming',
    tactics: ['Daily ZackZack flash promotions', 'Component bundle pricing']
  },
  {
    id: 'mindfactory',
    name: 'Mindfactory',
    hosts: ['mindfactory.de'],
    defaultCategory: 'Computing & Gaming',
    tactics: ['Midnight-shopping shipping waivers', 'Mindstar limited hardware drops']
  },
  {
    id: 'expert',
    name: 'Expert',
    hosts: ['expert.de', 'expert.at'],
    defaultCategory: 'Consumer Electronics & Appliances',
    tactics: ['Regional franchise price variation', 'Weekly flyer promos vs. online market street price']
  },
  {
    id: 'euronics',
    name: 'Euronics',
    hosts: ['euronics.de', 'euronics.at'],
    defaultCategory: 'Consumer Electronics & Appliances',
    tactics: ['Independent regional dealer pricing', 'Seasonal promotional rebates']
  },
  {
    id: 'conrad',
    name: 'Conrad',
    hosts: ['conrad.de', 'conrad.at', 'conrad.com'],
    defaultCategory: 'Consumer Electronics & Tech',
    tactics: ['List MSRP baseline with voucher campaigns', 'Higher margin on accessories vs. main hardware']
  },
  {
    id: 'kaufland',
    name: 'Kaufland',
    hosts: ['kaufland.de'],
    defaultCategory: 'General E-Commerce Marketplace',
    tactics: ['Aggressive third-party marketplace price undercutting', 'Frequent coupon promos']
  },
  {
    id: 'lidl',
    name: 'Lidl',
    hosts: ['lidl.de', 'lidl.co.uk'],
    defaultCategory: 'Home, Kitchen & General Retail',
    tactics: ['Lidl Plus app rebates', 'High-velocity weekly online clearance drops']
  },
  {
    id: 'tchibo',
    name: 'Tchibo',
    hosts: ['tchibo.de', 'tchibo.at'],
    defaultCategory: 'Coffee, Home & Apparel',
    tactics: ['Rotating weekly thematic collections', 'Member card sale windows']
  },
  {
    id: 'bauhaus',
    name: 'Bauhaus',
    hosts: ['bauhaus.info', 'bauhaus.at'],
    defaultCategory: 'Home Improvement & Garden',
    tactics: ['Best-price guarantee matching local competitors', 'High seasonal price stability']
  },
  {
    id: 'obi',
    name: 'OBI',
    hosts: ['obi.de', 'obi.at'],
    defaultCategory: 'Home Improvement & Garden',
    tactics: ['HEY OBI app percentage coupons', 'Occasional UVP anchoring on power tools']
  },
  {
    id: 'home24',
    name: 'Home24',
    hosts: ['home24.de', 'home24.at', 'home24.ch'],
    defaultCategory: 'Home & Furniture',
    tactics: ['Recurring sitewide voucher codes', 'Inflated RRP reference badges']
  },
  {
    id: 'wayfair',
    name: 'Wayfair',
    hosts: ['wayfair.de', 'wayfair.co.uk', 'wayfair.com'],
    defaultCategory: 'Home & Furniture',
    tactics: ['White-label rebranding of identical furniture SKUs', 'Constant flash-sale countdown timers']
  },
  {
    id: 'breuninger',
    name: 'Breuninger',
    hosts: ['breuninger.com'],
    defaultCategory: 'Apparel & Premium Fashion',
    tactics: ['End-of-season designer markdowns', 'Strict RRP outside sale windows']
  },
  {
    id: 'snipes',
    name: 'Snipes',
    hosts: ['snipes.com'],
    defaultCategory: 'Apparel & Footwear',
    tactics: ['Limited sneaker restocks', 'App-exclusive flash sales']
  },
  {
    id: 'decathlon',
    name: 'Decathlon',
    hosts: ['decathlon.de', 'decathlon.co.uk', 'decathlon.com', 'decathlon.fr'],
    defaultCategory: 'Sports & Outdoor',
    tactics: ['Uniform low-margin house-brand pricing', 'Third-party marketplace price variance']
  },
  {
    id: 'douglas',
    name: 'Douglas',
    hosts: ['douglas.de', 'douglas.at'],
    defaultCategory: 'Beauty & Personal Care',
    tactics: ['Online app 20% off vouchers vs. higher storefront shelf prices', 'Gift-with-purchase promotions']
  },
  {
    id: 'dm',
    name: 'dm',
    hosts: ['dm.de', 'dm.at'],
    defaultCategory: 'Drugstore & Personal Care',
    tactics: ['Always-low uniform everyday pricing', 'Payback point multipliers']
  },
  {
    id: 'rossmann',
    name: 'Rossmann',
    hosts: ['rossmann.de'],
    defaultCategory: 'Drugstore & Personal Care',
    tactics: ['10% app coupon windows', 'Frequent weekly drugstore flyers']
  },
  {
    id: 'thalia',
    name: 'Thalia',
    hosts: ['thalia.de', 'thalia.at'],
    defaultCategory: 'Books, Toys & Electronics',
    tactics: ['Fixed book pricing alongside competitive toy/e-reader rebates', '15% subscriber coupon drops']
  },
  {
    id: 'samsung',
    name: 'Samsung',
    hosts: ['samsung.com'],
    defaultCategory: 'Computing & Consumer Electronics',
    tactics: ['Trade-in credits masking higher cash price', 'Members-only educational/corporate store pricing']
  },
  {
    id: 'sony',
    name: 'Sony',
    hosts: ['sony.de', 'sony.eu', 'sony.com', 'sony.co.uk'],
    defaultCategory: 'Consumer Electronics & Audio',
    tactics: ['Official MSRP baseline', 'Occasional manufacturer cashback rebates']
  },
  {
    id: 'dyson',
    name: 'Dyson',
    hosts: ['dyson.de', 'dyson.co.uk', 'dyson.com'],
    defaultCategory: 'Home Appliances',
    tactics: ['Direct-to-consumer bundle accessories at MSRP', 'Rare seasonal cash markdowns']
  },
  {
    id: 'bosch',
    name: 'Bosch',
    hosts: ['bosch-home.com', 'bosch-diy.com'],
    defaultCategory: 'Home & Kitchen Appliances',
    tactics: ['Manufacturer RRP showcase vs. significantly cheaper retail partners']
  },
  {
    id: 'tefal',
    name: 'Tefal',
    hosts: ['tefal.de', 'tefal.com', 'tefal.co.uk'],
    defaultCategory: 'Cookware & Kitchen Appliances',
    tactics: ['High UVP anchoring paired with steep authorized retailer discounts']
  },
  {
    id: 'braun',
    name: 'Braun',
    hosts: ['braun.de', 'braun.com'],
    defaultCategory: 'Personal Care Appliances',
    tactics: ['High UVP list pricing vs. 35-50% street discounts at Amazon/MediaMarkt']
  },
  {
    id: 'philips',
    name: 'Philips',
    hosts: ['philips.de', 'philips.com', 'philips.co.uk'],
    defaultCategory: 'Consumer Electronics & Personal Care',
    tactics: ['Manufacturer cashback promos', 'Seasonal holiday bundles']
  },
  {
    id: 'nike',
    name: 'Nike Official',
    hosts: ['nike.com'],
    defaultCategory: 'Apparel & Footwear',
    tactics: ['Member-only promo codes', 'Full MSRP for 90 days post-launch']
  },
  {
    id: 'adidas',
    name: 'Adidas',
    hosts: ['adidas.de', 'adidas.com', 'adidas.co.uk'],
    defaultCategory: 'Apparel & Footwear',
    tactics: ['adiClub member markdown windows', 'Factory outlet price tiers']
  },
  {
    id: 'bestbuy',
    name: 'Best Buy',
    hosts: ['bestbuy.com'],
    defaultCategory: 'Consumer Electronics & Appliances',
    tactics: ['Weekly Member Deals & My Best Buy price matching']
  },
  {
    id: 'walmart',
    name: 'Walmart',
    hosts: ['walmart.com'],
    defaultCategory: 'General E-Commerce Retail',
    tactics: ['Rollback promo tags vs. third-party Marketplace variance']
  },
  {
    id: 'target',
    name: 'Target',
    hosts: ['target.com'],
    defaultCategory: 'General E-Commerce Retail',
    tactics: ['Target Circle percentage offers', 'Consistent MSRP matching']
  },
  {
    id: 'currys',
    name: 'Currys',
    hosts: ['currys.co.uk'],
    defaultCategory: 'Consumer Electronics & Appliances',
    tactics: ['UK Price Promise matching', 'Bank Holiday promo sales']
  },
  {
    id: 'argos',
    name: 'Argos',
    hosts: ['argos.co.uk'],
    defaultCategory: 'General E-Commerce Retail',
    tactics: ['Multi-buy promo codes', 'Weekend Red Tag clearance']
  },
  {
    id: 'johnlewis',
    name: 'John Lewis',
    hosts: ['johnlewis.com'],
    defaultCategory: 'Department & Electronics Retail',
    tactics: ['Extended hardware guarantees included at MSRP', 'Seasonal clearance markdowns']
  },
  {
    id: 'fnac',
    name: 'Fnac',
    hosts: ['fnac.com'],
    defaultCategory: 'Consumer Electronics & Books',
    tactics: ['Fnac+ member voucher rebates', 'Marketplace third-party pricing']
  },
  {
    id: 'darty',
    name: 'Darty',
    hosts: ['darty.com'],
    defaultCategory: 'Consumer Electronics & Appliances',
    tactics: ['Flash promo vouchers', 'Store pickup parity with Fnac']
  },
  {
    id: 'bol',
    name: 'Bol.com',
    hosts: ['bol.com'],
    defaultCategory: 'General E-Commerce Marketplace',
    tactics: ['Select member deals', 'Third-party partner seller price spread']
  },
  {
    id: 'proshop',
    name: 'Proshop',
    hosts: ['proshop.de', 'proshop.dk', 'proshop.nl', 'proshop.at'],
    defaultCategory: 'Computing & Consumer Electronics',
    tactics: ['Competitive Nordic-EU hardware pricing', 'Flash weekend electronics offers']
  },
  {
    id: 'alza',
    name: 'Alza',
    hosts: ['alza.de', 'alza.at', 'alza.cz'],
    defaultCategory: 'Computing & Consumer Electronics',
    tactics: ['Transparent multi-tier member & promo coupon pricing']
  }
];

/**
 * Aggregators, review blogs, forums, social platforms, and ultra-low-trust marketplaces
 * that MUST NEVER be surfaced as direct competing retail sellers.
 */
const AGGREGATOR_AND_NON_RETAIL_HOSTS = [
  'idealo.de',
  'idealo.at',
  'idealo.co.uk',
  'idealo.fr',
  'idealo.es',
  'idealo.it',
  'geizhals.de',
  'geizhals.at',
  'geizhals.eu',
  'billiger.de',
  'guenstiger.de',
  'check24.de',
  'keepa.com',
  'camelcamelcamel.com',
  'heise.de',
  'pricerunner.com',
  'pricerunner.co.uk',
  'pricerunner.se',
  'pricerunner.dk',
  'kelkoo.de',
  'kelkoo.com',
  'kelkoo.co.uk',
  'preissuchmaschine.de',
  'ladenzeile.de',
  'preis.de',
  'google.com',
  'google.de',
  'google.co.uk',
  'bing.com',
  'duckduckgo.com',
  'mydealz.de',
  'dealabs.com',
  'hotukdeals.com',
  'slickdeals.net',
  'reddit.com',
  'youtube.com',
  'youtu.be',
  'chip.de',
  'computerbild.de',
  'test.de',
  'hifi.de',
  'notebookcheck.com',
  'notebookcheck.net',
  'rtings.com',
  'techradar.com',
  'tomsguide.com',
  'trustpilot.com',
  'wikipedia.org',
  'kleinanzeigen.de',
  'temu.com',
  'aliexpress.com',
  'wish.com',
  'dhgate.com',
  'ebay-kleinanzeigen.de',
  'preisvergleich.de'
];

function hostMatchesDomainList(hostname, domainList) {
  const lower = String(hostname || '').toLowerCase().trim();
  if (!lower) return false;
  return domainList.some((dom) => lower === dom || lower.endsWith(`.${dom}`));
}

function isAggregatorOrNonRetailHost(hostname) {
  return hostMatchesDomainList(hostname, AGGREGATOR_AND_NON_RETAIL_HOSTS);
}

function isReputableRetailerHost(hostname) {
  const lower = String(hostname || '').toLowerCase().trim();
  if (!lower || isAggregatorOrNonRetailHost(lower)) return false;
  return RETAILER_PROFILES.some((profile) => hostMatchesDomainList(lower, profile.hosts));
}

function resolveReputableRetailerName(rawName) {
  const cleaned = String(rawName || '').toLowerCase().trim();
  if (!cleaned) return null;
  if (isAggregatorOrNonRetailHost(cleaned)) return null;
  const compact = cleaned.replace(/[^a-z0-9]/g, '');
  for (const profile of RETAILER_PROFILES) {
    const profNameCompact = profile.name.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (
      cleaned === profile.id ||
      compact === profNameCompact ||
      profile.hosts.some((h) => cleaned === h || cleaned.startsWith(`${profile.id}.`))
    ) {
      return profile.name;
    }
  }
  return null;
}

function isReputableRetailerName(rawName) {
  return resolveReputableRetailerName(rawName) !== null;
}

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

  // Zalando article SKU (e.g. ad115o03m-a11.html)
  if (!sku && retailerId === 'zalando') {
    const zalandoMatch = pathname.match(/-([a-z0-9]{7,12}-[a-z0-9]{2,4})\.html(?:$|\/)/i);
    if (zalandoMatch) sku = zalandoMatch[1].toUpperCase();
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
  AGGREGATOR_AND_NON_RETAIL_HOSTS,
  PRESET_BENCHMARKS,
  RETAILER_PROFILES,
  findMatchingPreset,
  identifyRetailer,
  inferCategory,
  inferCurrency,
  isAggregatorOrNonRetailHost,
  isReputableRetailerHost,
  isReputableRetailerName,
  parseProductFromPath,
  resolveReputableRetailerName
};

