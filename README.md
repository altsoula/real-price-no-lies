# RealPriceNoLies (`realpricenolies`)

Zero-signup, monotone-forensic AI price intelligence and deal-truth analyzer. Paste any product URL from Amazon, MediaMarkt, Saturn, IKEA, Otto, Zalando, H&M, or virtually any online retailer to get an instant **0–100 Deal Truth Score**, 180-day price trajectory chart, cross-retailer comparison, transparent intelligence provenance, and explicit AI accuracy disclaimers.

## Security-First Architecture

Built strictly on **zero third-party runtime dependencies** using Node.js native standard library modules to eliminate supply-chain/trojan risk:
- **Anti-SSRF & DNS Rebinding Guard (`src/security/urlGuard.js`)**: Rejects `localhost`, loopback, link-local, cloud metadata (`169.254.169.254`), private IPv4/IPv6 ranges, embedded credentials, non-HTTP(S) schemes, and validates every resolved IP via DNS lookup. Strips tracking parameters (`utm_*`, `fbclid`, `gclid`, `ref`, `tag`).
- **Strict Injection & Prototype Pollution Defense (`src/security/sanitizer.js`)**: Enforces `application/json`, caps request bodies to 4 KB, rejects `__proto__` / `constructor` / `prototype` keys, strips control characters, and renders all UI output via `textContent` / `createElement` (never `innerHTML` with untrusted data).
- **Hardened HTTP Headers (`src/security/headers.js`)**: Strict `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `COOP`, `CORP`, and `HSTS`.
- **Sliding-Window Rate Limiter (`src/security/rateLimiter.js`)**: Bounded-memory IP rate limiter preventing abuse and resource exhaustion.
- **GDPR/ePrivacy Cookie Manager & Ad-Slot Ready (`public/cookie-Consent.js`)**: Gates analytics and ad scripts behind explicit consent, with CLS-safe ad placements ready for AdSense, EthicalAds, or direct sponsors.

## Quick Start

```bash
node src/server.js
```

Then open `http://127.0.0.1:3000`.

## Running Security & Engine Tests

```bash
node --test tests/security-and-engine.test.js
```

