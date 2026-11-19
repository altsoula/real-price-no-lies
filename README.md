<div align="center">

# RealPriceNoLies

**Paste any product URL. Expose fake discounts in seconds.**

[![Live Website](https://img.shields.io/badge/Live%20Site-realpricenolies.online-10b981?style=for-the-badge)](https://realpricenolies.online)
[![Zero Signup](https://img.shields.io/badge/Access-Zero%20Signup%20%2F%20No%20Email-0f172a?style=for-the-badge)](https://realpricenolies.online)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B%20(Zero%20Runtime%20Deps)-339933?style=for-the-badge)](package.json)
[![License](https://img.shields.io/badge/License-MIT-475569?style=for-the-badge)](package.json)

**[Launch Live App → https://realpricenolies.online](https://realpricenolies.online)**

</div>

---

## Why RealPriceNoLies?

Online stores routinely inflate "Was / UVP / MSRP" strike-through prices right before a sale so an ordinary price looks like `-40% OFF`.

**RealPriceNoLies** (`realpricenolies.online`) cuts through fake urgency. Paste any product link—no account, no login, no email required—and get an instant, evidence-backed verdict on whether the deal is a **steal** or a **pricing trap**.

---

## What It Does

### 1. Instant 0–100 Deal Truth Score
Every pasted product URL is scored on a **0–100 scale** across four transparent weights:

| Pillar | Weight | What It Audits |
|---|---|---|
| **vs. 90-Day Market Average** | `35 pts` | Checks whether today's price actually beats the rolling 90-day street price. |
| **180-Day Low/High Position** | `30 pts` | Measures how close today's listing sits to the verified 6-month market floor. |
| **Cross-Retailer Spread** | `20 pts` | Compares the listing against competing online stores selling the exact item right now. |
| **UVP & Promo Honesty Audit** | `15 pts` | Penalizes exaggerated strike-through anchors and pre-sale price spikes. |

**Verdict Scale:** `0–19 TRAP` · `20–39 INFLATED` · `40–64 STANDARD` · `65–84 SOLID` · `85–100 STEAL`

### 2. Interactive 30 / 90 / 180-Day Price History Chart
- Toggle between **30-day**, **90-day**, and **180-day** views.
- Hover or tap any data point on the SVG trajectory graph to inspect the exact date, target store price, 90-day rolling average, and lowest competing market floor.
- Side-by-side **30 / 90 / 180-day window cards** comparing the store against both its own history and competing sellers.

### 3. Live Multi-Store Extraction + Grounded AI Research
- **Works Across Retailers:** Built for **Amazon**, **MediaMarkt**, **Saturn**, **IKEA**, **Otto**, **Zalando**, **H&M**, plus virtually any public e-commerce product URL.
- **Hybrid Price Verification:** Extracts live product titles, SKUs, and shelf prices directly from the store page (including compressed HTML and JSON-LD product offers), cleans tracking parameters (`utm_*`, `fbclid`, `gclid`, `ref`, `tag`), and cross-checks competing stores using Google-Search-grounded Gemini AI and web price search.
- **Deterministic Repeat Consistency:** Locks verified shelf prices and normalizes canonical product keys so checking the same product URL gives consistent, cache-backed results instead of drifting numbers.

### 4. Sharp Monotone UX + Full Source Transparency
- Switch between **Paper Mode** (high-contrast editorial off-white) and **Carbon Mode** (dark slate) with one click.
- Displays a **Where We Got The Intel** provenance table breaking down the exact weight and status of every price signal used in the verdict.
- Shows typical pricing tactics used by that retailer so shoppers know what tricks to watch out for.

---

## How It Works

```text
  [1] Paste Product URL  ──▶  [2] Clean Tracking Tags & Extract Live Store Offer
                                        │
                                        ▼
  [4] Render Score, Chart  ◀──  [3] Audit 180-Day History + Competing Stores
      & Source Provenance           (Live Scrape + Grounded Search AI + Search Fallback)
```

---

## Quick Local Setup & Self-Hosting

RealPriceNoLies runs on native Node.js with **zero third-party runtime npm packages**.

### Prerequisites
- **Node.js `20+`** (tested on Node 24)
- Optional: A free or billed **`GEMINI_API_KEY`** from Google AI Studio for Google-Search-grounded AI research

### Run Locally
```bash
git clone https://github.com/altsoula/real-price-no-lies.git
cd real-price-no-lies
cp .env.example .env
# Add your optional GEMINI_API_KEY inside .env
node src/server.js
```

Open `http://127.0.0.1:3000`.

### Run Tests
```bash
npm test
```

### Deploy
Production-ready configurations are included out of the box:
- **Docker:** [Dockerfile](Dockerfile)
- **Railway:** [railway.json](railway.json)
- **Render:** [render.yaml](render.yaml)

---

## Privacy & Safety Summary

- **Zero Personal Data:** No user accounts, emails, or saved search profiles; affiliate/tracking query tags are stripped automatically from pasted URLs.
- **Hardened Networking & Browser Boundaries:** Blocks private/local network SSRF targets, enforces strict `Content-Security-Policy` (`script-src 'self'`), bounds concurrency/caches against traffic spikes, and rate-limits API abuse.
- **Consent-First Cookie Manager:** Ad slots remain hidden unless explicitly configured and consented to.

---

## AI Accuracy Disclaimer

RealPriceNoLies combines live retailer extraction, web price lookup, and AI-grounded market analysis. **AI systems can occasionally make mistakes**, misread regional shipping/VAT variants, or encounter stores with automated bot protection. Always verify the final checkout price, seller rating, and shipping cost directly on the retailer's page before purchasing.
