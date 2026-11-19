(function () {
  'use strict';

  const THEME_STORAGE_KEY = 'rpnl_theme_v1';
  const SVG_NS = 'http://www.w3.org/2000/svg';

  let lastReport = null;
  let currentChartRange = 180;
  let turnstileWidgetId = null;
  let turnstileSiteKey = '';
  let turnstileToken = '';

  function formatMoney(amount, currency) {
    const num = Number(amount);
    if (!Number.isFinite(num)) return '-';
    const symbol =
      currency === 'USD' ? '$' : currency === 'GBP' ? '£' : currency === 'CHF' ? 'CHF ' : '€';
    return `${symbol}${num.toFixed(2)}`;
  }

  function createSvgEl(tag, attrs = {}) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) {
      el.setAttribute(k, String(v));
    }
    return el;
  }

  function initTheme() {
    const toggleBtn = document.getElementById('theme-toggle-btn');
    let saved = 'paper';
    try {
      const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
      if (stored === 'carbon' || stored === 'paper') saved = stored;
    } catch {
      saved = 'paper';
    }

    function applyTheme(theme) {
      document.documentElement.setAttribute('data-theme', theme);
      if (toggleBtn) {
        toggleBtn.textContent = theme === 'carbon' ? '☼ PAPER MODE' : '◐ CARBON MODE';
      }
      try {
        window.localStorage.setItem(THEME_STORAGE_KEY, theme);
      } catch {
        // Ignore storage errors
      }
    }

    applyTheme(saved);
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'paper';
        applyTheme(current === 'carbon' ? 'paper' : 'carbon');
      });
    }
  }

  function initTermsModal() {
    const modal = document.getElementById('terms-modal');
    const openFooter = document.getElementById('footer-terms-btn');
    const closeBtn = document.getElementById('close-terms-modal-btn');
    const acceptBtn = document.getElementById('accept-terms-btn');

    const open = () => modal && modal.classList.remove('hidden');
    const close = () => modal && modal.classList.add('hidden');

    if (openFooter) openFooter.addEventListener('click', open);
    if (closeBtn) closeBtn.addEventListener('click', close);
    if (acceptBtn) acceptBtn.addEventListener('click', close);
    if (modal) {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) close();
      });
    }
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && modal && !modal.classList.contains('hidden')) {
        close();
      }
    });
  }

  function updateClock() {
    const el = document.getElementById('utc-clock');
    if (!el) return;
    const now = new Date();
    el.textContent = `UTC ${now.toISOString().slice(0, 16).replace('T', ' ')}`;
  }

  function showError(message) {
    const errEl = document.getElementById('form-error');
    if (!errEl) return;
    errEl.textContent = message;
    errEl.classList.remove('hidden');
  }

  function hideError() {
    const errEl = document.getElementById('form-error');
    if (!errEl) return;
    errEl.textContent = '';
    errEl.classList.add('hidden');
  }

  /**
   * Renders the interactive monotone SVG price trajectory chart using createElementNS only.
   */
  function renderPriceChart(report, daysWindow) {
    const container = document.getElementById('chart-container');
    const readout = document.getElementById('chart-hover-readout');
    if (!container || !report || !Array.isArray(report.priceHistory)) return;

    container.replaceChildren();
    const currency = report.pricing.currency;
    const fullSeries = report.priceHistory;
    const points =
      daysWindow === 30
        ? fullSeries.filter((p) => p.daysAgo <= 30)
        : daysWindow === 90
          ? fullSeries.filter((p) => p.daysAgo <= 90)
          : fullSeries;

    if (points.length < 2) return;

    const width = 880;
    const height = 290;
    const pad = { top: 24, right: 24, bottom: 38, left: 68 };
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;

    const allPrices = [];
    for (const pt of points) {
      allPrices.push(pt.retailerPrice, pt.marketBestPrice, pt.movingAvg90d);
    }
    const minVal = Math.min(...allPrices);
    const maxVal = Math.max(...allPrices);
    const padding = Math.max((maxVal - minVal) * 0.14, maxVal * 0.04, 1);
    const yMin = Math.max(0, minVal - padding);
    const yMax = maxVal + padding;

    const xForIndex = (idx) =>
      pad.left + (idx / Math.max(1, points.length - 1)) * plotW;
    const yForPrice = (price) =>
      pad.top + ((yMax - price) / Math.max(0.01, yMax - yMin)) * plotH;

    const svg = createSvgEl('svg', {
      viewBox: `0 0 ${width} ${height}`,
      class: 'chart-svg',
      role: 'img',
      'aria-label': `Price history chart over ${daysWindow} days`
    });

    // Horizontal grid lines & Y-axis labels
    const yTicks = 5;
    for (let i = 0; i <= yTicks; i += 1) {
      const ratio = i / yTicks;
      const val = yMin + (yMax - yMin) * (1 - ratio);
      const y = pad.top + ratio * plotH;

      svg.appendChild(
        createSvgEl('line', {
          x1: pad.left,
          y1: y,
          x2: width - pad.right,
          y2: y,
          stroke: 'var(--grid-line)',
          'stroke-width': 1
        })
      );

      const label = createSvgEl('text', {
        x: pad.left - 8,
        y: y + 4,
        'text-anchor': 'end',
        fill: 'var(--ink-muted)',
        'font-size': 11,
        'font-family': 'ui-monospace, monospace'
      });
      label.textContent = formatMoney(val, currency);
      svg.appendChild(label);
    }

    // X-axis date ticks
    const stepIndices = [0, Math.floor((points.length - 1) / 3), Math.floor(((points.length - 1) * 2) / 3), points.length - 1];
    for (const idx of stepIndices) {
      const pt = points[idx];
      if (!pt) continue;
      const x = xForIndex(idx);
      const xLabel = createSvgEl('text', {
        x,
        y: height - 10,
        'text-anchor': idx === 0 ? 'start' : idx === points.length - 1 ? 'end' : 'middle',
        fill: 'var(--ink-muted)',
        'font-size': 11,
        'font-family': 'ui-monospace, monospace'
      });
      xLabel.textContent = pt.date;
      svg.appendChild(xLabel);
    }

    // Area shading under target price line
    const areaPoints = [
      `${xForIndex(0)},${pad.top + plotH}`,
      ...points.map((pt, idx) => `${xForIndex(idx)},${yForPrice(pt.retailerPrice)}`),
      `${xForIndex(points.length - 1)},${pad.top + plotH}`
    ].join(' ');
    svg.appendChild(
      createSvgEl('polygon', {
        points: areaPoints,
        fill: 'var(--brand-cobalt)',
        'fill-opacity': '0.1'
      })
    );

    // 90-day moving average line (dashed)
    const avgPath = points
      .map((pt, idx) => `${idx === 0 ? 'M' : 'L'} ${xForIndex(idx)} ${yForPrice(pt.movingAvg90d)}`)
      .join(' ');
    svg.appendChild(
      createSvgEl('path', {
        d: avgPath,
        fill: 'none',
        stroke: 'var(--score-mid)',
        'stroke-width': 2,
        'stroke-dasharray': '6 5'
      })
    );

    // Lowest market floor line (dotted)
    const floorPath = points
      .map((pt, idx) => `${idx === 0 ? 'M' : 'L'} ${xForIndex(idx)} ${yForPrice(pt.marketBestPrice)}`)
      .join(' ');
    svg.appendChild(
      createSvgEl('path', {
        d: floorPath,
        fill: 'none',
        stroke: 'var(--score-high)',
        'stroke-width': 1.8,
        'stroke-dasharray': '2 4'
      })
    );

    // Target store price trajectory (solid bold line)
    const mainPath = points
      .map((pt, idx) => `${idx === 0 ? 'M' : 'L'} ${xForIndex(idx)} ${yForPrice(pt.retailerPrice)}`)
      .join(' ');
    svg.appendChild(
      createSvgEl('path', {
        d: mainPath,
        fill: 'none',
        stroke: 'var(--brand-cobalt)',
        'stroke-width': 2.8
      })
    );

    // Hover crosshair vertical line
    const crosshair = createSvgEl('line', {
      x1: pad.left,
      y1: pad.top,
      x2: pad.left,
      y2: pad.top + plotH,
      stroke: 'var(--ink)',
      'stroke-width': 1,
      'stroke-dasharray': '3 3',
      visibility: 'hidden'
    });
    svg.appendChild(crosshair);

    function selectPointIndex(idx) {
      if (idx < 0 || idx >= points.length) return;
      const pt = points[idx];
      const cx = xForIndex(idx);
      crosshair.setAttribute('x1', String(cx));
      crosshair.setAttribute('x2', String(cx));
      crosshair.setAttribute('visibility', 'visible');
      if (readout) {
        const eventStr = pt.event ? ` | EVENT: ${pt.event}` : '';
        readout.textContent = `${pt.date} — Store: ${formatMoney(pt.retailerPrice, currency)} | Market Floor: ${formatMoney(pt.marketBestPrice, currency)} | 90d Avg: ${formatMoney(pt.movingAvg90d, currency)}${eventStr}`;
      }
    }

    // Interactive point markers & invisible hit targets
    points.forEach((pt, idx) => {
      const cx = xForIndex(idx);
      const cy = yForPrice(pt.retailerPrice);
      const isSpecial = Boolean(pt.event);

      const dot = createSvgEl('circle', {
        cx,
        cy,
        r: isSpecial ? 5.5 : 3.2,
        fill: isSpecial ? 'var(--surface)' : 'var(--brand-cobalt)',
        stroke: 'var(--brand-cobalt)',
        'stroke-width': isSpecial ? 2.5 : 1
      });
      svg.appendChild(dot);

      const hit = createSvgEl('rect', {
        x: cx - plotW / (points.length * 2),
        y: pad.top,
        width: Math.max(12, plotW / points.length),
        height: plotH,
        fill: 'transparent',
        style: 'cursor: crosshair;'
      });

      hit.addEventListener('mouseenter', () => selectPointIndex(idx));
      hit.addEventListener('click', () => selectPointIndex(idx));
      svg.appendChild(hit);
    });

    // Touch & pointer scrub support for seamless mobile inspection
    const scrubPointFromEvent = (e) => {
      const rect = svg.getBoundingClientRect();
      const clientX = e.touches && e.touches[0] ? e.touches[0].clientX : e.clientX;
      if (typeof clientX !== 'number' || Number.isNaN(clientX) || rect.width <= 0) return;
      const relX = clientX - rect.left;
      const scaleX = width / rect.width;
      const svgX = relX * scaleX;
      const clampedX = Math.max(pad.left, Math.min(width - pad.right, svgX));
      const idx = Math.min(
        points.length - 1,
        Math.max(0, Math.round(((clampedX - pad.left) / plotW) * (points.length - 1)))
      );
      selectPointIndex(idx);
    };

    svg.addEventListener('touchstart', scrubPointFromEvent, { passive: true });
    svg.addEventListener('touchmove', scrubPointFromEvent, { passive: true });
    svg.addEventListener('pointermove', (e) => {
      if (e.buttons > 0 || e.pointerType === 'mouse') {
        scrubPointFromEvent(e);
      }
    });

    // Select the latest point (today) by default so mobile users see immediate values
    selectPointIndex(points.length - 1);

    container.appendChild(svg);
  }

  /**
   * 21st.dev Style Smooth Ease-out Count-up Odometer for Deal Truth Score.
   */
  function animateScoreCountUp(targetScore) {
    const el = document.getElementById('res-score');
    if (!el) return;
    const target = Math.round(Number(targetScore) || 0);
    const duration = 1000;
    const startTime = performance.now();

    function frame(now) {
      const progress = Math.min(1, (now - startTime) / duration);
      // easeOutExpo for tactile spring deceleration
      const ease = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
      const val = Math.round(target * ease);
      el.textContent = String(val);
      if (progress < 1) {
        requestAnimationFrame(frame);
      } else {
        el.textContent = String(target);
      }
    }
    requestAnimationFrame(frame);
  }

  /**
   * Renders the full forensic analysis report safely using textContent / createElement.
   */
  function renderReport(data) {
    lastReport = data;
    const resultsSection = document.getElementById('results-section');
    if (!resultsSection) return;

    const { product, pricing, scoring, competitors, aiAnalysis, intelSources, aiDisclaimer } = data;
    const c = pricing.currency;

    // Disclaimer
    document.getElementById('ai-disclaimer-text').textContent = aiDisclaimer;

    // Product Identity
    document.getElementById('res-retailer').textContent = product.retailerName;
    document.getElementById('res-category').textContent = product.category;
    document.getElementById('res-sku').textContent = `SKU: ${product.sku}`;
    document.getElementById('res-trackers-stripped').textContent =
      product.strippedTrackers > 0
        ? `STRIPPED ${product.strippedTrackers} TRACKER(S)`
        : 'CLEAN URL';
    document.getElementById('res-title').textContent = product.title;
    document.getElementById('res-url-display').textContent = product.normalizedUrl;

    // 0-100 Score Hero with 21st.dev Dynamic Tone, Glow & Rolling Odometer
    const scoreEl = document.getElementById('res-score');
    const scoreFillEl = document.getElementById('res-score-fill');
    const verdictBadge = document.getElementById('res-verdict-badge');
    const toneClass =
      scoring.dealScore >= 85
        ? 'tone-high'
        : scoring.dealScore >= 65
          ? 'tone-solid'
          : scoring.dealScore >= 40
            ? 'tone-mid'
            : 'tone-low';

    const scoreHeroCard = document.querySelector('.score-hero-card');
    if (scoreHeroCard) {
      scoreHeroCard.classList.remove('score-steal-glow', 'score-trap-glow');
      if (scoring.dealScore >= 85) {
        scoreHeroCard.classList.add('score-steal-glow');
      } else if (scoring.dealScore < 40) {
        scoreHeroCard.classList.add('score-trap-glow');
      }
    }

    animateScoreCountUp(scoring.dealScore);
    scoreEl.className = `score-big mono ${toneClass}`;
    verdictBadge.textContent = scoring.verdictLabel;
    verdictBadge.className = `verdict-badge ${toneClass}`;
    document.getElementById('res-verdict-action').textContent = scoring.verdictAction;

    scoreFillEl.className = `score-meter-fill ${toneClass}`;
    requestAnimationFrame(() => {
      scoreFillEl.style.width = `${scoring.dealScore}%`;
      const marker = document.getElementById('res-score-marker');
      if (marker) marker.style.left = `calc(${scoring.dealScore}% - 2px)`;
    });

    // Breakdown Bars
    const breakdownList = document.getElementById('res-breakdown-list');
    breakdownList.replaceChildren();
    scoring.breakdown.forEach((item) => {
      const row = document.createElement('div');
      row.className = 'breakdown-item';

      const head = document.createElement('div');
      head.className = 'breakdown-item-head';
      const lbl = document.createElement('span');
      lbl.textContent = item.label;
      const pts = document.createElement('span');
      pts.className = 'mono';
      pts.textContent = `${item.score} / ${item.maxScore}`;
      head.append(lbl, pts);

      const track = document.createElement('div');
      track.className = 'breakdown-bar-track';
      const fill = document.createElement('div');
      fill.className = 'breakdown-bar-fill';
      fill.style.width = `${Math.round((item.score / Math.max(1, item.maxScore)) * 100)}%`;
      track.appendChild(fill);

      const detail = document.createElement('div');
      detail.className = 'breakdown-detail';
      detail.textContent = item.detail;

      row.append(head, track, detail);
      breakdownList.appendChild(row);
    });

    // Key Price Ledger
    document.getElementById('res-current-price').textContent = formatMoney(pricing.currentPrice, c);
    document.getElementById('res-claimed-uvp').textContent =
      pricing.claimedReferencePrice > pricing.currentPrice
        ? `Claimed UVP: ${formatMoney(pricing.claimedReferencePrice, c)} (-${scoring.claimedDiscountPct}%)`
        : 'No strike-through UVP claimed';

    document.getElementById('res-avg-90d').textContent = formatMoney(pricing.average90d, c);
    const avgDeltaText =
      pricing.realDeltaVsAvg >= 0
        ? `${formatMoney(pricing.realDeltaVsAvg, c)} (${scoring.realSavingsPct}%) below avg`
        : `${formatMoney(Math.abs(pricing.realDeltaVsAvg), c)} above 90d avg`;
    document.getElementById('res-avg-delta').textContent = avgDeltaText;

    document.getElementById('res-low-180d').textContent = formatMoney(pricing.lowest180d, c);
    document.getElementById('res-low-meta').textContent =
      `${pricing.lowest180dDate} (${pricing.lowest180dRetailer})`;

    document.getElementById('res-fair-price').textContent = formatMoney(pricing.fairPriceEstimate, c);
    document.getElementById('res-honesty-flag').textContent =
      pricing.prePromoHikeDetected
        ? 'WARNING: Pre-promo anchor spike flagged'
        : `Fake-discount gap: ${scoring.fakeDiscountGapPct.toFixed(1)}%`;

    // Price Trajectory Chart & 30/90/180-Day Window Comparison Cards
    currentChartRange = 180;
    document.getElementById('range-180-btn').classList.add('active');
    document.getElementById('range-90-btn').classList.remove('active');
    document.getElementById('range-30-btn').classList.remove('active');
    renderPriceChart(data, 180);

    const winContainer = document.getElementById('res-window-comparison');
    if (winContainer && pricing.windowComparisons) {
      winContainer.replaceChildren();
      const windows = [
        pricing.windowComparisons.days30,
        pricing.windowComparisons.days90,
        pricing.windowComparisons.days180
      ].filter(Boolean);

      windows.forEach((w) => {
        const card = document.createElement('div');
        card.className = 'window-card';

        const head = document.createElement('div');
        head.className = 'window-card-head';
        const titleEl = document.createElement('strong');
        titleEl.textContent = w.label;
        const badgeEl = document.createElement('span');
        badgeEl.className = 'window-badge mono';
        badgeEl.textContent =
          w.deltaVsOwnAvgPct >= 0
            ? `-${w.deltaVsOwnAvgPct}% vs own avg`
            : `+${Math.abs(w.deltaVsOwnAvgPct)}% vs own avg`;
        head.append(titleEl, badgeEl);

        const ownLine = document.createElement('div');
        ownLine.className = 'window-metric mono';
        ownLine.textContent = `${product.retailerName}: Avg ${formatMoney(w.ownSellerAvg, c)} (Low ${formatMoney(w.ownSellerLow, c)} / High ${formatMoney(w.ownSellerHigh, c)})`;

        const compLine = document.createElement('div');
        compLine.className = 'window-metric window-metric-comp mono';
        if (w.hasExternalCompetitors === false) {
          compLine.textContent = 'Competitors: No verified external offers for this exact SKU';
        } else {
          const diffComp =
            w.deltaVsCompetitorLow < -0.01
              ? `Cheaper by ${formatMoney(Math.abs(w.deltaVsCompetitorLow), c)}`
              : w.deltaVsCompetitorLow <= 0.01
                ? 'Cheapest or tied'
                : `+${formatMoney(w.deltaVsCompetitorLow, c)} above best`;
          compLine.textContent = `Competitors: Low ${formatMoney(w.competitorLow, c)} · Avg ${formatMoney(w.competitorAvg, c)} (${diffComp})`;
        }

        card.append(head, ownLine, compLine);
        winContainer.appendChild(card);
      });
    }

    // Cross-Retailer Comparison Table
    const compBody = document.getElementById('res-competitors-body');
    compBody.replaceChildren();
    competitors.forEach((comp) => {
      const tr = document.createElement('tr');
      if (comp.isTargetStore) tr.className = 'row-highlight';

      const tdStore = document.createElement('td');
      tdStore.setAttribute('data-label', 'Retailer');
      tdStore.textContent = comp.retailer;
      if (comp.isBestPrice) {
        const badge = document.createElement('span');
        badge.className = 'badge-mini badge-mini-solid';
        badge.textContent = 'CHEAPEST';
        tdStore.appendChild(badge);
      }
      if (comp.isTargetStore) {
        const badge = document.createElement('span');
        badge.className = 'badge-mini';
        badge.textContent = 'YOUR URL';
        tdStore.appendChild(badge);
      } else if (comp.verificationLabel) {
        const vBadge = document.createElement('span');
        vBadge.className = comp.verifiedLive ? 'badge-mini badge-mini-verified' : 'badge-mini';
        vBadge.textContent = comp.verificationLabel;
        tdStore.appendChild(vBadge);
      }

      const tdPrice = document.createElement('td');
      tdPrice.className = 'mono';
      tdPrice.setAttribute('data-label', 'Price');
      tdPrice.textContent = formatMoney(comp.price, c);

      const tdDelta = document.createElement('td');
      tdDelta.className = 'mono';
      tdDelta.setAttribute('data-label', 'vs. Target');
      if (Math.abs(comp.deltaVsTarget) < 0.01) {
        tdDelta.textContent = 'BASELINE';
      } else if (comp.deltaVsTarget < 0) {
        tdDelta.textContent = `-${formatMoney(Math.abs(comp.deltaVsTarget), c)}`;
      } else {
        tdDelta.textContent = `+${formatMoney(comp.deltaVsTarget, c)}`;
      }

      const tdShip = document.createElement('td');
      tdShip.setAttribute('data-label', 'Delivery & Stock');
      tdShip.textContent = `${comp.shipping} · ${comp.stock}`;

      const tdOffer = document.createElement('td');
      tdOffer.setAttribute('data-label', 'Offer');
      if (typeof comp.offerUrl === 'string' && comp.offerUrl.startsWith('https://')) {
        const offerLink = document.createElement('a');
        offerLink.href = comp.offerUrl;
        offerLink.target = '_blank';
        offerLink.rel = comp.isAffiliate ? 'sponsored noopener noreferrer' : 'noopener noreferrer';
        offerLink.className = 'offer-link-btn mono';
        offerLink.textContent = comp.isTargetStore ? 'View Store ↗' : comp.directProductUrl ? 'Direct Offer ↗' : 'Check Offer ↗';
        tdOffer.appendChild(offerLink);
      } else {
        tdOffer.textContent = '-';
      }

      tr.append(tdStore, tdPrice, tdDelta, tdShip, tdOffer);
      compBody.appendChild(tr);
    });
    if (competitors.length <= 1) {
      const infoTr = document.createElement('tr');
      const infoTd = document.createElement('td');
      infoTd.colSpan = 5;
      infoTd.className = 'mono';
      infoTd.textContent = 'No verified identical competing retailer offers matched this exact SKU right now (exclusive or unindexed item).';
      infoTr.appendChild(infoTd);
      compBody.appendChild(infoTr);
    }

    // AI Findings & Tactics
    document.getElementById('res-ai-headline').textContent = aiAnalysis.headline;
    const findingsEl = document.getElementById('res-ai-findings');
    findingsEl.replaceChildren();
    aiAnalysis.findings.forEach((bullet) => {
      const li = document.createElement('li');
      li.textContent = bullet;
      findingsEl.appendChild(li);
    });

    const tacticsEl = document.getElementById('res-retailer-tactics');
    tacticsEl.replaceChildren();
    (product.retailerTactics || []).forEach((tactic) => {
      const li = document.createElement('li');
      li.textContent = tactic;
      tacticsEl.appendChild(li);
    });

    // Intel Provenance Table
    const intelBody = document.getElementById('res-intel-body');
    intelBody.replaceChildren();
    intelSources.forEach((src) => {
      const tr = document.createElement('tr');
      const tdSource = document.createElement('td');
      tdSource.setAttribute('data-label', 'Intel Source');
      tdSource.textContent = src.source;
      const tdMethod = document.createElement('td');
      tdMethod.setAttribute('data-label', 'Method');
      tdMethod.textContent = src.method;
      const tdWeight = document.createElement('td');
      tdWeight.className = 'mono';
      tdWeight.setAttribute('data-label', 'Weight');
      tdWeight.textContent = src.weight;
      const tdStatus = document.createElement('td');
      tdStatus.setAttribute('data-label', 'Status');
      const tag = document.createElement('span');
      tag.className = 'badge-mini';
      tag.textContent = src.status;
      tdStatus.appendChild(tag);

      tr.append(tdSource, tdMethod, tdWeight, tdStatus);
      intelBody.appendChild(tr);
    });

    resultsSection.classList.remove('hidden');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  async function runAnalysis(rawUrl) {
    hideError();
    const urlInput = document.getElementById('url-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const progressPanel = document.getElementById('progress-panel');
    const stepItems = document.querySelectorAll('#progress-steps li');

    let candidate = (rawUrl || '').trim();
    if (!candidate) {
      showError('Please paste a product URL from an online shop.');
      return;
    }

    // Convenience helper only when user omitted https:// without a scheme prefix
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(candidate)) {
      candidate = `https://${candidate}`;
      if (urlInput) urlInput.value = candidate;
    }

    if (analyzeBtn) analyzeBtn.disabled = true;
    if (progressPanel) progressPanel.classList.remove('hidden');

    const stopwatchEl = document.getElementById('audit-stopwatch');
    const auditStart = performance.now();
    const stopwatchTimer = setInterval(() => {
      if (stopwatchEl) {
        const sec = ((performance.now() - auditStart) / 1000).toFixed(1);
        stopwatchEl.textContent = `${sec}s`;
      }
    }, 100);

    let activeStep = 0;
    const stepTimer = setInterval(() => {
      stepItems.forEach((li, i) => {
        li.classList.toggle('active-step', i === activeStep);
      });
      activeStep = Math.min(stepItems.length - 1, activeStep + 1);
    }, 240);

    try {
      const requestBody = { url: candidate };
      if (turnstileSiteKey && turnstileToken) {
        requestBody.turnstileToken = turnstileToken;
      }

      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      const payload = await response.json();
      if (!response.ok) {
        showError(payload.message || 'Unable to inspect this URL.');
        return;
      }

      renderReport(payload);
      try {
        const u = new URL(window.location.href);
        u.searchParams.set('url', candidate);
        window.history.replaceState({}, '', u.toString());
      } catch {
        // Ignore URL state errors
      }
    } catch {
      showError('Network or server error while inspecting URL. Please check your connection and try again.');
    } finally {
      clearInterval(stepTimer);
      clearInterval(stopwatchTimer);
      if (stopwatchEl) stopwatchEl.textContent = '0.0s';
      if (progressPanel) progressPanel.classList.add('hidden');
      if (analyzeBtn) analyzeBtn.disabled = false;
      if (turnstileWidgetId !== null && window.turnstile && typeof window.turnstile.reset === 'function') {
        turnstileToken = '';
        window.turnstile.reset(turnstileWidgetId);
      }
    }
  }

  function initTurnstileIfConfigured() {
    const slot = document.getElementById('turnstile-widget-slot');
    if (!slot) return;

    const cfgPromise =
      window.__rpnlPublicConfigPromise ||
      fetch('/api/public-config', { method: 'GET' })
        .then((r) => (r.ok ? r.json() : {}))
        .catch(() => ({}));

    cfgPromise.then((cfg) => {
      if (!cfg || !cfg.turnstileSiteKey) return;
      turnstileSiteKey = cfg.turnstileSiteKey;
      slot.classList.remove('hidden');

      window.__onRpnlTurnstileLoad = () => {
        if (!window.turnstile || turnstileWidgetId !== null) return;
        const isMobileNarrow = typeof window !== 'undefined' && window.innerWidth < 380;
        turnstileWidgetId = window.turnstile.render(slot, {
          sitekey: turnstileSiteKey,
          action: 'analyze',
          size: isMobileNarrow ? 'compact' : 'normal',
          theme: document.documentElement.getAttribute('data-theme') === 'carbon' ? 'dark' : 'light',
          callback: (token) => {
            turnstileToken = token;
          },
          'expired-callback': () => {
            turnstileToken = '';
          }
        });
      };

      const s = document.createElement('script');
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=__onRpnlTurnstileLoad';
      s.async = true;
      s.defer = true;
      document.head.appendChild(s);
    });
  }

  function initApp() {
    initTheme();
    initTermsModal();
    initTurnstileIfConfigured();
    updateClock();
    setInterval(updateClock, 30_000);

    const form = document.getElementById('analyze-form');
    const urlInput = document.getElementById('url-input');
    const clearBtn = document.getElementById('clear-url-btn');
    const newCheckBtn = document.getElementById('inspect-another-btn');
    const range30Btn = document.getElementById('range-30-btn');
    const range90Btn = document.getElementById('range-90-btn');
    const range180Btn = document.getElementById('range-180-btn');

    if (form) {
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        runAnalysis(urlInput ? urlInput.value : '');
      });
    }

    if (clearBtn && urlInput) {
      clearBtn.addEventListener('click', () => {
        urlInput.value = '';
        hideError();
        urlInput.focus();
      });
    }

    if (newCheckBtn && urlInput) {
      newCheckBtn.addEventListener('click', () => {
        urlInput.value = '';
        hideError();
        window.scrollTo({ top: 0, behavior: 'smooth' });
        urlInput.focus();
      });
    }

    const rangeButtons = [
      { btn: range30Btn, days: 30 },
      { btn: range90Btn, days: 90 },
      { btn: range180Btn, days: 180 }
    ];
    rangeButtons.forEach(({ btn, days }) => {
      if (!btn) return;
      btn.addEventListener('click', () => {
        currentChartRange = days;
        rangeButtons.forEach((b) => {
          if (b.btn) b.btn.classList.toggle('active', b.days === days);
        });
        if (lastReport) renderPriceChart(lastReport, currentChartRange);
      });
    });

    // 21st.dev Interactive Quick Live Audit Chips
    document.querySelectorAll('.demo-chip').forEach((chip) => {
      chip.addEventListener('click', () => {
        const demoUrl = chip.getAttribute('data-url');
        if (demoUrl) {
          if (urlInput) urlInput.value = demoUrl;
          runAnalysis(demoUrl);
        }
      });
    });

    // Share report button with tactile feedback
    const shareBtn = document.getElementById('share-report-btn');
    if (shareBtn) {
      shareBtn.addEventListener('click', async () => {
        const shareUrl = window.location.href;
        try {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(shareUrl);
          } else {
            const temp = document.createElement('input');
            temp.value = shareUrl;
            document.body.appendChild(temp);
            temp.select();
            document.execCommand('copy');
            document.body.removeChild(temp);
          }
          const orig = shareBtn.textContent;
          shareBtn.textContent = 'COPIED! ✓';
          shareBtn.classList.add('btn-copied');
          setTimeout(() => {
            shareBtn.textContent = orig;
            shareBtn.classList.remove('btn-copied');
          }, 2000);
        } catch {
          // Ignore clipboard failure
        }
      });
    }

    // 21st.dev Dynamic Cursor Spotlight Tracking
    document.querySelectorAll('.card-sharp').forEach((card) => {
      card.addEventListener('pointermove', (e) => {
        const rect = card.getBoundingClientRect();
        card.style.setProperty('--mouse-x', `${e.clientX - rect.left}px`);
        card.style.setProperty('--mouse-y', `${e.clientY - rect.top}px`);
      });
    });

    // Auto-inspect if ?url= parameter is provided in query string
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const initialUrl = urlParams.get('url');
      if (initialUrl && (initialUrl.startsWith('http://') || initialUrl.startsWith('https://'))) {
        if (urlInput) urlInput.value = initialUrl;
        runAnalysis(initialUrl);
      }
    } catch {
      // Ignore query string parse errors
    }
  }

  document.addEventListener('DOMContentLoaded', initApp);
})();

