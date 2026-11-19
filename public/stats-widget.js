(function () {
  'use strict';

  const THEME_STORAGE_KEY = 'rpnl_theme_v1';

  function initSubpageTheme() {
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
        toggleBtn.textContent = theme === 'carbon' ? 'PAPER MODE' : 'CARBON MODE';
      }
      try {
        window.localStorage.setItem(THEME_STORAGE_KEY, theme);
      } catch {
        // Ignore storage restrictions
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

  function updateClock() {
    const el = document.getElementById('utc-clock');
    if (!el) return;
    el.textContent = `UTC ${new Date().toISOString().slice(0, 16).replace('T', ' ')}`;
  }

  function loadPublicStats() {
    const pvEl = document.getElementById('stat-pageviews');
    const checksEl = document.getElementById('stat-analyses');
    const todayEl = document.getElementById('stat-today');
    const hitsEl = document.getElementById('stat-cache-hits');
    const retailersListEl = document.getElementById('stat-retailers-list');
    if (!pvEl && !checksEl) return;

    fetch('/api/stats')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!data) return;
        if (pvEl) pvEl.textContent = Number(data.totalPageViews || 0).toLocaleString();
        if (checksEl) checksEl.textContent = Number(data.totalAnalyses || 0).toLocaleString();
        if (todayEl) todayEl.textContent = Number(data.dailyAnalyses || 0).toLocaleString();
        if (hitsEl) hitsEl.textContent = Number(data.cacheHits || 0).toLocaleString();

        if (retailersListEl && Array.isArray(data.topRetailers)) {
          retailersListEl.replaceChildren();
          if (data.topRetailers.length === 0) {
            const span = document.createElement('span');
            span.className = 'tag-outline mono';
            span.textContent = 'AWAITING LIVE INSPECTIONS';
            retailersListEl.appendChild(span);
          } else {
            data.topRetailers.forEach((item) => {
              const span = document.createElement('span');
              span.className = 'tag-outline mono';
              span.textContent = `${item.retailer}: ${item.count}`;
              retailersListEl.appendChild(span);
            });
          }
        }
      })
      .catch(() => {});
  }

  document.addEventListener('DOMContentLoaded', () => {
    initSubpageTheme();
    updateClock();
    setInterval(updateClock, 30_000);
    loadPublicStats();
  });
})();

