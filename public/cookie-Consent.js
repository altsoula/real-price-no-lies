(function () {
  'use strict';

  const CONSENT_STORAGE_KEY = 'rpnl_cookie_consent_v1';
  const CONSENT_COOKIE_NAME = 'rpnl_consent';

  /**
   * Production Monetization & Sponsor Configuration.
   * Keep `enabled: false` to hide ad containers completely when no live buyer/network is active.
   *
   * Option A — Direct Sponsor Buyer (`provider: 'direct'`):
   *   Set `enabled: true` and configure any slot under `directCampaigns` with `enabled: true`.
   * Option B — Google AdSense (`provider: 'adsense'`):
   *   Set `enabled: true`, fill `adsenseClientId` ('ca-pub-...'), and slot IDs in `adsenseSlots`,
   *   and whitelist Google AdSense domains in `src/security/headers.js` CSP.
   */
  const AD_MONETIZATION_CONFIG = {
    enabled: false,
    provider: 'direct', // 'direct' | 'adsense'
    adsenseClientId: '',
    adsenseSlots: {
      'top-leaderboard': '',
      'in-report-native': '',
      'footer-leaderboard': ''
    },
    directCampaigns: {
      'top-leaderboard': {
        enabled: false,
        sponsorName: '',
        headline: '',
        description: '',
        ctaText: 'Learn More',
        targetUrl: ''
      },
      'in-report-native': {
        enabled: false,
        sponsorName: '',
        headline: '',
        description: '',
        ctaText: 'Visit Partner',
        targetUrl: ''
      },
      'footer-leaderboard': {
        enabled: false,
        sponsorName: '',
        headline: '',
        description: '',
        ctaText: 'Learn More',
        targetUrl: ''
      }
    }
  };

  function isSafeExternalUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl.trim()) return null;
    try {
      const parsed = new URL(rawUrl.trim());
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
      return parsed.toString();
    } catch {
      return null;
    }
  }

  function readConsent() {
    try {
      const raw = window.localStorage.getItem(CONSENT_STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && parsed.necessary === true) {
        return {
          necessary: true,
          analytics: Boolean(parsed.analytics),
          advertising: Boolean(parsed.advertising),
          updatedAt: String(parsed.updatedAt || '')
        };
      }
    } catch {
      return null;
    }
    return null;
  }

  function writeConsent(prefs) {
    const normalized = {
      necessary: true,
      analytics: Boolean(prefs.analytics),
      advertising: Boolean(prefs.advertising),
      updatedAt: new Date().toISOString()
    };

    try {
      window.localStorage.setItem(CONSENT_STORAGE_KEY, JSON.stringify(normalized));
    } catch {
      // Storage blocked in private browsing; proceed cleanly in-memory
    }

    const cookieVal = encodeURIComponent(
      `n:1|a:${normalized.analytics ? 1 : 0}|ad:${normalized.advertising ? 1 : 0}`
    );
    const secureFlag = window.location.protocol === 'https:' ? '; Secure' : '';
    document.cookie = `${CONSENT_COOKIE_NAME}=${cookieVal}; Max-Age=15552000; Path=/; SameSite=Lax${secureFlag}`;
    return normalized;
  }

  function renderDirectSponsor(bodyEl, campaign) {
    const safeHref = isSafeExternalUrl(campaign.targetUrl);
    if (!safeHref) return false;

    bodyEl.replaceChildren();
    const wrap = document.createElement('div');
    wrap.className = 'sponsor-banner-live';

    const copy = document.createElement('div');
    copy.className = 'sponsor-copy';

    const badge = document.createElement('span');
    badge.className = 'sponsor-badge';
    badge.textContent = `AD · ${campaign.sponsorName || 'SPONSOR'}`;

    const title = document.createElement('strong');
    title.textContent = campaign.headline || '';

    const desc = document.createElement('p');
    desc.textContent = campaign.description || '';

    copy.append(badge, title, desc);

    const cta = document.createElement('a');
    cta.className = 'btn-primary sponsor-cta';
    cta.href = safeHref;
    cta.target = '_blank';
    cta.rel = 'sponsored noopener noreferrer';
    cta.textContent = campaign.ctaText || 'Learn More';

    wrap.append(copy, cta);
    bodyEl.appendChild(wrap);
    return true;
  }

  function renderAdsenseUnit(bodyEl, clientId, slotId) {
    if (!clientId || !slotId) return false;
    bodyEl.replaceChildren();
    const ins = document.createElement('ins');
    ins.className = 'adsbygoogle';
    ins.style.display = 'block';
    ins.setAttribute('data-ad-client', clientId);
    ins.setAttribute('data-ad-slot', slotId);
    ins.setAttribute('data-ad-format', 'auto');
    ins.setAttribute('data-full-width-responsive', 'true');
    bodyEl.appendChild(ins);
    if (Array.isArray(window.adsbygoogle)) {
      try {
        window.adsbygoogle.push({});
      } catch {
        return false;
      }
    }
    return true;
  }

  function syncAdSlots(consent) {
    const slots = document.querySelectorAll('[data-ad-slot]');
    const adsAllowed = Boolean(consent && consent.advertising);

    slots.forEach((slot) => {
      const rail = slot.closest('aside');
      const slotName = slot.getAttribute('data-ad-slot');
      const bodyEl = slot.querySelector('[data-ad-body]');
      if (!rail || !bodyEl) return;

      // Never render placeholder/empty ad boxes if monetization is disabled or unconfigured
      if (!AD_MONETIZATION_CONFIG.enabled) {
        rail.classList.add('hidden');
        bodyEl.replaceChildren();
        return;
      }

      if (AD_MONETIZATION_CONFIG.provider === 'direct') {
        const campaign = AD_MONETIZATION_CONFIG.directCampaigns[slotName];
        if (campaign && campaign.enabled && renderDirectSponsor(bodyEl, campaign)) {
          rail.classList.remove('hidden');
        } else {
          rail.classList.add('hidden');
          bodyEl.replaceChildren();
        }
        return;
      }

      if (AD_MONETIZATION_CONFIG.provider === 'adsense' && adsAllowed) {
        const slotId = AD_MONETIZATION_CONFIG.adsenseSlots[slotName];
        if (renderAdsenseUnit(bodyEl, AD_MONETIZATION_CONFIG.adsenseClientId, slotId)) {
          rail.classList.remove('hidden');
        } else {
          rail.classList.add('hidden');
          bodyEl.replaceChildren();
        }
        return;
      }

      rail.classList.add('hidden');
      bodyEl.replaceChildren();
    });
  }

  function initCookieManager() {
    const banner = document.getElementById('cookie-banner');
    const modal = document.getElementById('cookie-modal');
    const acceptAllBtn = document.getElementById('cookie-accept-all-btn');
    const essentialOnlyBtn = document.getElementById('cookie-essential-btn');
    const customizeBtn = document.getElementById('cookie-customize-btn');
    const savePrefsBtn = document.getElementById('save-cookie-prefs-btn');
    const closeModalBtn = document.getElementById('close-cookie-modal-btn');
    const openTopBtn = document.getElementById('open-cookie-btn');
    const openFooterBtn = document.getElementById('footer-cookies-btn');
    const analyticsCheckbox = document.getElementById('toggle-analytics-cookie');
    const adsCheckbox = document.getElementById('toggle-ads-cookie');

    function openCookieModal() {
      const current = readConsent() || { necessary: true, analytics: false, advertising: false };
      if (analyticsCheckbox) analyticsCheckbox.checked = Boolean(current.analytics);
      if (adsCheckbox) adsCheckbox.checked = Boolean(current.advertising);
      if (modal) modal.classList.remove('hidden');
    }

    function closeCookieModal() {
      if (modal) modal.classList.add('hidden');
    }

    function commitConsent(prefs) {
      const saved = writeConsent(prefs);
      if (banner) banner.classList.add('hidden');
      closeCookieModal();
      syncAdSlots(saved);
    }

    const existing = readConsent();
    if (!existing) {
      if (banner) banner.classList.remove('hidden');
      syncAdSlots(null);
    } else {
      syncAdSlots(existing);
    }

    if (acceptAllBtn) {
      acceptAllBtn.addEventListener('click', () => {
        commitConsent({ analytics: true, advertising: true });
      });
    }
    if (essentialOnlyBtn) {
      essentialOnlyBtn.addEventListener('click', () => {
        commitConsent({ analytics: false, advertising: false });
      });
    }
    if (customizeBtn) {
      customizeBtn.addEventListener('click', openCookieModal);
    }
    if (openTopBtn) {
      openTopBtn.addEventListener('click', openCookieModal);
    }
    if (openFooterBtn) {
      openFooterBtn.addEventListener('click', openCookieModal);
    }
    if (closeModalBtn) {
      closeModalBtn.addEventListener('click', closeCookieModal);
    }
    if (savePrefsBtn) {
      savePrefsBtn.addEventListener('click', () => {
        commitConsent({
          analytics: analyticsCheckbox ? analyticsCheckbox.checked : false,
          advertising: adsCheckbox ? adsCheckbox.checked : false
        });
      });
    }
    if (modal) {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) closeCookieModal();
      });
    }

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && modal && !modal.classList.contains('hidden')) {
        closeCookieModal();
      }
    });
  }

  document.addEventListener('DOMContentLoaded', initCookieManager);
})();
