/**
 * شريط أحمر موحّد أسفل صفحات العملاء — المحتوى من لوحة الفريق (GET /api/settings/global-banner).
 */
(function () {
  function injectStyles() {
    if (document.getElementById('site-global-banner-styles')) return;
    const s = document.createElement('style');
    s.id = 'site-global-banner-styles';
    s.textContent = `
#siteGlobalBannerBar {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  z-index: 999999;
  max-height: min(32vh, 12rem);
  overflow-y: auto;
  -webkit-overflow-scrolling: touch;
  padding: 0.55rem 1rem calc(0.55rem + env(safe-area-inset-bottom, 0px));
  margin: 0;
  border-top: 2px solid rgba(248, 113, 113, 0.7);
  background: linear-gradient(180deg, rgba(153, 27, 27, 0.94) 0%, rgba(40, 10, 18, 0.98) 100%);
  color: #fecaca;
  font-size: 0.84rem;
  line-height: 1.55;
  text-align: center;
  box-shadow: 0 -10px 36px rgba(0, 0, 0, 0.5);
}
#siteGlobalBannerBar a { color: #fbcfe8; font-weight: 700; }
#siteGlobalBannerBar strong { color: #fff; }
body.site-global-banner-on { box-sizing: border-box; }
`;
    document.head.appendChild(s);
  }

  function syncPadding() {
    const bar = document.getElementById('siteGlobalBannerBar');
    if (!bar || !document.body.classList.contains('site-global-banner-on')) {
      document.body.style.paddingBottom = '';
      return;
    }
    const h = Math.ceil(bar.getBoundingClientRect().height);
    document.body.style.paddingBottom = h + 'px';
  }

  async function run() {
    injectStyles();
    try {
      const r = await fetch('/api/settings/global-banner', { cache: 'no-store', headers: { Accept: 'application/json' } });
      const data = await r.json().catch(() => ({}));
      const html = data.globalBannerHtml != null ? String(data.globalBannerHtml).trim() : '';
      if (!r.ok || !html) return;

      const bar = document.createElement('div');
      bar.id = 'siteGlobalBannerBar';
      bar.setAttribute('role', 'region');
      bar.setAttribute('aria-label', 'تنبيه أو عرض من المنصة');
      bar.innerHTML = html;
      document.body.appendChild(bar);
      document.body.classList.add('site-global-banner-on');

      syncPadding();
      if (typeof ResizeObserver !== 'undefined') {
        const ro = new ResizeObserver(() => syncPadding());
        ro.observe(bar);
      }
      window.addEventListener('resize', syncPadding);
    } catch (_) {}
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run);
  else run();
})();
