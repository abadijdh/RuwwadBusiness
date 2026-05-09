/**
 * يحمّل نصوصاً من /site-public-copy.json لتعديلها بدون لمس HTML.
 * الرسائل التي تحتوي وسوم HTML استخدم data-copy-html مع قيمة في JSON تحتوي وسوماً آمينة (أنت تتحكم بالملف).
 */
async function applyPublicCopyFromJson(pageKey) {
  window.__PUBLIC_COPY__ = window.__PUBLIC_COPY__ || {};
  try {
    const r = await fetch('/site-public-copy.json', { cache: 'no-store' });
    if (!r.ok) return;
    const all = await r.json();
    window.__PUBLIC_COPY__ = all;
    const block = all[pageKey];
    if (!block || typeof block !== 'object') return;

    if (pageKey === 'join' && typeof block.metaTitle === 'string' && block.metaTitle.trim()) {
      document.title = block.metaTitle.trim();
    }
    if (pageKey === 'join' && typeof block.metaDescription === 'string' && block.metaDescription.trim()) {
      const m = document.querySelector('meta[name="description"]');
      if (m) m.setAttribute('content', block.metaDescription.trim());
    }
    if (pageKey === 'subscriberLogin' && typeof block.metaTitle === 'string' && block.metaTitle.trim()) {
      document.title = block.metaTitle.trim();
    }
    if (pageKey === 'myAccount' && typeof block.metaTitle === 'string' && block.metaTitle.trim()) {
      document.title = block.metaTitle.trim();
    }

    document.querySelectorAll('[data-copy]').forEach((el) => {
      const key = el.getAttribute('data-copy');
      if (!key || block[key] == null || String(block[key]).trim() === '') return;
      const v = String(block[key]);
      if (el.hasAttribute('data-copy-html')) el.innerHTML = v;
      else el.textContent = v;
    });

    document.querySelectorAll('[data-copy-placeholder]').forEach((el) => {
      const key = el.getAttribute('data-copy-placeholder');
      if (!key || block[key] == null || String(block[key]).trim() === '') return;
      el.setAttribute('placeholder', String(block[key]));
    });

    document.querySelectorAll('[data-copy-aria]').forEach((el) => {
      const key = el.getAttribute('data-copy-aria');
      if (!key || block[key] == null || String(block[key]).trim() === '') return;
      el.setAttribute('aria-label', String(block[key]));
    });
  } catch (_) {
    /* يبقى النص الافتراضي في HTML */
  }
}
