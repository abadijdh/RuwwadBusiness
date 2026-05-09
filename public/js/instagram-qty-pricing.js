/**
 * نفس منطق الخادم: سعر ≈ (كمية/1000)×سعر_الألف، نقاط مقترحة = ⌈كمية/2⌉
 */
(function (global) {
  global.instagramQtyEstimate = {
    compute(pricing, rawQty) {
      if (!pricing || typeof pricing.pricePer1000 !== 'number') {
        return { ok: false, errorAr: '—' };
      }
      const q = Math.floor(Number(rawQty));
      if (!Number.isFinite(q)) return { ok: false, errorAr: 'كمية غير صالحة' };
      if (q < pricing.minQty || q > pricing.maxQty) {
        return {
          ok: false,
          errorAr: `الحد ${pricing.minQty}–${pricing.maxQty.toLocaleString('en-US')}`,
        };
      }
      const sar = Math.round((q / 1000) * pricing.pricePer1000 * 100) / 100;
      const pointsRequired = Math.ceil(q / 2);
      return { ok: true, quantity: q, priceSar: sar, pointsRequired };
    },
  };
})(typeof window !== 'undefined' ? window : globalThis);
