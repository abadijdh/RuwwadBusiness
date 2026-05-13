'use strict';

/**
 * إرسال رسائل واتساب عبر Cloud API باستخدام قوالب معتمدة من Meta فقط.
 * @see https://developers.facebook.com/docs/whatsapp/cloud-api/guides/send-messages#template-messages
 */

function stripDigits(s) {
  return String(s ?? '').replace(/\D/g, '');
}

function normalizeGraphVersion(raw) {
  let v = String(raw ?? 'v21.0').trim();
  if (!v) v = 'v21.0';
  if (!/^v?\d+/i.test(v)) v = 'v21.0';
  if (!v.startsWith('v')) v = `v${v}`;
  return v;
}

function whatsappCloudConfig() {
  const accessToken = String(process.env.WHATSAPP_CLOUD_ACCESS_TOKEN ?? '').trim();
  const phoneNumberId = String(process.env.WHATSAPP_PHONE_NUMBER_ID ?? '').trim();
  const graphVersion = normalizeGraphVersion(process.env.WHATSAPP_GRAPH_API_VERSION);
  return {
    configured: !!(accessToken && phoneNumberId),
    accessToken,
    phoneNumberId,
    graphVersion,
  };
}

function maskPhoneNumberId(id) {
  const s = String(id);
  if (s.length < 5) return '***';
  return `${s.slice(0, 2)}…${s.slice(-2)}`;
}

/**
 * @param {{ toDigits: string, templateName: string, languageCode?: string, bodyParams?: string[] }} opts
 */
async function sendWhatsappTemplate(opts) {
  const cfg = whatsappCloudConfig();
  if (!cfg.configured) {
    const err = new Error(
      'واتساب غير مُهيأ على السيرفر — أضِف WHATSAPP_CLOUD_ACCESS_TOKEN و WHATSAPP_PHONE_NUMBER_ID في .env'
    );
    err.code = 'WA_NOT_CONFIGURED';
    throw err;
  }

  const to = stripDigits(opts.toDigits);
  if (!to || to.length < 9) {
    const err = new Error('رقم المستقبل غير صالح');
    err.code = 'WA_INVALID_TO';
    throw err;
  }

  const templateName = String(opts.templateName ?? '').trim().toLowerCase();
  if (!templateName || !/^[a-z][a-z0-9_]{0,511}$/.test(templateName)) {
    const err = new Error(
      'اسم القالب غير صالح — استخدم الاسم كما في مدير واتساب (أحرف إنجليزية صغيرة وأرقام و _).'
    );
    err.code = 'WA_BAD_TEMPLATE';
    throw err;
  }

  const languageCode = String(opts.languageCode ?? 'ar').trim().slice(0, 16) || 'ar';
  const bodyParams = Array.isArray(opts.bodyParams)
    ? opts.bodyParams.map((x) => String(x ?? '').slice(0, 1024))
    : [];

  const template = {
    name: templateName,
    language: { code: languageCode },
  };
  if (bodyParams.length) {
    template.components = [
      {
        type: 'body',
        parameters: bodyParams.map((text) => ({ type: 'text', text })),
      },
    ];
  }

  const url = `https://graph.facebook.com/${cfg.graphVersion}/${cfg.phoneNumberId}/messages`;
  const payload = {
    messaging_product: 'whatsapp',
    to,
    type: 'template',
    template,
  };

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${cfg.accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { _raw: text };
  }

  if (!res.ok) {
    const msg =
      json?.error?.message ||
      json?.error?.error_user_msg ||
      (typeof text === 'string' && text.slice(0, 500)) ||
      res.statusText;
    const err = new Error(msg || `HTTP ${res.status}`);
    err.code = 'WA_GRAPH_ERROR';
    err.status = res.status;
    err.details = json;
    throw err;
  }

  return json;
}

module.exports = {
  whatsappCloudConfig,
  sendWhatsappTemplate,
  stripDigits,
  maskPhoneNumberId,
};
