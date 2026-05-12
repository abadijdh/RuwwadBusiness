/**
 * Instagram Platform — OAuth (Instagram Login) للتحقق من حساب احترافي وربطه بملف المشترك.
 *
 * ضبط متغيرات البيئة (Meta App من نوع Business + منتج Instagram):
 * - INSTAGRAM_APP_ID   ← من لوحة Meta: Instagram → إعداد API مع تسجيل دخول Instagram → تسجيل دخول Business → إعدادات Business login → «Instagram App ID» (قد يطابق App ID العام وقد لا؛ لا تستخدم رقماً من تطبيق آخر)
 * - INSTAGRAM_APP_SECRET ← من نفس الشاشة: «Instagram app secret» (قد يطابق سر التطبيق العام)
 * - INSTAGRAM_REDIRECT_URI  ← يجب أن يطابق «Valid OAuth Redirect URIs» حرفياً (بما فيه الشرطة المائلة الأخيرة إن وُجدت)
 * - INSTAGRAM_LOGIN_SCOPE     اختياري، افتراضي: instagram_business_basic
 * - INSTAGRAM_GRAPH_API_VERSION اختياري، افتراضي: v21.0
 * - INSTAGRAM_OAUTH_STATE_SECRET اختياري لتوقيع state (إن غاب يُستخدم INSTAGRAM_APP_SECRET)
 * - PUBLIC_URL أو PUBLIC_BASE_URL للعودة بعد الربط عند النشر على نطاق مختلف
 *
 * مرجع: https://developers.facebook.com/docs/instagram-platform/instagram-api-with-instagram-login/
 */
const crypto = require('crypto');

function getInstagramOAuthConfig() {
  const appId = String(process.env.INSTAGRAM_APP_ID || '').trim();
  const appSecret = String(process.env.INSTAGRAM_APP_SECRET || '').trim();
  const redirectUri = String(process.env.INSTAGRAM_REDIRECT_URI || '').trim();
  const graphVersion = String(process.env.INSTAGRAM_GRAPH_API_VERSION || 'v21.0').trim() || 'v21.0';
  const scope = String(process.env.INSTAGRAM_LOGIN_SCOPE || 'instagram_business_basic').trim();
  return {
    appId,
    appSecret,
    redirectUri,
    graphVersion,
    scope,
    configured: !!(appId && appSecret && redirectUri),
  };
}

function stateSecret() {
  return String(process.env.INSTAGRAM_OAUTH_STATE_SECRET || process.env.INSTAGRAM_APP_SECRET || '').trim();
}

function makeInstagramOAuthState(portalToken) {
  const sec = stateSecret();
  if (!sec) throw new Error('INSTAGRAM_APP_SECRET مطلوب لتوقيع جلسة الربط');
  const payload = Buffer.from(
    JSON.stringify({ t: String(portalToken || ''), exp: Date.now() + 15 * 60 * 1000 }),
    'utf8'
  ).toString('base64url');
  const sig = crypto.createHmac('sha256', sec).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function parseInstagramOAuthState(state) {
  const sec = stateSecret();
  if (!sec || state == null) return '';
  const s = String(state).trim();
  const dot = s.lastIndexOf('.');
  if (dot === -1) return '';
  const payload = s.slice(0, dot);
  const sig = s.slice(dot + 1);
  const expected = crypto.createHmac('sha256', sec).update(payload).digest('base64url');
  try {
    const sb = Buffer.from(sig, 'utf8');
    const eb = Buffer.from(expected, 'utf8');
    if (sb.length !== eb.length || !crypto.timingSafeEqual(sb, eb)) return '';
  } catch {
    return '';
  }
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data || typeof data.t !== 'string' || data.t.length < 24) return '';
    if (typeof data.exp !== 'number' || data.exp < Date.now()) return '';
    return data.t;
  } catch {
    return '';
  }
}

function cleanAuthCode(raw) {
  let c = String(raw ?? '').trim();
  const h = c.indexOf('#');
  if (h !== -1) c = c.slice(0, h).trim();
  return c;
}

function normalizeInstagramUsername(u) {
  return String(u ?? '')
    .trim()
    .replace(/^@+/, '')
    .toLowerCase();
}

async function exchangeInstagramAuthorizationCode(code, redirectUri) {
  const { appId, appSecret } = getInstagramOAuthConfig();
  const body = new URLSearchParams({
    client_id: appId,
    client_secret: appSecret,
    grant_type: 'authorization_code',
    redirect_uri: redirectUri,
    code: cleanAuthCode(code),
  });
  const r = await fetch('https://api.instagram.com/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = j.error_message || j.error?.message || JSON.stringify(j);
    throw new Error(msg || 'فشل استبدال رمز التفويض');
  }
  if (!j.access_token) throw new Error('لم يُرجَد رمز وصول من إنستغرام');
  return j;
}

/** يطيل عمر الرمز عند نجاح الطلب؛ عند الفشل يُعاد الرمز القصير */
async function exchangeInstagramLongLivedToken(shortLivedToken) {
  const { appSecret } = getInstagramOAuthConfig();
  const u = new URL('https://graph.instagram.com/access_token');
  u.searchParams.set('grant_type', 'ig_exchange_token');
  u.searchParams.set('client_secret', appSecret);
  u.searchParams.set('access_token', shortLivedToken);
  const r = await fetch(u.toString(), { method: 'GET' });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) return shortLivedToken;
  return String(j.access_token);
}

async function fetchInstagramMe(accessToken) {
  const { graphVersion } = getInstagramOAuthConfig();
  const u = new URL(`https://graph.instagram.com/${graphVersion}/me`);
  u.searchParams.set('fields', 'id,user_id,username');
  u.searchParams.set('access_token', accessToken);
  const r = await fetch(u.toString(), { method: 'GET' });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = j.error?.message || j.error_message || 'فشل طلب بيانات المستخدم';
    throw new Error(msg);
  }
  if (j.username != null) {
    return {
      igUserId: String(j.user_id ?? j.id ?? ''),
      username: String(j.username),
    };
  }
  const row = Array.isArray(j.data) ? j.data[0] : null;
  if (row && row.username != null) {
    return {
      igUserId: String(row.user_id ?? row.id ?? ''),
      username: String(row.username),
    };
  }
  throw new Error('استجابة غير متوقعة من واجهة إنستغرام');
}

function buildInstagramAuthorizeUrl({ portalToken }) {
  const cfg = getInstagramOAuthConfig();
  if (!cfg.configured) throw new Error('not_configured');
  const state = makeInstagramOAuthState(portalToken);
  /** Meta Business Login يستخدم نطاق www (راجع وثائق Business Login for Instagram) */
  const p = new URL('https://www.instagram.com/oauth/authorize');
  p.searchParams.set('client_id', cfg.appId);
  p.searchParams.set('redirect_uri', cfg.redirectUri);
  p.searchParams.set('response_type', 'code');
  p.searchParams.set('scope', cfg.scope);
  p.searchParams.set('state', state);
  return p.toString();
}

module.exports = {
  getInstagramOAuthConfig,
  makeInstagramOAuthState,
  parseInstagramOAuthState,
  exchangeInstagramAuthorizationCode,
  exchangeInstagramLongLivedToken,
  fetchInstagramMe,
  buildInstagramAuthorizeUrl,
  normalizeInstagramUsername,
};
