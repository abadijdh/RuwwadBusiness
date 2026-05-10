/**
 * رواد الأعمال — API بسيطة (Express + MongoDB)
 * الإشعارات (Firebase) يمكن إضافتها لاحقاً عند الحاجة.
 */
const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const { Decimal128, BSONRegExp } = require('bson');
const { ZipArchive } = require('archiver');

const app = express();
app.set('trust proxy', 1);
app.use(express.json());

const PORT = Number(process.env.PORT) || 5000;
const MONGO_URI = (process.env.MONGO_URI || '').trim();
const publicDir = path.join(__dirname, 'public');

/** مسار لوحة الطاقم السري (بدون /). إن وُجد: الجذر / يوجّه العملاء إلى /join واللوحة فقط على /<المسار> */
function sanitizeTeamPanelSecretPath(raw) {
  const s = String(raw ?? '')
    .trim()
    .replace(/^\/+/g, '')
    .replace(/\/+$/g, '');
  if (!s) return '';
  if (s.length > 128 || !/^[a-zA-Z0-9_-]+$/.test(s)) {
    console.warn(
      '[WARN] TEAM_PANEL_SECRET_PATH غير صالح — حروف لاتينية وأرقام و _ و - فقط، بدون /. تم تجاهله.'
    );
    return '';
  }
  if (s.length < 4) {
    console.warn('[WARN] TEAM_PANEL_SECRET_PATH قصير جداً — تم تجاهله.');
    return '';
  }
  return s;
}

const TEAM_PANEL_SECRET_PATH = sanitizeTeamPanelSecretPath(process.env.TEAM_PANEL_SECRET_PATH);
const TEAM_PANEL_PASSWORD = String(process.env.TEAM_PANEL_PASSWORD || '').trim();

const TEAM_GATE_COOKIE = 'team_gate';
const TEAM_GATE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const teamGateSessions = new Map();

function cookieSecureFromReq(req) {
  if (req.secure) return true;
  const xf = String(req.headers['x-forwarded-proto'] || '')
    .split(',')[0]
    .trim()
    .toLowerCase();
  return xf === 'https';
}

function readTeamGateCookie(req) {
  const raw = req.headers.cookie;
  if (!raw || typeof raw !== 'string') return '';
  const parts = raw.split(';');
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    const idx = p.indexOf('=');
    if (idx === -1) continue;
    const k = p.slice(0, idx).trim();
    if (k !== TEAM_GATE_COOKIE) continue;
    let v = p.slice(idx + 1).trim();
    try {
      v = decodeURIComponent(v);
    } catch {
      /* keep */
    }
    return String(v).trim();
  }
  return '';
}

function appendTeamGateCookie(res, token, req) {
  const tok = String(token || '').trim();
  if (!tok) return;
  const bits = [
    `${TEAM_GATE_COOKIE}=${encodeURIComponent(tok)}`,
    'Path=/',
    `Max-Age=${Math.floor(TEAM_GATE_MAX_AGE_MS / 1000)}`,
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (cookieSecureFromReq(req)) bits.push('Secure');
  res.append('Set-Cookie', bits.join('; '));
}

function clearTeamGateCookie(res, req) {
  const bits = [`${TEAM_GATE_COOKIE}=`, 'Path=/', 'Max-Age=0', 'HttpOnly', 'SameSite=Lax'];
  if (cookieSecureFromReq(req)) bits.push('Secure');
  res.append('Set-Cookie', bits.join('; '));
}

function hasValidTeamGate(req) {
  if (!TEAM_PANEL_PASSWORD) return true;
  const tok = readTeamGateCookie(req);
  if (!tok) return false;
  const exp = teamGateSessions.get(tok);
  if (!exp || exp < Date.now()) {
    teamGateSessions.delete(tok);
    return false;
  }
  return true;
}

function verifyTeamPanelPassword(submitted) {
  const a = crypto.createHash('sha256').update(String(submitted ?? ''), 'utf8').digest();
  const b = crypto.createHash('sha256').update(TEAM_PANEL_PASSWORD, 'utf8').digest();
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function serveTeamDashboardHtml(req, res) {
  if (TEAM_PANEL_PASSWORD && !hasValidTeamGate(req)) {
    return res.sendFile(path.join(publicDir, 'team-panel-login.html'));
  }
  /** واجهة لوحة الطاقم في team.html (وليس index.html الذي يُستخدم لصفحات أخرى عند الحاجة) */
  res.sendFile(path.join(publicDir, 'team.html'));
}

function teamPanelPublicApiPath(p, method) {
  const m = String(method || 'GET').toUpperCase();
  if (p === '/api/team-panel/login' && m === 'POST') return true;
  if (p === '/api/settings/join' && m === 'GET') return true;
  if (p === '/api/settings/subscriber-login' && m === 'GET') return true;
  if (p === '/api/settings/global-banner' && m === 'GET') return true;
  if (p === '/api/users' && m === 'POST') return true;
  if (p === '/api/client/service-requests' && m === 'POST') return true;
  if (p === '/api/public/service-request-options' && m === 'GET') return true;
  if (p.startsWith('/api/portal')) return true;
  if (p === '/api/campaign-portal/summary' && m === 'GET') return true;
  return false;
}

function teamPanelApiProtection(req, res, next) {
  if (!TEAM_PANEL_PASSWORD) return next();
  const p = req.path || '';
  if (!p.startsWith('/api')) return next();
  if (teamPanelPublicApiPath(p, req.method)) return next();
  if (!hasValidTeamGate(req)) {
    return res.status(401).json({
      error: 'غير مصرّح — سجّل الدخول إلى لوحة الطاقم.',
      code: 'TEAM_AUTH_REQUIRED',
    });
  }
  next();
}

app.use(express.static(publicDir, { index: false }));

app.get('/', (_req, res) => {
  if (TEAM_PANEL_SECRET_PATH) return res.redirect(302, '/join');
  serveTeamDashboardHtml(_req, res);
});

if (TEAM_PANEL_SECRET_PATH) {
  const teamBase = '/' + TEAM_PANEL_SECRET_PATH;
  app.get([teamBase, teamBase + '/'], serveTeamDashboardHtml);
}

app.get('/index.html', (req, res) => {
  if (TEAM_PANEL_SECRET_PATH) return res.redirect(302, '/' + TEAM_PANEL_SECRET_PATH);
  serveTeamDashboardHtml(req, res);
});

app.get('/team.html', (req, res) => {
  if (TEAM_PANEL_SECRET_PATH) return res.redirect(302, '/' + TEAM_PANEL_SECRET_PATH);
  serveTeamDashboardHtml(req, res);
});

/** شعار المنصة — ملف واحد يُخزَّن تحت /uploads/branding ويُعرَض في لوحة الفريق وصفحة الاشتراك */
const BRANDING_UPLOAD_DIR = path.join(__dirname, 'public', 'uploads', 'branding');
try {
  fs.mkdirSync(BRANDING_UPLOAD_DIR, { recursive: true });
} catch (e) {
  console.warn('[WARN] Branding upload dir:', e.message);
}

function unlinkBrandingUploadByPublicPath(relUrl) {
  if (!relUrl || typeof relUrl !== 'string') return;
  const u = relUrl.trim();
  if (!u.startsWith('/uploads/branding/')) return;
  const rel = u.replace(/^\/+/, '');
  const full = path.resolve(path.join(__dirname, 'public', rel));
  const root = path.resolve(BRANDING_UPLOAD_DIR);
  const relToRoot = path.relative(root, full);
  if (relToRoot.startsWith('..') || path.isAbsolute(relToRoot)) return;
  try {
    fs.unlinkSync(full);
  } catch (_) {}
}

const logoUploadMiddleware = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, BRANDING_UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || '').toLowerCase();
      const allowed = new Set(['.jpg', '.jpeg', '.png', '.webp', '.gif']);
      const safeExt = allowed.has(ext) ? ext : '.png';
      cb(null, `logo-${crypto.randomBytes(10).toString('hex')}${safeExt}`);
    },
  }),
  limits: { fileSize: 1.5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok = /^image\/(jpeg|png|webp|gif)$/i.test(file.mimetype || '');
    if (!ok) return cb(new Error('يُسمح بصور jpeg أو png أو webp أو gif فقط'));
    cb(null, true);
  },
}).single('logo');

const dbRestoreUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 250 * 1024 * 1024 },
}).single('backup');

/** يجب مطابقته حرفياً في حقل confirmText عند رفع ملف الاستعادة */
const DB_RESTORE_CONFIRM_PHRASE = 'FULL_DATABASE_RESTORE';

/** منصات التسجيل — المعرف ثابت للبرمجة؛ العرض بالعربية في الواجهات */
const SOCIAL_PLATFORM_META = [
  { id: 'instagram', labelAr: 'إنستغرام', profileUrl: (h) => `https://www.instagram.com/${encodeURIComponent(h)}/` },
  { id: 'tiktok', labelAr: 'تيك توك', profileUrl: (h) => `https://www.tiktok.com/@${encodeURIComponent(h)}` },
  { id: 'snapchat', labelAr: 'سناب شات', profileUrl: (h) => `https://www.snapchat.com/add/${encodeURIComponent(h)}` },
  { id: 'twitter', labelAr: 'إكس (تويتر)', profileUrl: (h) => `https://x.com/${encodeURIComponent(h)}` },
  { id: 'youtube', labelAr: 'يوتيوب', profileUrl: (h) => `https://www.youtube.com/@${encodeURIComponent(h)}` },
];
const PLATFORM_IDS = SOCIAL_PLATFORM_META.map((p) => p.id);
const PLATFORM_ID_SET = new Set(PLATFORM_IDS);
const PLATFORM_META_BY_ID = Object.fromEntries(SOCIAL_PLATFORM_META.map((p) => [p.id, p]));

/** خيارات طلبات المشترك عند التسجيل — المعرف للبرمجة، النص للعرض */
const SIGNUP_SERVICE_OPTIONS = [
  { id: 'campaigns', labelAr: 'المشاركة في الحملات والفرص التسويقية' },
  { id: 'brand_collab', labelAr: 'تعاون مع علامات تجارية' },
  { id: 'reviews', labelAr: 'مراجعات وتجارب منتجات' },
  { id: 'events', labelAr: 'فعاليات وزيارات' },
  { id: 'consulting', labelAr: 'استشارة أو خدمة مخصّصة' },
  { id: 'followers_pack', labelAr: 'المتابعات (Followers) — إنستغرام' },
  { id: 'likes_pack', labelAr: 'الإعجابات (Likes) — إنستغرام' },
  { id: 'comments_pack', labelAr: 'التعليقات (Comments) — إنستغرام' },
  { id: 'mentions_pack', labelAr: 'المنشن (Mentions) — إنستغرام' },
  { id: 'views_pack', labelAr: 'المشاهدات (Views) — إنستغرام' },
  { id: 'tw_followers_premium', labelAr: 'متابعين تويتر' },
  { id: 'tw_followers_global', labelAr: 'متابعين (عالمي) — تويتر' },
  { id: 'tw_retweet', labelAr: 'رتويت (Retweet) — تويتر' },
  { id: 'tw_likes', labelAr: 'لايكات (Likes) — تويتر' },
  { id: 'tw_views', labelAr: 'المشاهدات (Views) — تويتر' },
  { id: 'tt_followers', labelAr: 'المتابعات (Followers) — تيك توك' },
  { id: 'tt_likes', labelAr: 'إعجابات الفيديو (Likes) — تيك توك' },
  { id: 'tt_views', labelAr: 'المشاهدات (Views) — تيك توك' },
  { id: 'tt_comments', labelAr: 'التعليقات (Comments) — تيك توك' },
  { id: 'tt_shares', labelAr: 'المشاركة (Shares) — تيك توك' },
  { id: 'tt_saves', labelAr: 'حفظ الفيديو (Saves) — تيك توك' },
  { id: 'snap_followers_world', labelAr: 'متابعين (عالمي) — سناب شات' },
  { id: 'snap_followers_gulf', labelAr: 'متابعين (خليجي/سعودي) — سناب شات' },
  { id: 'snap_story_views', labelAr: 'مشاهدات ستوري (Story) — سناب شات' },
  { id: 'snap_spotlight_views', labelAr: 'مشاهدات منصة الأضواء (Spotlight) — سناب شات' },
  { id: 'snap_screenshots', labelAr: 'سكرين شوت — سناب شات' },
  { id: 'snap_score_boost', labelAr: 'رفع سكور الحساب — سناب شات' },
  { id: 'other', labelAr: 'أخرى (اذكرها في النص)' },
];
const SIGNUP_SERVICE_ID_SET = new Set(SIGNUP_SERVICE_OPTIONS.map((x) => x.id));
const SIGNUP_SERVICE_LABEL_BY_ID = Object.assign(
  Object.fromEntries(SIGNUP_SERVICE_OPTIONS.map((x) => [x.id, x.labelAr])),
  {
    ig_followers_world: 'متابعين (عالمي) — إنستغرام (سجل قديم)',
    ig_followers_gulf: 'متابعين (خليجي/سعودي) — إنستغرام (سجل قديم)',
    ig_story_views: 'مشاهدات ستوري (Story) — إنستغرام (سجل قديم)',
    ig_spotlight_views: 'مشاهدات الأضواء (Spotlight) — إنستغرام (سجل قديم)',
    ig_screenshots: 'سكبرين شوت — إنستغرام (سجل قديم)',
    ig_score_boost: 'رفع سكور الحساب — إنستغرام (سجل قديم)',
  }
);

/** إرشادات تسعير تقريبية للعرض مع خيارات الطلب — السعر النهائي بالاتفاق */
const SIGNUP_SERVICE_PRICING_HINT_AR = {
  followers_pack:
    'جدول المنصة: سعر الألف 1.85 ر.س؛ الحد 20–500,000؛ نقاط مقترحة ⌈كمية÷2⌉؛ مدة تنفيذ تقريبية 1–24 ساعة.',
  likes_pack:
    'سعر الألف 1.85 ر.س؛ الحد 20–100,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 5 دقائق–3 ساعات.',
  comments_pack:
    'سعر الألف 4.50 ر.س؛ الحد 5–10,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 1–12 ساعة.',
  mentions_pack:
    'سعر الألف 9.38 ر.س؛ الحد 100–50,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 12–48 ساعة.',
  views_pack:
    'سعر الألف 0.19 ر.س؛ الحد 100–10,000,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية فوري–ساعة واحدة.',
  tw_followers_premium:
    'جدول تويتر/إكس: سعر الألف 79 ر.س؛ الحد 100–50,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 24–72 ساعة.',
  tw_followers_global:
    'سعر الألف 15 ر.س؛ الحد 100–200,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 12–48 ساعة.',
  tw_retweet:
    'سعر الألف 35 ر.س؛ الحد 50–20,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 1–6 ساعات.',
  tw_likes:
    'سعر الألف 19 ر.س؛ الحد 50–50,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 30 دقيقة–3 ساعات.',
  tw_views:
    'سعر الألف 0.99 ر.س؛ الحد 1,000–1,000,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية فوري–ساعة واحدة.',
  tt_followers:
    'جدول تيك توك: سعر الألف 3.38 ر.س؛ الحد 100–2,000,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 12–48 ساعة.',
  tt_likes:
    'سعر الألف 1.15 ر.س؛ الحد 50–500,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 30 دقيقة–6 ساعات.',
  tt_views:
    'سعر الألف 0.04 ر.س؛ الحد 500–100,000,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية فوري (دقائق).',
  tt_comments:
    'سعر الألف 5.60 ر.س؛ الحد 5–20,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 2–12 ساعة.',
  tt_shares:
    'سعر الألف 0.35 ر.س؛ الحد 100–1,000,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية فوري–ساعتان.',
  tt_saves:
    'سعر الألف 0.30 ر.س؛ الحد 100–500,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية فوري–ساعة واحدة.',
  snap_followers_world:
    'جدول سناب شات: سعر الألف 25 ر.س؛ الحد 100–50,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 2–5 أيام.',
  snap_followers_gulf:
    'سعر الألف 120 ر.س؛ الحد 100–10,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 3–7 أيام.',
  snap_story_views:
    'سعر الألف 15 ر.س؛ الحد 500–100,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 1–12 ساعة.',
  snap_spotlight_views:
    'سعر الألف 3.50 ر.س؛ الحد 1,000–1,000,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية فوري–ساعتان.',
  snap_screenshots:
    'سعر الألف 18.75 ر.س؛ الحد 10–5,000؛ نقاط ⌈كمية÷2⌉؛ مدة تقريبية 6–24 ساعة.',
  snap_score_boost:
    'سعر الألف 37.50 ر.س؛ الحد 1,000–1,000,000؛ نقاط ⌈كمية÷2⌉؛ مدة التنفيذ تقريبًا حسب الكمية.',
  consulting: 'يُقتَرح عرض سعر أو جلسة بعد مراجعة الطلب من الفريق.',
  brand_collab: 'يختلف حسب العلامة ونطاق التعاون؛ وضّح نوع المحتوى والمدة في الوصف.',
  reviews: 'غالباً يشمل استلام منتج أو زيارة؛ اذكر ما إن كان لديك منتج محدد.',
  events: 'يُسعَّر حسب نوع الفعالية والحضور؛ اذكر التاريخ والمدينة إن أمكن.',
};

/**
 * إنستغرام — سعر لكل 1000 وحدة (ريال سعودي)، حدود الكمية، مدة تنفيذ تقريبية.
 * نقاط الاستبدال المقترحة للعميل: ⌈الكمية ÷ 2⌉ (مثال 20 متابعًا → 10 نقاط).
 */
const INSTAGRAM_QTY_PRICING_BY_SERVICE_ID = {
  followers_pack: {
    pricePer1000: 1.85,
    minQty: 20,
    maxQty: 500_000,
    durationHintAr: 'تقريبًا 1 - 24 ساعة',
  },
  likes_pack: {
    pricePer1000: 1.85,
    minQty: 20,
    maxQty: 100_000,
    durationHintAr: 'تقريبًا 5 دقائق - 3 ساعات',
  },
  comments_pack: {
    pricePer1000: 4.5,
    minQty: 5,
    maxQty: 10_000,
    durationHintAr: 'تقريبًا 1 - 12 ساعة',
  },
  mentions_pack: {
    pricePer1000: 9.38,
    minQty: 100,
    maxQty: 50_000,
    durationHintAr: 'تقريبًا 12 - 48 ساعة',
  },
  views_pack: {
    pricePer1000: 0.19,
    minQty: 100,
    maxQty: 10_000_000,
    durationHintAr: 'تقريبًا فوري - ساعة واحدة',
  },
};

/**
 * تويتر / إكس — سعر لكل 1000 وحدة (ريال)، حدود الكمية، مدة تنفيذ تقريبية.
 * نقاط مقترحة للاستبدال: ⌈الكمية ÷ 2⌉ (نفس صيغة العرض مع الفريق).
 */
const TWITTER_QTY_PRICING_BY_SERVICE_ID = {
  tw_followers_premium: {
    pricePer1000: 79,
    minQty: 100,
    maxQty: 50_000,
    durationHintAr: 'تقريبًا 24 - 72 ساعة',
  },
  tw_followers_global: {
    pricePer1000: 15,
    minQty: 100,
    maxQty: 200_000,
    durationHintAr: 'تقريبًا 12 - 48 ساعة',
  },
  tw_retweet: {
    pricePer1000: 35,
    minQty: 50,
    maxQty: 20_000,
    durationHintAr: 'تقريبًا 1 - 6 ساعات',
  },
  tw_likes: {
    pricePer1000: 19,
    minQty: 50,
    maxQty: 50_000,
    durationHintAr: 'تقريبًا 30 دقيقة - 3 ساعات',
  },
  tw_views: {
    pricePer1000: 0.99,
    minQty: 1000,
    maxQty: 1_000_000,
    durationHintAr: 'تقريبًا فوري - ساعة واحدة',
  },
};

/**
 * تيك توك — سعر لكل 1000 وحدة (ريال)، حدود الكمية، مدة تنفيذ تقريبية.
 */
const TIKTOK_QTY_PRICING_BY_SERVICE_ID = {
  tt_followers: {
    pricePer1000: 3.38,
    minQty: 100,
    maxQty: 2_000_000,
    durationHintAr: 'تقريبًا 12 - 48 ساعة',
  },
  tt_likes: {
    pricePer1000: 1.15,
    minQty: 50,
    maxQty: 500_000,
    durationHintAr: 'تقريبًا 30 دقيقة - 6 ساعات',
  },
  tt_views: {
    pricePer1000: 0.04,
    minQty: 500,
    maxQty: 100_000_000,
    durationHintAr: 'تقريبًا فوري (دقائق)',
  },
  tt_comments: {
    pricePer1000: 5.6,
    minQty: 5,
    maxQty: 20_000,
    durationHintAr: 'تقريبًا 2 - 12 ساعة',
  },
  tt_shares: {
    pricePer1000: 0.35,
    minQty: 100,
    maxQty: 1_000_000,
    durationHintAr: 'تقريبًا فوري - ساعتان',
  },
  tt_saves: {
    pricePer1000: 0.3,
    minQty: 100,
    maxQty: 500_000,
    durationHintAr: 'تقريبًا فوري - ساعة واحدة',
  },
};

/**
 * سناب شات — سعر لكل 1000 وحدة (ريال)، حدود الكمية، مدة تنفيذ تقريبية.
 */
const SNAPCHAT_QTY_PRICING_BY_SERVICE_ID = {
  snap_followers_world: {
    pricePer1000: 25,
    minQty: 100,
    maxQty: 50_000,
    durationHintAr: 'تقريبًا 2 - 5 أيام',
  },
  snap_followers_gulf: {
    pricePer1000: 120,
    minQty: 100,
    maxQty: 10_000,
    durationHintAr: 'تقريبًا 3 - 7 أيام',
  },
  snap_story_views: {
    pricePer1000: 15,
    minQty: 500,
    maxQty: 100_000,
    durationHintAr: 'تقريبًا 1 - 12 ساعة',
  },
  snap_spotlight_views: {
    pricePer1000: 3.5,
    minQty: 1000,
    maxQty: 1_000_000,
    durationHintAr: 'تقريبًا فوري - ساعتان',
  },
  snap_screenshots: {
    pricePer1000: 18.75,
    minQty: 10,
    maxQty: 5_000,
    durationHintAr: 'تقريبًا 6 - 24 ساعة',
  },
  snap_score_boost: {
    pricePer1000: 37.5,
    minQty: 1000,
    maxQty: 1_000_000,
    durationHintAr: 'تقريبًا حسب الكمية',
  },
};

function qtyPricingRowForServiceId(serviceId) {
  return (
    INSTAGRAM_QTY_PRICING_BY_SERVICE_ID[serviceId] ||
    TWITTER_QTY_PRICING_BY_SERVICE_ID[serviceId] ||
    TIKTOK_QTY_PRICING_BY_SERVICE_ID[serviceId] ||
    SNAPCHAT_QTY_PRICING_BY_SERVICE_ID[serviceId] ||
    null
  );
}

function qtyPricingPlatformIdForServiceId(serviceId) {
  if (INSTAGRAM_QTY_PRICING_BY_SERVICE_ID[serviceId]) return 'instagram';
  if (TWITTER_QTY_PRICING_BY_SERVICE_ID[serviceId]) return 'twitter';
  if (TIKTOK_QTY_PRICING_BY_SERVICE_ID[serviceId]) return 'tiktok';
  if (SNAPCHAT_QTY_PRICING_BY_SERVICE_ID[serviceId]) return 'snapchat';
  const id = String(serviceId ?? '').trim();
  if (id.startsWith('tw_')) return 'twitter';
  if (id.startsWith('ig_')) return 'instagram';
  if (id.startsWith('tt_')) return 'tiktok';
  if (id.startsWith('snap_')) return 'snapchat';
  return null;
}

function serviceRequestOptionPayload(o) {
  const row = qtyPricingRowForServiceId(o.id);
  const platformId = qtyPricingPlatformIdForServiceId(o.id);
  const base = {
    ...o,
    pricingHintAr: SIGNUP_SERVICE_PRICING_HINT_AR[o.id] || '',
  };
  /** لتجميع العرض في «حسابي» و«طلب الخدمة» تحت أيقونة المنصة */
  const platformGroup = platformId || 'general';
  const platformGroupLabelAr = platformId
    ? PLATFORM_META_BY_ID[platformId]?.labelAr || platformId
    : 'خدمات عامة';
  if (!row || !platformId) {
    return { ...base, platformGroup, platformGroupLabelAr, quantityPricing: null };
  }
  const platformLabelAr = PLATFORM_META_BY_ID[platformId]?.labelAr || platformId;
  return {
    ...base,
    platformGroup,
    platformGroupLabelAr,
    quantityPricing: {
      platform: platformId,
      platformLabelAr,
      pricePer1000: row.pricePer1000,
      minQty: row.minQty,
      maxQty: row.maxQty,
      durationHintAr: row.durationHintAr,
      pointsFormulaAr: '⌈الكمية ÷ 2⌉ (مثال: 20 → 10 نقاط)',
      sarFormulaAr: '(الكمية ÷ 1000) × سعر الألف (ريال)',
    },
  };
}

/** null = لا تقييد (كل الخدمات المعرفة في SIGNUP_SERVICE_OPTIONS). لا يُعاد Set فارغ — يُعدّل كلا تقييداً */
async function getEnabledClientServiceIdFilterSet() {
  if (!MONGO_URI || mongoose.connection.readyState !== 1) return null;
  try {
    const doc = await SiteSettings.findById('main').select('enabledClientServiceIds').lean();
    const raw = doc?.enabledClientServiceIds;
    if (!Array.isArray(raw) || raw.length === 0) return null;
    const cleaned = raw
      .map((id) => String(id).trim().toLowerCase())
      .filter((id) => SIGNUP_SERVICE_ID_SET.has(id));
    if (!cleaned.length) return null;
    return new Set(cleaned);
  } catch {
    return null;
  }
}

const QTY_PRICING_NOTE_AR =
  'تقدير الكمية (إنستغرام أو تويتر/إكس أو تيك توك أو سناب شات حسب الخيار): السعر ≈ (الكمية÷1000)×سعر الألف بالجدول؛ نقاط مقترحة للاستبدال = ⌈الكمية÷2⌉ (لا يُخصم تلقائياً من الرصيد حتى يعتمدها الفريق).';

function normalizeServiceQuantitiesBody(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const [k, v] of Object.entries(raw)) {
    const sid = String(k).trim().toLowerCase();
    if (!SIGNUP_SERVICE_ID_SET.has(sid)) continue;
    if (v == null || String(v).trim() === '') continue;
    const n = Math.floor(Number(v));
    if (!Number.isFinite(n)) continue;
    out[sid] = n;
  }
  return out;
}

/**
 * @param {string} serviceId
 * @param {unknown} rawQty
 * @returns {{ ok: true, serviceId: string, labelAr: string, quantity: number, priceSar: number, pointsRequired: number, durationHintAr: string } | { ok: false, error: string }}
 */
function estimateQtyPricedServiceLine(serviceId, rawQty) {
  const row = qtyPricingRowForServiceId(serviceId);
  if (!row) return { ok: false, error: 'غير مدرج في جدول الكمية' };
  const q = Math.floor(Number(rawQty));
  if (!Number.isFinite(q)) return { ok: false, error: 'كمية غير صالحة' };
  if (q < row.minQty || q > row.maxQty) {
    return {
      ok: false,
      error: `الكمية يجب بين ${row.minQty} و ${row.maxQty.toLocaleString('en-US')}`,
    };
  }
  const priceRaw = (q / 1000) * row.pricePer1000;
  const priceSar = Math.round(priceRaw * 100) / 100;
  const pointsRequired = Math.ceil(q / 2);
  return {
    ok: true,
    serviceId,
    labelAr: SIGNUP_SERVICE_LABEL_BY_ID[serviceId] || serviceId,
    quantity: q,
    priceSar,
    pointsRequired,
    durationHintAr: row.durationHintAr,
  };
}

/**
 * @param {string[]} requestedServices
 * @param {Record<string, number>} serviceQuantities
 */
function buildQtyPricingForRequest(requestedServices, serviceQuantities) {
  const lines = [];
  const qtyIds = requestedServices.filter((id) => qtyPricingRowForServiceId(id));
  for (const sid of qtyIds) {
    if (!(sid in serviceQuantities)) {
      return {
        ok: false,
        error: `أدخل حقل الكمية لخدمة «${SIGNUP_SERVICE_LABEL_BY_ID[sid] || sid}» (جدول الكمية حسب المنصة).`,
      };
    }
    const est = estimateQtyPricedServiceLine(sid, serviceQuantities[sid]);
    if (!est.ok) {
      return {
        ok: false,
        error: `${SIGNUP_SERVICE_LABEL_BY_ID[sid] || sid}: ${est.error}`,
      };
    }
    lines.push({
      serviceId: est.serviceId,
      labelAr: est.labelAr,
      quantity: est.quantity,
      priceSar: est.priceSar,
      pointsRequired: est.pointsRequired,
      durationHintAr: est.durationHintAr,
    });
  }
  if (!lines.length) {
    return { ok: true, lines: [], estimatedTotalSar: null, estimatedTotalPoints: null };
  }
  const estimatedTotalSar = Math.round(lines.reduce((s, x) => s + x.priceSar, 0) * 100) / 100;
  const estimatedTotalPoints = lines.reduce((s, x) => s + x.pointsRequired, 0);
  return { ok: true, lines, estimatedTotalSar, estimatedTotalPoints };
}

/** نقاط تُمنح لكل تسجيل تفاعل عندما لا يُحدَّد للحملة قيمة خاصة */
const POINTS_PER_INTERACTION = 10;

/**
 * @param {unknown} ppiIn
 * @returns {{ ok: true, value: number | null } | { ok: false, error: string }}
 */
function parsePointsPerInteractionInput(ppiIn) {
  if (ppiIn == null || String(ppiIn).trim() === '') {
    return { ok: true, value: null };
  }
  const pp = Math.floor(Number(ppiIn));
  if (!Number.isFinite(pp) || pp < 1 || pp > 100000) {
    return {
      ok: false,
      error: 'pointsPerInteraction يجب أن يكون عدداً صحيحاً بين 1 و 100000 أو فارغاً للاستخدام الافتراضي للمنصة',
    };
  }
  return { ok: true, value: pp };
}

/** نقاط مكلَّفة بهذه الحملة عند كل مشاركة مسجّلة (1–100000)؛ خلاف ذلك المنصة الافتراضية أعلاه */
function effectiveCampaignPoints(campaign) {
  if (!campaign || campaign.pointsPerInteraction == null) return POINTS_PER_INTERACTION;
  const n = Math.floor(Number(campaign.pointsPerInteraction));
  if (!Number.isFinite(n) || n < 1 || n > 100000) return POINTS_PER_INTERACTION;
  return n;
}

/** نقاط مُسجَّلة مع التفاعل (أو الافتراضي القديم للصفوف قبل الإصدارات التي تحفظ pointsAwarded) */
function interactionPointsStored(row) {
  const stored = row.pointsAwarded;
  if (stored != null && Number.isFinite(Number(stored))) return Math.floor(Number(stored));
  return POINTS_PER_INTERACTION;
}

const siteSettingsSchema = new mongoose.Schema(
  {
    _id: { type: String, default: 'main' },
    enabledPlatforms: [{ type: String }],
    /** مسار عام للشعار، مثل /uploads/branding/logo-xxx.png */
    platformLogoUrl: { type: String, trim: true, default: '' },
    /** عنوان البطل في /join — نص عادي فقط */
    joinHeroTitle: { type: String, trim: true, default: '' },
    /** وصف تحت العنوان في /join — يسمح بوسوم HTML بسيطة بعد التصفية على الخادم */
    joinHeroLeadHtml: { type: String, trim: true, default: '' },
    /** المربع الجانبي بجانب البطل في /join (HTML مُصفّى) — من لوحة الفريق */
    joinHeroAsideHtml: { type: String, trim: true, default: '' },
    /** عنوان قسم «لماذا تنضم» في /join */
    joinWhyHeading: { type: String, trim: true, default: '' },
    joinWhyCard1Title: { type: String, trim: true, default: '' },
    joinWhyCard1Html: { type: String, trim: true, default: '' },
    joinWhyCard2Title: { type: String, trim: true, default: '' },
    joinWhyCard2Html: { type: String, trim: true, default: '' },
    joinWhyCard3Title: { type: String, trim: true, default: '' },
    joinWhyCard3Html: { type: String, trim: true, default: '' },
    /** قسم الخطوات الثلاث */
    joinStepsHeading: { type: String, trim: true, default: '' },
    joinStep1Title: { type: String, trim: true, default: '' },
    joinStep1Html: { type: String, trim: true, default: '' },
    joinStep2Title: { type: String, trim: true, default: '' },
    joinStep2Html: { type: String, trim: true, default: '' },
    joinStep3Title: { type: String, trim: true, default: '' },
    joinStep3Html: { type: String, trim: true, default: '' },
    /** عنوان ومقدمة نموذج الاشتراك */
    joinSubscribeHeading: { type: String, trim: true, default: '' },
    joinSubscribeIntroHtml: { type: String, trim: true, default: '' },
    /** صفحة دخول المشترك — عنوان البطل */
    subscriberHeroTitle: { type: String, trim: true, default: '' },
    subscriberHeroLeadHtml: { type: String, trim: true, default: '' },
    /** شريط أحمر ثابت أسفل كل صفحات العملاء — HTML مُصفّى */
    globalBannerHtml: { type: String, trim: true, default: '' },
    /**
     * إن وُجدت كمصفوفة: يُعرَض للعميل في «طلب الخدمة» و«حسابي» فقط هذه المعرفات (من SIGNUP_SERVICE_OPTIONS).
     * غير موجودة أو null = كل الخدمات المعرفة (سلوك افتراضي قديم).
     */
    enabledClientServiceIds: [{ type: String, trim: true }],
  },
  { collection: 'sitesettings' }
);
const SiteSettings = mongoose.model('SiteSettings', siteSettingsSchema);

function sanitizeJoinHeroTitle(raw) {
  return String(raw ?? '')
    .replace(/\r\n/g, ' ')
    .replace(/[<>`]/g, '')
    .trim()
    .slice(0, 280);
}

function sanitizeJoinHeroLeadHtml(raw) {
  let s = String(raw ?? '').replace(/\r\n/g, '\n').trim().slice(0, 4000);
  s = s.replace(/<\/(?:script|iframe|object)[^>]*>/gi, '');
  s = s.replace(/<(?:script|iframe|object)[^>]*>[\s\S]*?<\/(?:script|iframe|object)>/gi, '');
  s = s.replace(/<\s*\/?\s*(script|iframe|object)\b[^>]*>/gi, '');
  s = s.replace(/\son\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');
  s = s.replace(/javascript:/gi, '');
  return s.trim().slice(0, 4000);
}

function pickTrimmedSiteString(doc, key) {
  const v = doc?.[key];
  return v != null && String(v).trim() ? String(v).trim() : '';
}

function sanitizeGlobalBannerHtml(raw) {
  let s = String(raw ?? '').replace(/\r\n/g, '\n').trim().slice(0, 3500);
  s = s.replace(/<\/(?:script|iframe|object)[^>]*>/gi, '');
  s = s.replace(/<(?:script|iframe|object)[^>]*>[\s\S]*?<\/(?:script|iframe|object)>/gi, '');
  s = s.replace(/<\s*\/?\s*(script|iframe|object)\b[^>]*>/gi, '');
  s = s.replace(/\son\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');
  s = s.replace(/javascript:/gi, '');
  return s.trim().slice(0, 3500);
}

async function getJoinPlatformSettings() {
  const doc = await SiteSettings.findById('main').lean();
  let enabled = Array.isArray(doc?.enabledPlatforms) ? doc.enabledPlatforms.filter((id) => PLATFORM_ID_SET.has(id)) : [];
  if (!enabled.length) enabled = ['instagram'];
  const platforms = enabled.map((id) => ({
    id,
    labelAr: PLATFORM_META_BY_ID[id]?.labelAr || id,
  }));
  const platformLogoUrl =
    doc?.platformLogoUrl && String(doc.platformLogoUrl).trim() ? String(doc.platformLogoUrl).trim() : '';
  const joinHeroTitle =
    doc?.joinHeroTitle != null && String(doc.joinHeroTitle).trim() ? String(doc.joinHeroTitle).trim() : '';
  const joinHeroLeadHtml =
    doc?.joinHeroLeadHtml != null && String(doc.joinHeroLeadHtml).trim() ? String(doc.joinHeroLeadHtml).trim() : '';
  const joinHeroAsideHtml = pickTrimmedSiteString(doc, 'joinHeroAsideHtml');
  const joinWhyHeading = pickTrimmedSiteString(doc, 'joinWhyHeading');
  const joinWhyCard1Title = pickTrimmedSiteString(doc, 'joinWhyCard1Title');
  const joinWhyCard1Html = pickTrimmedSiteString(doc, 'joinWhyCard1Html');
  const joinWhyCard2Title = pickTrimmedSiteString(doc, 'joinWhyCard2Title');
  const joinWhyCard2Html = pickTrimmedSiteString(doc, 'joinWhyCard2Html');
  const joinWhyCard3Title = pickTrimmedSiteString(doc, 'joinWhyCard3Title');
  const joinWhyCard3Html = pickTrimmedSiteString(doc, 'joinWhyCard3Html');
  const joinStepsHeading = pickTrimmedSiteString(doc, 'joinStepsHeading');
  const joinStep1Title = pickTrimmedSiteString(doc, 'joinStep1Title');
  const joinStep1Html = pickTrimmedSiteString(doc, 'joinStep1Html');
  const joinStep2Title = pickTrimmedSiteString(doc, 'joinStep2Title');
  const joinStep2Html = pickTrimmedSiteString(doc, 'joinStep2Html');
  const joinStep3Title = pickTrimmedSiteString(doc, 'joinStep3Title');
  const joinStep3Html = pickTrimmedSiteString(doc, 'joinStep3Html');
  const joinSubscribeHeading = pickTrimmedSiteString(doc, 'joinSubscribeHeading');
  const joinSubscribeIntroHtml = pickTrimmedSiteString(doc, 'joinSubscribeIntroHtml');
  return {
    enabledPlatformIds: enabled,
    platforms,
    platformLogoUrl,
    joinHeroTitle,
    joinHeroLeadHtml,
    joinHeroAsideHtml,
    joinWhyHeading,
    joinWhyCard1Title,
    joinWhyCard1Html,
    joinWhyCard2Title,
    joinWhyCard2Html,
    joinWhyCard3Title,
    joinWhyCard3Html,
    joinStepsHeading,
    joinStep1Title,
    joinStep1Html,
    joinStep2Title,
    joinStep2Html,
    joinStep3Title,
    joinStep3Html,
    joinSubscribeHeading,
    joinSubscribeIntroHtml,
  };
}

async function getSubscriberPortalSettings() {
  const doc = await SiteSettings.findById('main').lean();
  return {
    subscriberHeroTitle: pickTrimmedSiteString(doc, 'subscriberHeroTitle'),
    subscriberHeroLeadHtml: pickTrimmedSiteString(doc, 'subscriberHeroLeadHtml'),
  };
}

async function getGlobalBannerSettings() {
  const doc = await SiteSettings.findById('main').lean();
  return {
    globalBannerHtml: pickTrimmedSiteString(doc, 'globalBannerHtml'),
  };
}

async function ensureSiteSettingsDoc() {
  const defaults = [...PLATFORM_IDS];
  await SiteSettings.updateOne(
    { _id: 'main' },
    { $setOnInsert: { enabledPlatforms: defaults } },
    { upsert: true }
  );
}

function profileUrlForPlatform(platformId, handle) {
  const pid = PLATFORM_ID_SET.has(platformId) ? platformId : 'instagram';
  const h = String(handle || '').trim();
  if (!h) return '';
  const meta = PLATFORM_META_BY_ID[pid];
  return meta ? meta.profileUrl(h) : '';
}

/** رابط يفتحه المشارك لتنفيذ المتابعة/التفاعل — الرابط المحفوظ للحملة أولاً ثم حساب targetUserId */
function portalParticipationOpenUrlFromCampaign(c) {
  const L = String(c.link || '').trim();
  if (/^https?:\/\//i.test(L)) return L;
  const tu = c.targetUserId;
  if (!tu) return '';
  if (tu instanceof mongoose.Types.ObjectId) return '';
  if (typeof tu === 'string' && mongoose.isValidObjectId(tu)) return '';
  const h = String(tu.instagramUsername || '').trim();
  if (!h) return '';
  return profileUrlForPlatform(tu.socialPlatform || 'instagram', h) || '';
}

/** رابط المشاركة مع تتبّع ضغطة عبر /go (نفس وجهة المنشور). لا يُسجِّل الإعجاب تلقائياً على المنصة. */
function participationTrackedPortalHref(req, campaignDoc, subscriberUserId) {
  const dest = portalParticipationOpenUrlFromCampaign(campaignDoc);
  if (!dest || !/^https?:\/\//i.test(dest)) return dest || '';
  const cid = String(campaignDoc._id || '');
  const uid = String(subscriberUserId || '');
  if (!mongoose.isValidObjectId(cid) || !mongoose.isValidObjectId(uid)) return dest;
  const base = resolvedPublicBaseUrl(req).replace(/\/+$/, '');
  return `${base}/go?c=${encodeURIComponent(cid)}&u=${encodeURIComponent(uid)}`;
}

function portalCompletionNoteArForCampaignType(type) {
  const k = String(type || '').trim();
  if (k === 'like') {
    return 'إنستغرام وغيرها لا تُخطر موقعنا بالإعجاب. افتح المنشور من الزر، اعجب من تطبيق المنصة، ثم عد واضغط «تسجيل مشاركتي».';
  }
  if (k === 'follow') {
    return 'المتابعة تتم من تطبيق المنصة؛ عد ثم سجّل مشاركتك من هذه الصفحة.';
  }
  if (k === 'comment') {
    return 'التعليق على المنصة لا يظهر هنا تلقائياً. علّق من التطبيق ثم سجّل مشاركتك (وكود التحقق إن وُجد).';
  }
  if (k === 'visit') {
    return 'قد يُسجَّل للفريق ضغطة الرابط فقط، وليس إثبات كل خطوة داخل الموقع.';
  }
  return 'نفّذ المطلوب على المنصة أو الرابط، ثم عد لتسجيل المشاركة من هنا.';
}

function portalCampaignTargetSubscriberHint(tu) {
  if (!tu) return '';
  if (tu instanceof mongoose.Types.ObjectId) return '';
  if (typeof tu === 'string' && mongoose.isValidObjectId(tu)) return '';
  const name = String(tu.name || '').trim();
  const h = String(tu.instagramUsername || '').trim();
  const plat = PLATFORM_META_BY_ID[tu.socialPlatform || 'instagram']?.labelAr || '';
  if (name && h) return `${name} — ${plat}: @${h}`;
  if (name) return name;
  if (h) return `${plat ? `${plat}: ` : ''}@${h}`;
  return '';
}

if (MONGO_URI) {
  mongoose
    .connect(MONGO_URI, {
      serverSelectionTimeoutMS: 20_000,
      family: 4,
    })
    .then(async () => {
      console.log('[OK] MongoDB connected');
      try {
        await User.collection.dropIndex('instagramUsername_1');
        console.log('[OK] Legacy users index instagramUsername_1 removed (if it existed)');
      } catch (e) {
        const msg = String(e?.message || e);
        if (!/not found|ns not found/i.test(msg)) {
          console.warn('[WARN] Legacy index drop:', msg);
        }
      }
      try {
        await User.collection.dropIndex('socialPlatform_1_instagramUsername_1');
        console.log('[OK] Removed socialPlatform+instagramUsername index (will recreate as partial unique)');
      } catch (e) {
        const msg = String(e?.message || e);
        if (!/not found|ns not found/i.test(msg)) {
          console.warn('[WARN] Compound index drop:', msg);
        }
      }
      try {
        await User.syncIndexes();
      } catch (e) {
        console.warn('[WARN] User.syncIndexes:', e.message);
      }
      try {
        const needsPortal = await User.find({
          $or: [{ portalToken: { $exists: false } }, { portalToken: null }, { portalToken: '' }],
        })
          .select('_id')
          .lean();
        let portalN = 0;
        for (const row of needsPortal) {
          await User.updateOne({ _id: row._id }, { $set: { portalToken: crypto.randomBytes(32).toString('hex') } });
          portalN++;
        }
        if (portalN > 0) {
          console.log(`[OK] Assigned portal tokens for ${portalN} user(s)`);
        }
      } catch (e) {
        console.warn('[WARN] Portal token backfill:', e.message);
      }
      try {
        const mig = await User.updateMany({ socialPlatform: { $exists: false } }, { $set: { socialPlatform: 'instagram' } });
        if (mig.modifiedCount > 0) {
          console.log(`[OK] Backfilled socialPlatform for ${mig.modifiedCount} user(s)`);
        }
      } catch (e) {
        console.warn('[WARN] User platform backfill:', e.message);
      }
      try {
        await ensureSiteSettingsDoc();
      } catch (e) {
        console.warn('[WARN] SiteSettings seed:', e.message);
      }
      try {
        await Campaign.syncIndexes();
      } catch (e) {
        console.warn('[WARN] Campaign.syncIndexes:', e.message);
      }
      try {
        const needsCampTok = await Campaign.find({
          $or: [
            { campaignPortalToken: { $exists: false } },
            { campaignPortalToken: null },
            { campaignPortalToken: '' },
          ],
        })
          .select('_id')
          .lean();
        let cn = 0;
        for (const row of needsCampTok) {
          await Campaign.updateOne(
            { _id: row._id },
            { $set: { campaignPortalToken: crypto.randomBytes(32).toString('hex') } }
          );
          cn++;
        }
        if (cn > 0) {
          console.log(`[OK] Assigned campaign track tokens for ${cn} campaign(s)`);
        }
      } catch (e) {
        console.warn('[WARN] Campaign portal token backfill:', e.message);
      }
    })
    .catch((err) => {
      console.error('[ERR] MongoDB:', err.message);
      if (/querySrv|ECONNREFUSED|ENOTFOUND/i.test(String(err.message))) {
        console.error(
          '[HINT] If you see querySrv/ECONNREFUSED: (1) Try another network/VPN off (2) Set DNS to 8.8.8.8 (3) In Atlas Connect → Drivers turn OFF “SRV” and paste the standard mongodb://... URI into MONGO_URI'
        );
      }
    });
} else {
  console.warn('[WARN] MONGO_URI is empty — set it in .env and restart');
}

const userSchema = new mongoose.Schema(
  {
    name: String,
    city: { type: String, required: true },
    interests: [String],
    fcmToken: String,
    points: { type: Number, default: 0 },
    /** المنصة التي أُدخل عليها اسم المستخدم (اليوزر يُخزَّن في instagramUsername لتوافق سابق) */
    socialPlatform: { type: String, enum: PLATFORM_IDS, default: 'instagram' },
    /** اسم المستخدم على المنصة المختارة (اسم الحقل تاريخي من إنستغرام) */
    instagramUsername: { type: String, trim: true, lowercase: true },
    phone: { type: String, trim: true },
    gender: { type: String, enum: ['male', 'female', 'unspecified'], default: 'unspecified' },
    instagramVerified: { type: Boolean, default: false },
    phoneVerified: { type: Boolean, default: false },
    /** رمز سري لصفحة «حسابي» — لا يُشارك علناً */
    portalToken: { type: String, trim: true, sparse: true, unique: true },
    /** أنواع الخدمات التي اختارها المشترك عند التسجيل (معرفات من SIGNUP_SERVICE_OPTIONS) */
    requestedServices: [{ type: String, trim: true }],
    /** نص حر: طلبات، توضيح، نوع التعاون المطلوب */
    signupNotes: { type: String, trim: true, default: '' },
  },
  { timestamps: true }
);
userSchema.index(
  { socialPlatform: 1, instagramUsername: 1 },
  {
    unique: true,
    partialFilterExpression: {
      instagramUsername: { $exists: true, $gt: '' },
    },
  }
);
userSchema.index({ phone: 1 }, { unique: true, sparse: true });
const User = mongoose.model('User', userSchema);

/** ذاكرة مؤقتة لرمز جوال (التطوير فقط — الإنتاج يستبدل ببوابة SMS) */
const phoneOtpPending = new Map();
/** دخول «حسابي» بالجوال — المفتاح رقم الجوال المطبَّع */
const portalLoginOtpByPhone = new Map();

function randomOtp6() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function csvEscapeCell(val) {
  if (val == null || val === '') return '';
  const s = String(val);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function escapeRegExp(str) {
  return String(str ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const campaignSchema = new mongoose.Schema({
  title: String,
  type: String,
  city: String,
  interest: String,
  targetCount: Number,
  currentCount: { type: Number, default: 0 },
  link: String,
  status: { type: String, default: 'active' },
  /** وجهة الحملة: سوشال أو موقع أو متجر */
  destinationKind: {
    type: String,
    enum: ['social', 'website', 'store', 'other'],
    default: 'social',
  },
  /** اسم موقع، متجر، أو ملاحظة قصيرة (اختياري) */
  destinationLabel: { type: String, trim: true, default: '' },
  /**
   * ملخص تجاري داخلي (اختياري): هل الحملة ضمن باقة مدفوعة لصاحب العلامة أم مجانية،
   * ونوع الباقة (زيارات، متابعين، …). لا يُعرض للمشترك — لتنسيق الفريق فقط.
   */
  dealSummary: { type: String, trim: true, default: '', maxlength: 280 },
  /**
   * تصنيف تجاري للتمييز في اللوحة ولصفحة تتبع العميل (لا يغني عن سجل الدفعات اليدوي).
   */
  billingKind: {
    type: String,
    enum: ['paid', 'free', 'unspecified'],
    default: 'unspecified',
  },
  /**
   * نقاط يمنحها الفريق للمشترك عن كل مشاركة موثّقة في هذه الحملة (فراغ أو غير صالح = المنصة الافتراضية).
   */
  pointsPerInteraction: { type: Number, default: null },
  /** رمز سري لصفحة تتبع صاحب الحملة — لا يُشارك علناً */
  campaignPortalToken: { type: String, trim: true, sparse: true, unique: true },
  /**
   * مشترك مرتبط بالحملة (مثلاً لمتابعته على منصته).
   * إن لم يُملأ «الرابط» بصيغة http صالحة يُعرَض للمشاركين زر يفتح حساب هذا المشترك تلقائياً.
   */
  targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  /** مرجع اختياري لصف «طلبات العملاء» — يُعرَض في صفحة تتبع الحملة لصاحب العلامة */
  linkedClientServiceRequestId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ClientServiceRequest',
    default: null,
  },
});
campaignSchema.index({ linkedClientServiceRequestId: 1 }, { sparse: true });
const Campaign = mongoose.model('Campaign', campaignSchema);

/** نص إرشاد للمشرف عند إصدار كود تحقق — يعتمد على نوع وجهة الحملة (سوشال، موقع، متجر…) */
function verificationInstructionForCampaign(campaign) {
  const kind = campaign?.destinationKind || 'social';
  const hasLink = !!(campaign?.link && String(campaign.link).trim());
  const linkNote = hasLink
    ? 'رابط الحملة المحفوظ يُستخدم مع مسار التتبع /go ثم التحويل لهذه الوجهة.'
    : 'يُفضَّل حفظ رابط الحملة عند الإنشاء فيظهر في الرد وفي روابط التتبع.';
  if (kind === 'website') {
    return `كود التحقق يربط هذا المشترك بهذه الحملة لأي رابط موقع. اطلب إرسال الكود عبر واتساب أو نموذج أو غيرهما، أو أدخله عندك عند تأكيد التفاعل يدوياً. لا يثبت النظام تلقائياً خطوات داخل الموقع بدون أدوات تحليلات خاصة بك. ${linkNote}`;
  }
  if (kind === 'store') {
    return `كود التحقق يربط المشترك بحملة المتجر. يمكن جمع الكود مع الطلب أو بعده أو مطابقته مع لقطة شاشة أو رسالة من العميل. ${linkNote}`;
  }
  if (kind === 'other') {
    return `استخدم الكود كمرجع لربط المشترك بالحملة عبر أي قناة تناسب عملك. ${linkNote}`;
  }
  return `كود التحقق صالح لأي رابط حملة على وسائل التواصل. يمكن طلب إرسال الكود أو نشره في تعليق للمطابقة اليدوية؛ على إنستغرام لا يصل إشعار برمجي بالتعليقات بدون Instagram Graph API. ${linkNote}`;
}

const interactionSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign', required: true },
    /** لقطعة ثابتة وقت التسجيل — لا تتغير إذا عدّلتم نقاط الحملة لاحقاً */
    pointsAwarded: { type: Number, default: null },
  },
  { timestamps: true }
);
interactionSchema.index({ userId: 1, campaignId: 1 }, { unique: true });
const Interaction = mongoose.model('Interaction', interactionSchema);

/** كود فريد لكل (مشترك + حملة) — مطابقة التفاعل الفعلي مع المنصات تحتاج واجهات المنصة أو مراجعة يدوية */
const campaignClaimSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign', required: true },
    code: { type: String, required: true, unique: true, uppercase: true, trim: true },
  },
  { timestamps: true }
);
campaignClaimSchema.index({ userId: 1, campaignId: 1 }, { unique: true });
const CampaignClaim = mongoose.model('CampaignClaim', campaignClaimSchema);

/** تسجيل ضغطات رابط الحملة قبل التحويل للوجهة */
const linkClickSchema = new mongoose.Schema(
  {
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign', required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    ip: { type: String, default: '' },
    userAgent: { type: String, default: '' },
  },
  { timestamps: true }
);
linkClickSchema.index({ campaignId: 1, createdAt: -1 });
linkClickSchema.index({ userId: 1, createdAt: -1 });
const LinkClick = mongoose.model('LinkClick', linkClickSchema);

/** مدفوعات مسجَّلة للمشترك (إدخال يدوي من لوحة الفريق — أو ربط بوابة دفع لاحقاً) */
const subscriberPaymentSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amountSar: { type: Number, required: true },
    label: { type: String, trim: true, default: '' },
    note: { type: String, trim: true, default: '' },
  },
  { timestamps: true }
);
subscriberPaymentSchema.index({ userId: 1, createdAt: -1 });
const SubscriberPayment = mongoose.model('SubscriberPayment', subscriberPaymentSchema);

/** إضافة نقاط للمشترك كمكافئة من الفريق — تُسجَّل في سجل «حسابي» */
const subscriberPointsGrantSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    points: { type: Number, required: true },
    /** يُعرَض للمشترك في سجل التحركات */
    note: { type: String, trim: true, default: '' },
  },
  { timestamps: true }
);
subscriberPointsGrantSchema.index({ userId: 1, createdAt: -1 });
const SubscriberPointsGrant = mongoose.model('SubscriberPointsGrant', subscriberPointsGrantSchema);

/**
 * مدفوعات من عميل الحملة / المعلن لفريق المنصة (تسجيل يدوي — لا تُعرض لمشترك «حسابي»)
 */
const advertiserPaymentSchema = new mongoose.Schema(
  {
    campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign', default: null },
    /** اسم العلامة أو المرجع التجاري */
    clientLabel: { type: String, trim: true, default: '' },
    amountSar: { type: Number, required: true },
    label: { type: String, trim: true, default: '' },
    note: { type: String, trim: true, default: '' },
  },
  { timestamps: true }
);
advertiserPaymentSchema.index({ campaignId: 1, createdAt: -1 });
advertiserPaymentSchema.index({ createdAt: -1 });
const AdvertiserPayment = mongoose.model('AdvertiserPayment', advertiserPaymentSchema);

/** طلب من عميل: خدمة مدفوعة و/أو نقاط — من صفحة منفصلة عن الاشتراك */
const clientServiceRequestSchema = new mongoose.Schema(
  {
    phone: { type: String, trim: true, required: true },
    name: { type: String, trim: true, default: '' },
    requestKind: {
      type: String,
      enum: ['paid_service', 'points', 'both', 'other'],
      default: 'other',
    },
    requestedServices: [{ type: String, trim: true }],
    /** كميات الخدمات العدّية (معرف الخدمة → عدد صحيح) — جداول إنستغرام وتويتر/إكس وتيك توك وسناب شات */
    serviceQuantities: { type: mongoose.Schema.Types.Mixed, default: {} },
    pricingEstimateLines: [
      {
        serviceId: { type: String, trim: true },
        labelAr: { type: String, trim: true, default: '' },
        quantity: { type: Number },
        priceSar: { type: Number },
        pointsRequired: { type: Number },
        durationHintAr: { type: String, trim: true, default: '' },
      },
    ],
    estimatedTotalSar: { type: Number, default: null },
    estimatedTotalPoints: { type: Number, default: null },
    pricingNoteAr: { type: String, trim: true, default: '' },
    /** عنوان مختصر يعرضه الفريق والعميل في السجل */
    title: { type: String, trim: true, default: '' },
    details: { type: String, trim: true, required: true },
    /** إن وُجد مطابق لرمز صفحة «حسابي» */
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    linkedViaPortal: { type: Boolean, default: false },
    /** تم التنفيذ / ملغاة / قيد المعالجة — يحدّثها الفريق من لوحة الطلبات */
    fulfillmentStatus: {
      type: String,
      enum: ['pending', 'completed', 'cancelled'],
      default: 'pending',
    },
  },
  { timestamps: true }
);
clientServiceRequestSchema.index({ createdAt: -1 });
clientServiceRequestSchema.index({ userId: 1, createdAt: -1 });
clientServiceRequestSchema.index({ phone: 1, createdAt: -1 });
const ClientServiceRequest = mongoose.model('ClientServiceRequest', clientServiceRequestSchema);

/** إخفاء جوال للعرض في بوابة العميل */
function maskSaudiPhoneLast4(phone) {
  const p = String(phone || '').replace(/\D/g, '');
  if (p.length < 4) return '···';
  return `···${p.slice(-4)}`;
}

async function createUserWithPortalToken(payload) {
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      return await User.create({
        ...payload,
        portalToken: crypto.randomBytes(32).toString('hex'),
      });
    } catch (err) {
      if (err.code === 11000 && err.keyPattern && err.keyPattern.portalToken) continue;
      throw err;
    }
  }
  throw new Error('تعذّر إنشاء رمز حساب العميل');
}

function makeVerificationCode() {
  return `RW-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

/** التحقق من معرّف طلب عميل قبل ربطه بحملة */
async function resolveLinkedClientServiceRequestId(rawId, targetUserIdOpt) {
  const s = rawId != null ? String(rawId).trim() : '';
  if (!s) return { ok: true, value: null };
  if (!mongoose.isValidObjectId(s)) {
    return { ok: false, error: 'معرّف طلب العميل المرتبط غير صالح' };
  }
  const csr = await ClientServiceRequest.findById(s).select('userId phone').lean();
  if (!csr) return { ok: false, error: 'طلب العميل المرجَع غير موجود' };
  if (targetUserIdOpt && mongoose.isValidObjectId(targetUserIdOpt)) {
    const tu = String(targetUserIdOpt);
    if (csr.userId && String(csr.userId) !== tu) {
      return { ok: false, error: 'طلب العميل المرتبط لا يخص المشترك المستهدَف في الحملة' };
    }
    if (!csr.userId) {
      const u = await User.findById(tu).select('phone').lean();
      const pn = String(u?.phone || '').trim();
      const crp = String(csr.phone || '').trim();
      if (pn && crp && pn !== crp) {
        return { ok: false, error: 'طلب العميل المرتبط لا يطابق جوال المشترك المستهدَف' };
      }
    }
  }
  return { ok: true, value: s };
}

async function createCampaignWithPortalToken(payload) {
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      return await Campaign.create({
        ...payload,
        campaignPortalToken: crypto.randomBytes(32).toString('hex'),
      });
    } catch (err) {
      if (err.code === 11000 && err.keyPattern && err.keyPattern.campaignPortalToken) continue;
      throw err;
    }
  }
  throw new Error('تعذّر إنشاء رمز تتبع الحملة');
}

/** تطبيع اسم مستخدم المنصة (بدون @، إنجليزي صغير) — قواعد إنستغرام أشد من باقي المنصات */
function normalizeSignupSocial(platform, raw) {
  const p = PLATFORM_ID_SET.has(platform) ? platform : 'instagram';
  const s = String(raw ?? '')
    .trim()
    .replace(/^@+/, '')
    .trim()
    .toLowerCase();
  if (!s) return { error: 'اسم المستخدم على المنصة مطلوب' };
  if (p === 'instagram') {
    if (!/^[a-z0-9._]{1,30}$/.test(s)) {
      return {
        error: 'يوزر إنستغرام غير صالح (أحرف إنجليزية وأرقام و _ و . فقط، حتى 30)',
      };
    }
  } else if (!/^[a-z0-9._-]{2,64}$/.test(s)) {
    return { error: 'اسم المستخدم غير صالح — استخدم أحرفاً إنجليزية وأرقام و _ و . و - فقط (٢–٦٤)' };
  }
  return { username: s, platform: p };
}

/** جوال سعودي → تخزين كـ 9665xxxxxxxx */
function normalizeSignupPhone(raw) {
  let d = String(raw ?? '').replace(/\D/g, '');
  if (d.startsWith('966')) d = d.slice(3);
  if (d.startsWith('0')) d = d.slice(1);
  if (!d || d.length < 9) return { error: 'رقم الجوال مطلوب' };
  if (!/^5\d{8}$/.test(d)) {
    return { error: 'استخدم رقم جوال سعودي يبدأ بـ 5 (مثال: 0591234567 أو 966591234567)' };
  }
  return { phone: `966${d}` };
}

/** استخراج رمز portal من قيمة مطولة أو من رابط «حسابي» (?t=) */
function extractPortalTokenFromInput(raw) {
  const s = String(raw ?? '').trim();
  if (!s) return '';
  const hex64 = /^[a-f0-9]{64}$/i;
  if (hex64.test(s)) return s.toLowerCase();
  try {
    const u = new URL(s, 'http://local.invalid');
    const t = u.searchParams.get('t');
    if (t && String(t).trim().length >= 24) return String(t).trim();
  } catch {
    /* skip */
  }
  const q = s.match(/[?&]t=([^&]+)/);
  if (q && q[1]) {
    try {
      const dec = decodeURIComponent(q[1].trim());
      if (dec.length >= 24) return dec;
    } catch {
      /* skip */
    }
  }
  return '';
}

const PORTAL_SID_COOKIE = 'portal_sid';
const PORTAL_SID_MAX_AGE_SEC = 90 * 24 * 60 * 60;

function readPortalSidCookie(req) {
  const raw = req.headers.cookie;
  if (!raw || typeof raw !== 'string') return '';
  const parts = raw.split(';');
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    const idx = p.indexOf('=');
    if (idx === -1) continue;
    const k = p.slice(0, idx).trim();
    if (k !== PORTAL_SID_COOKIE) continue;
    let v = p.slice(idx + 1).trim();
    try {
      v = decodeURIComponent(v);
    } catch {
      /* keep raw */
    }
    return String(v).trim();
  }
  return '';
}

function portalCookieSecure(req) {
  if (req.secure) return true;
  const xf = String(req.headers['x-forwarded-proto'] || '')
    .split(',')[0]
    .trim()
    .toLowerCase();
  return xf === 'https';
}

function appendPortalSessionCookie(res, token, req) {
  const tok = String(token || '').trim();
  if (!tok) return;
  const bits = [
    `${PORTAL_SID_COOKIE}=${encodeURIComponent(tok)}`,
    'Path=/',
    `Max-Age=${PORTAL_SID_MAX_AGE_SEC}`,
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (portalCookieSecure(req)) bits.push('Secure');
  res.append('Set-Cookie', bits.join('; '));
}

function clearPortalSessionCookie(res, req) {
  const bits = [`${PORTAL_SID_COOKIE}=`, 'Path=/', 'Max-Age=0', 'HttpOnly', 'SameSite=Lax'];
  if (portalCookieSecure(req)) bits.push('Secure');
  res.append('Set-Cookie', bits.join('; '));
}

/** رمز الدخول إلى بوابة المشترك: من query أو من الجسم أو من كوكي الجلسة */
function portalTokenFromReq(req, bodyToken) {
  const q = String(req.query?.t ?? '').trim();
  if (q.length >= 24) return q;
  const b = bodyToken != null ? String(bodyToken).trim() : '';
  if (b.length >= 24) return b;
  const c = readPortalSidCookie(req);
  if (c.length >= 24) return c;
  return '';
}

/** عرض نوع التفاعل المطلوب من الجمهور للعميل */
function campaignInteractionTypeAr(type) {
  const m = {
    visit: 'زيارة الرابط',
    like: 'إعجابات',
    follow: 'متابعين',
    comment: 'تعليقات',
  };
  const k = String(type ?? '').trim();
  return m[k] || (k ? k : '—');
}

/** نص زر «افتح الوجهة» في بوابة المشاركة — حسب نوع الخدمة المطلوبة */
function portalParticipationOpenLabelAr(type) {
  const k = String(type ?? '').trim();
  if (k === 'visit') return 'الانتقال لتنفيذ الزيارة';
  if (k === 'like') return 'الانتقال لتنفيذ الإعجاب';
  if (k === 'follow') return 'الانتقال لتنفيذ المتابعة';
  if (k === 'comment') return 'الانتقال لتنفيذ التعليق';
  return 'فتح وجهة الحملة';
}

/** تذكير بعد الزّر: ما يفعله المشترك ثم العودة لتسجيل المشاركة */
function portalParticipationReturnHintAr(type, destinationKind) {
  const k = String(type ?? '').trim();
  const dk = String(destinationKind ?? 'social').trim();
  const onSocial =
    'على منصة التواصل أنجز المطلوب (زيارة منشور، إعجاب، متابعة حساب، تعليق…) ثم عد إلى هذه الصفحة وسجِّل مشاركتك.';
  const onSite =
    'افتح الرابط وأكمل الزيارة أو الخطوة التي تطلبها الحملة على الموقع، ثم عد لتسجيل مشاركتك.';
  const onStore =
    'افتح رابط المتجر وأكمل ما تطلبه الحملة (زيارة، تصفّح، شراء إن وُجد…) ثم عد لتسجيل مشاركتك.';
  if (dk === 'website') return onSite;
  if (dk === 'store') return onStore;
  if (dk !== 'social') {
    return 'أكمل ما تطلبه الحملة على الوجهة المعروضة، ثم عد لتسجيل مشاركتك.';
  }
  if (k === 'visit') return onSocial;
  if (k === 'like') return 'افتح المنشور أو الصفحة المعروضة وأضِف الإعجاب، ثم عد لتسجيل مشاركتك.';
  if (k === 'follow') return 'افتح الحساب المعروض وتابعه إن طُلب ذلك، ثم عد لتسجيل مشاركتك.';
  if (k === 'comment') return 'افتح المنشور أو المكان المعروض وأضِف التعليق المطلوب، ثم عد لتسجيل مشاركتك.';
  return onSocial;
}

/** ما يهم المشترك: لا يدفع مقابل المشاركة؛ تصفية الحملة للشفافية فقط */
function campaignBillingSubscriberHintAr(billingKind) {
  const bk = String(billingKind ?? '').trim();
  if (bk === 'paid') return 'مدفوعة للمنصة من المعلن — لا رسوم اشتراك عليك';
  if (bk === 'free') return 'مجانية أو شراكة — لا رسوم عليك';
  return 'تصنيف الحملة التجاري غير محدد في النظام';
}

const PORTAL_SERVICE_REQUEST_KIND_AR = {
  paid_service: 'طلب خدمة مدفوعة',
  points: 'طلب متعلق بالنقاط',
  both: 'طلب خدمة مدفوعة والنقاط',
  other: 'طلب أو استفسار',
};

/** حالة تنفيذ طلب العميل في لوحة الفريق */
const CLIENT_SERVICE_FULFILLMENT_LABEL_AR = {
  pending: 'قيد المعالجة',
  completed: 'تم تنفيذ الطلب',
  cancelled: 'ملغاة',
};

function clientServiceFulfillmentLabelAr(raw) {
  const k = String(raw || '').trim();
  return CLIENT_SERVICE_FULFILLMENT_LABEL_AR[k] || CLIENT_SERVICE_FULFILLMENT_LABEL_AR.pending;
}

/** تنظيف الرابط قبل الحفظ: إزالة / الزائدة، وإضافة https:// إذا وُجد نطاق بدون بروتوكول */
function normalizeStoredLink(link) {
  if (link == null) return undefined;
  let s = String(link).trim();
  while (s.startsWith('/')) s = s.slice(1).trim();
  if (!s) return undefined;
  if (!/^https?:\/\//i.test(s)) {
    const looksLikeHost = /^([\w-]+\.)+[a-z]{2,}/i.test(s);
    if (looksLikeHost) s = `https://${s}`;
  }
  return s;
}

/** المنفذ الفعلي بعد الاستماع (قد يختلف إذا كان PORT مشغولاً) */
let listeningPort = null;

/** أساس الروابط المطلقة في قوالب التبليغ وCSV؛ محلياً يُستنتج من الطلب، وعند النشر استخدم PUBLIC_URL */
function resolvedPublicBaseUrl(req) {
  const raw = (process.env.PUBLIC_URL || process.env.PUBLIC_BASE_URL || '').trim();
  const fromEnv = raw.replace(/\/+$/, '');
  if (fromEnv && /^https?:\/\//i.test(fromEnv)) return fromEnv;
  const host = req.get('host');
  const h = host || `127.0.0.1:${listeningPort ?? PORT}`;
  const proto = req.protocol === 'http' || req.protocol === 'https' ? req.protocol : 'http';
  return `${proto}://${h}`;
}

function requireMongo(req, res, next) {
  if (!MONGO_URI) {
    return res.status(503).json({
      error: 'أضف MONGO_URI في ملف .env ثم أعد تشغيل السيرفر.',
    });
  }
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({
      error: 'MongoDB غير متصل. تحقق من سلسلة الاتصال أو انتظر ثوانٍ ثم أعد المحاولة.',
    });
  }
  next();
}

/** تحويل قيم BSON إلى JSON قابل للقراءة في ملف النسخ الاحتياطي */
function serializeMongoValueForBackup(val) {
  if (val === undefined) return undefined;
  if (val === null) return null;
  const t = typeof val;
  if (t !== 'object') return val;
  if (val instanceof Date) return { __backupType: 'Date', iso: val.toISOString() };
  if (Buffer.isBuffer(val)) return { __backupType: 'Binary', base64: val.toString('base64') };
  if (Array.isArray(val)) return val.map((x) => serializeMongoValueForBackup(x));
  const ctor = val.constructor?.name;
  if (ctor === 'Binary' && val.buffer) {
    return { __backupType: 'Binary', base64: Buffer.from(val.buffer).toString('base64') };
  }
  if (ctor === 'ObjectId' || ctor === 'ObjectID') {
    return { __backupType: 'ObjectId', hex: typeof val.toHexString === 'function' ? val.toHexString() : String(val) };
  }
  if (ctor === 'Decimal128') return { __backupType: 'Decimal128', value: val.toString() };
  if (ctor === 'Long' || ctor === 'Int32') return Number(val.valueOf());
  if (ctor === 'BSONRegExp') return { __backupType: 'BSONRegExp', pattern: val.pattern, options: val.options };
  if (val instanceof RegExp) return { __backupType: 'RegExp', source: val.source, flags: val.flags };
  const out = {};
  for (const key of Object.keys(val)) {
    try {
      out[key] = serializeMongoValueForBackup(val[key]);
    } catch {
      out[key] = { __backupType: 'Error', message: String(val[key]) };
    }
  }
  return out;
}

/** عكس serializeMongoValueForBackup لاستيراد وثائق من ملف النسخة الاحتياطية */
function deserializeMongoValueFromBackup(val) {
  if (val === undefined || val === null) return val;
  const t = typeof val;
  if (t !== 'object') return val;
  if (Array.isArray(val)) return val.map((x) => deserializeMongoValueFromBackup(x));
  const bt = val.__backupType;
  if (bt === 'Date') return new Date(val.iso);
  if (bt === 'ObjectId') {
    const hex = String(val.hex || '').trim();
    if (!mongoose.Types.ObjectId.isValid(hex)) throw new Error(`معرّف ObjectId غير صالح في النسخة: ${hex}`);
    return new mongoose.Types.ObjectId(hex);
  }
  if (bt === 'Binary') return Buffer.from(String(val.base64 || ''), 'base64');
  if (bt === 'Decimal128') return Decimal128.fromString(String(val.value));
  if (bt === 'BSONRegExp') return new BSONRegExp(String(val.pattern || ''), String(val.options || ''));
  if (bt === 'RegExp') return new RegExp(val.source, val.flags || '');
  if (bt === 'Error') return val.message;
  const out = {};
  for (const key of Object.keys(val)) {
    out[key] = deserializeMongoValueFromBackup(val[key]);
  }
  return out;
}

async function buildDatabaseBackupPayload() {
  const db = mongoose.connection.db;
  const meta = await db.listCollections().toArray();
  const names = meta.map((m) => m.name).filter((n) => n && !String(n).startsWith('system.'));
  names.sort();
  const collections = {};
  for (const name of names) {
    const docs = await db.collection(name).find({}).toArray();
    collections[name] = docs.map((d) => serializeMongoValueForBackup(d));
  }
  return {
    ok: true,
    exportedAt: new Date().toISOString(),
    database: db.databaseName,
    noteAr:
      'نسخة للأرشفة أو الاستعادة من لوحة الفريق (استيراد JSON). النسخ الكامل ZIP يضم أيضاً مجلد uploads. احفظ الملفات في مكان آمن.',
    collections,
  };
}

app.get('/health', (_req, res) => {
  const port = listeningPort ?? PORT;
  res.json({
    ok: true,
    message: 'Server is running',
    mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    port,
    publicUrlEnvSet: !!(String(process.env.PUBLIC_URL || process.env.PUBLIC_BASE_URL || '').trim()),
  });
});

/** واجهة الاشتراك للعملاء — منفصلة عن لوحة الفريق */
app.get('/join', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'join.html'));
});

/** طلب خدمة مدفوعة أو نقاط — منفصل عن نموذج الاشتراك */
app.get('/service-request', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'service-request.html'));
});

/** دخول المشترك فقط — بدون لوحة الفريق */
app.get('/subscriber-login', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'subscriber-login.html'));
});

/** توافق مع روابط قديمة — يوجّه إلى مسار لوحة الطاقم الفعلي */
app.get('/team', (_req, res) => {
  if (TEAM_PANEL_SECRET_PATH) return res.redirect(302, '/' + TEAM_PANEL_SECRET_PATH);
  res.redirect(302, '/');
});

/** اسم بديل للوحة — يوجّه إلى المسار السري إن وُجد */
app.get('/panel', (_req, res) => {
  if (TEAM_PANEL_SECRET_PATH) return res.redirect(302, '/' + TEAM_PANEL_SECRET_PATH);
  res.redirect(302, '/');
});

/** حساب العميل — جلسة HttpOnly؛ إن وُجد ?t= يُثبَّت الكوكي ثم يُزال من العنوان */
app.get('/my-account', (req, res) => {
  const fromQuery = String(req.query.t || '').trim();
  const fromCookie = readPortalSidCookie(req).trim();
  if (fromQuery.length >= 24) {
    appendPortalSessionCookie(res, fromQuery, req);
    return res.redirect(302, '/my-account');
  }
  if (fromCookie.length < 24) {
    return res.redirect(302, '/subscriber-login');
  }
  res.sendFile(path.join(__dirname, 'public', 'my-account.html'));
});

/** خروج المشترك — مسح جلسة البوابة */
app.get('/api/portal/logout', (req, res) => {
  clearPortalSessionCookie(res, req);
  res.redirect(302, '/subscriber-login');
});

/** تتبع حملة لصاحب العلامة — الرمز السري في Query ?t= */
app.get('/campaign-track', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'campaign-track.html'));
});

/**
 * تتبع الضغط على رابط الحملة ثم تحويل لوجهة الحملة (متجر، موقع، سوشال…)
 * استخدام: /go?c=<معرف_الحملة>  أو  /go?c=...&u=<معرف_المشترك>
 */
app.get('/go', async (req, res) => {
  const c = req.query.c;
  const u = req.query.u;
  if (!mongoose.isValidObjectId(c)) {
    return res.status(400).type('text/plain; charset=utf-8').send('Invalid campaign id');
  }
  try {
    const campaign = await Campaign.findById(c).populate('targetUserId', 'socialPlatform instagramUsername').lean();
    if (!campaign) {
      return res.status(404).type('text/plain; charset=utf-8').send('Campaign or link not found');
    }
    const fromLink = normalizeStoredLink(campaign.link);
    let dest =
      fromLink && /^https?:\/\//i.test(String(fromLink).trim()) ? String(fromLink).trim() : '';
    if (!dest) {
      dest = portalParticipationOpenUrlFromCampaign(campaign);
    }
    if (!dest) {
      return res.status(404).type('text/plain; charset=utf-8').send('Campaign or link not found');
    }
    try {
      const parsed = new URL(dest);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('protocol');
      }
    } catch {
      return res.status(400).type('text/plain; charset=utf-8').send('Invalid destination URL');
    }

    const userId = u && mongoose.isValidObjectId(u) ? u : null;

    if (MONGO_URI && mongoose.connection.readyState === 1) {
      try {
        await LinkClick.create({
          campaignId: c,
          userId,
          ip: String(req.ip || req.socket.remoteAddress || '').slice(0, 64),
          userAgent: String(req.get('user-agent') || '').slice(0, 512),
        });
      } catch (err) {
        console.warn('[WARN] LinkClick:', err.message);
      }
    }

    res.redirect(302, dest);
  } catch (err) {
    console.error('[ERR] /go', err);
    res.status(500).type('text/plain; charset=utf-8').send('Server error');
  }
});

/** منع كاش استجابات الـ API في المتصفح (لوحة التحكم تعتمد على GET حديث) */
app.use('/api', (_req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  next();
});

app.post('/api/team-panel/login', (req, res) => {
  try {
    if (!TEAM_PANEL_PASSWORD) {
      return res.status(404).json({ error: 'كلمة مرور لوحة الطاقم غير مفعّلة على الخادم' });
    }
    if (!verifyTeamPanelPassword(req.body?.password)) {
      return res.status(401).json({ error: 'كلمة المرور غير صحيحة' });
    }
    const tok = crypto.randomBytes(32).toString('hex');
    teamGateSessions.set(tok, Date.now() + TEAM_GATE_MAX_AGE_MS);
    appendTeamGateCookie(res, tok, req);
    const redir = TEAM_PANEL_SECRET_PATH ? '/' + TEAM_PANEL_SECRET_PATH : '/';
    res.json({ ok: true, redirect: redir });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/team-panel/logout', (req, res) => {
  const tok = readTeamGateCookie(req);
  if (tok) teamGateSessions.delete(tok);
  clearTeamGateCookie(res, req);
  res.redirect(302, '/join');
});

app.use(teamPanelApiProtection);

/** خيارات نموذج طلب الخدمة — تُفلتر حسب إعدادات لوحة الفريق عند اتصال Mongo */
app.get('/api/public/service-request-options', async (_req, res) => {
  try {
    const enabledSet = await getEnabledClientServiceIdFilterSet();
    const restrictActive = enabledSet != null && enabledSet.size > 0;
    const serviceOptions = SIGNUP_SERVICE_OPTIONS.filter((o) => !restrictActive || enabledSet.has(o.id)).map((o) =>
      serviceRequestOptionPayload(o)
    );
    res.json({
      ok: true,
      serviceOptions,
      clientServicesRestricted: restrictActive,
      defaultPointsPerInteraction: POINTS_PER_INTERACTION,
      qtyPricingNoteAr: QTY_PRICING_NOTE_AR,
      instagramPricingNoteAr: QTY_PRICING_NOTE_AR,
    });
  } catch (err) {
    console.error('[ERR] /api/public/service-request-options', err);
    res.status(500).json({ error: err.message });
  }
});

app.use('/api', requireMongo);

/** إعدادات صفحة الاشتراك： المنصات المفعّلة للعميل */
app.get('/api/settings/join', async (_req, res) => {
  try {
    const j = await getJoinPlatformSettings();
    res.json({
      ok: true,
      platforms: j.platforms,
      allPlatforms: SOCIAL_PLATFORM_META.map(({ id, labelAr }) => ({ id, labelAr })),
      enabledPlatformIds: j.enabledPlatformIds,
      platformLogoUrl: j.platformLogoUrl,
      joinHeroTitle: j.joinHeroTitle,
      joinHeroLeadHtml: j.joinHeroLeadHtml,
      joinHeroAsideHtml: j.joinHeroAsideHtml,
      joinWhyHeading: j.joinWhyHeading,
      joinWhyCard1Title: j.joinWhyCard1Title,
      joinWhyCard1Html: j.joinWhyCard1Html,
      joinWhyCard2Title: j.joinWhyCard2Title,
      joinWhyCard2Html: j.joinWhyCard2Html,
      joinWhyCard3Title: j.joinWhyCard3Title,
      joinWhyCard3Html: j.joinWhyCard3Html,
      joinStepsHeading: j.joinStepsHeading,
      joinStep1Title: j.joinStep1Title,
      joinStep1Html: j.joinStep1Html,
      joinStep2Title: j.joinStep2Title,
      joinStep2Html: j.joinStep2Html,
      joinStep3Title: j.joinStep3Title,
      joinStep3Html: j.joinStep3Html,
      joinSubscribeHeading: j.joinSubscribeHeading,
      joinSubscribeIntroHtml: j.joinSubscribeIntroHtml,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** رفع شعار المنصة (لوحة الفريق) — يُستبدل الملف السابق إن وُجد */
app.post('/api/settings/logo', (req, res, next) => {
  logoUploadMiddleware(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'حجم الشعار يتجاوز ١٫٥ ميجابايت' });
      }
      return res.status(400).json({ error: err.message || 'فشل رفع الشعار' });
    }
    next();
  });
}, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'أرسل ملف الشعار في الحقل logo' });
    }
    const rel = `/uploads/branding/${req.file.filename}`;
    const prev = await SiteSettings.findById('main').select('platformLogoUrl').lean();
    if (prev?.platformLogoUrl) unlinkBrandingUploadByPublicPath(prev.platformLogoUrl);
    await SiteSettings.findOneAndUpdate(
      { _id: 'main' },
      { $set: { platformLogoUrl: rel } },
      { upsert: true }
    ).lean();
    res.json({ ok: true, platformLogoUrl: rel });
  } catch (err) {
    try {
      if (req.file?.path) fs.unlinkSync(req.file.path);
    } catch (_) {}
    res.status(500).json({ error: err.message });
  }
});

/** محتوى صفحة الاشتراك (/join): البطل والأقسام — لوحة الفريق. يمكن إرسال جزء من الحقول فقط. */
app.patch('/api/settings/join-hero', async (req, res) => {
  try {
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    const $set = {};
    const titleFields = [
      'joinHeroTitle',
      'joinWhyHeading',
      'joinWhyCard1Title',
      'joinWhyCard2Title',
      'joinWhyCard3Title',
      'joinStepsHeading',
      'joinStep1Title',
      'joinStep2Title',
      'joinStep3Title',
      'joinSubscribeHeading',
    ];
    for (const key of titleFields) {
      if (Object.prototype.hasOwnProperty.call(b, key)) $set[key] = sanitizeJoinHeroTitle(b[key]);
    }
    const htmlFields = [
      'joinHeroLeadHtml',
      'joinHeroAsideHtml',
      'joinWhyCard1Html',
      'joinWhyCard2Html',
      'joinWhyCard3Html',
      'joinStep1Html',
      'joinStep2Html',
      'joinStep3Html',
      'joinSubscribeIntroHtml',
    ];
    for (const key of htmlFields) {
      if (Object.prototype.hasOwnProperty.call(b, key)) $set[key] = sanitizeJoinHeroLeadHtml(b[key]);
    }
    if (!Object.keys($set).length) {
      return res.status(400).json({ error: 'لا حقول للتحديث' });
    }
    await SiteSettings.findOneAndUpdate({ _id: 'main' }, { $set }, { upsert: true }).lean();
    const fresh = await getJoinPlatformSettings();
    res.json({
      ok: true,
      joinHeroTitle: fresh.joinHeroTitle,
      joinHeroLeadHtml: fresh.joinHeroLeadHtml,
      joinHeroAsideHtml: fresh.joinHeroAsideHtml,
      joinWhyHeading: fresh.joinWhyHeading,
      joinWhyCard1Title: fresh.joinWhyCard1Title,
      joinWhyCard1Html: fresh.joinWhyCard1Html,
      joinWhyCard2Title: fresh.joinWhyCard2Title,
      joinWhyCard2Html: fresh.joinWhyCard2Html,
      joinWhyCard3Title: fresh.joinWhyCard3Title,
      joinWhyCard3Html: fresh.joinWhyCard3Html,
      joinStepsHeading: fresh.joinStepsHeading,
      joinStep1Title: fresh.joinStep1Title,
      joinStep1Html: fresh.joinStep1Html,
      joinStep2Title: fresh.joinStep2Title,
      joinStep2Html: fresh.joinStep2Html,
      joinStep3Title: fresh.joinStep3Title,
      joinStep3Html: fresh.joinStep3Html,
      joinSubscribeHeading: fresh.joinSubscribeHeading,
      joinSubscribeIntroHtml: fresh.joinSubscribeIntroHtml,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** نصوص صفحة دخول المشترك (/subscriber-login) — للجميع قراءة */
app.get('/api/settings/subscriber-login', async (_req, res) => {
  try {
    const s = await getSubscriberPortalSettings();
    res.json({ ok: true, ...s });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** شريط أحمر أسفل صفحات العملاء — قراءة عامة */
app.get('/api/settings/global-banner', async (_req, res) => {
  try {
    const { globalBannerHtml } = await getGlobalBannerSettings();
    res.json({ ok: true, globalBannerHtml });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** حفظ شريط الصفحات العامة — لوحة الفريق */
app.patch('/api/settings/global-banner', async (req, res) => {
  try {
    const globalBannerHtml = sanitizeGlobalBannerHtml(req.body?.globalBannerHtml ?? '');
    await SiteSettings.findOneAndUpdate(
      { _id: 'main' },
      { $set: { globalBannerHtml } },
      { upsert: true }
    ).lean();
    const fresh = await getGlobalBannerSettings();
    res.json({ ok: true, globalBannerHtml: fresh.globalBannerHtml });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** عنوان، وصف صفحة دخول المشترك — لوحة الفريق */
app.patch('/api/settings/subscriber-login-copy', async (req, res) => {
  try {
    const subscriberHeroTitle = sanitizeJoinHeroTitle(req.body?.subscriberHeroTitle ?? '');
    const subscriberHeroLeadHtml = sanitizeJoinHeroLeadHtml(req.body?.subscriberHeroLeadHtml ?? '');
    await SiteSettings.findOneAndUpdate(
      { _id: 'main' },
      { $set: { subscriberHeroTitle, subscriberHeroLeadHtml } },
      { upsert: true }
    ).lean();
    const fresh = await getSubscriberPortalSettings();
    res.json({ ok: true, ...fresh });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** تحديث المنصات المتاحة في نموذج الاشتراك (لوحة الفريق) */
app.patch('/api/settings/platforms', async (req, res) => {
  try {
    const raw = req.body?.enabledPlatforms;
    if (!Array.isArray(raw) || raw.length === 0) {
      return res.status(400).json({ error: 'أرسل enabledPlatforms كمصفوفة غير فارغة من معرفات المنصات' });
    }
    const enabledPlatforms = [...new Set(raw.map((x) => String(x).trim().toLowerCase()))].filter((id) =>
      PLATFORM_ID_SET.has(id)
    );
    if (!enabledPlatforms.length) {
      return res.status(400).json({ error: 'لا توجد معرفات منصات صالحة في الطلب' });
    }
    await SiteSettings.findOneAndUpdate(
      { _id: 'main' },
      { $set: { enabledPlatforms } },
      { upsert: true, new: true }
    ).lean();
    const fresh = await getJoinPlatformSettings();
    res.json({
      ok: true,
      enabledPlatformIds: fresh.enabledPlatformIds,
      platforms: fresh.platforms,
      platformLogoUrl: fresh.platformLogoUrl,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** إنشاء مشترك (مدينة + اهتمامات + طلبات خدمات + منصة + يوزر + جوال + جنس) */
app.post('/api/users', async (req, res) => {
  try {
    const { name, city, interests, fcmToken, instagramUsername, phone, gender, socialPlatform, signupNotes } =
      req.body;
    const rsRaw = req.body?.requestedServices;
    if (!city) {
      return res.status(400).json({ error: 'حقل city مطلوب' });
    }
    const { enabledPlatformIds } = await getJoinPlatformSettings();
    let plat = String(socialPlatform ?? 'instagram')
      .trim()
      .toLowerCase();
    if (!PLATFORM_ID_SET.has(plat)) {
      return res.status(400).json({ error: 'منصة غير معروفة' });
    }
    if (!enabledPlatformIds.includes(plat)) {
      return res.status(400).json({ error: 'هذه المنصة غير مفعّلة حالياً للتسجيل — راجع إعدادات المنصات في لوحة الفريق' });
    }

    const ig = normalizeSignupSocial(plat, instagramUsername);
    if (ig.error) return res.status(400).json({ error: ig.error });
    const ph = normalizeSignupPhone(phone);
    if (ph.error) return res.status(400).json({ error: ph.error });
    const genders = ['male', 'female', 'unspecified'];
    const g = genders.includes(gender) ? gender : 'unspecified';

    let requestedServices = [];
    if (Array.isArray(rsRaw)) {
      requestedServices = [...new Set(rsRaw.map((x) => String(x).trim().toLowerCase()))].filter((id) =>
        SIGNUP_SERVICE_ID_SET.has(id)
      );
    }
    const svcOfferFilter = await getEnabledClientServiceIdFilterSet();
    if (svcOfferFilter != null && requestedServices.some((id) => !svcOfferFilter.has(id))) {
      return res.status(400).json({
        error:
          'أحد خيارات الخدمة غير متاح حالياً للتسجيل — حدّث الصفحة أو أزل الخدمات التي أخفاها الفريق من الطلب.',
      });
    }
    const notes =
      signupNotes != null ? String(signupNotes).replace(/\r\n/g, '\n').trim().slice(0, 2000) : '';

    const user = await createUserWithPortalToken({
      name,
      city,
      interests: Array.isArray(interests) ? interests : [],
      fcmToken,
      socialPlatform: ig.platform,
      instagramUsername: ig.username,
      phone: ph.phone,
      gender: g,
      requestedServices,
      signupNotes: notes || undefined,
    });
    const raw = user.toObject ? user.toObject() : user;
    const { portalToken: _omitTok, ...userSafe } = raw;
    res.status(201).json({ ok: true, user: userSafe });
  } catch (err) {
    if (err.code === 11000) {
      const kv = err.keyValue && typeof err.keyValue === 'object' ? err.keyValue : {};
      if ('instagramUsername' in kv && 'socialPlatform' in kv) {
        return res.status(400).json({ error: 'اسم المستخدم مسجّل مسبقاً على هذه المنصة' });
      }
      if ('instagramUsername' in kv) {
        return res.status(400).json({ error: 'اسم المستخدم مسجّل مسبقاً على هذه المنصة' });
      }
      if ('phone' in kv) {
        return res.status(400).json({ error: 'رقم الجوال مسجّل مسبقاً' });
      }
    }
    res.status(500).json({ error: err.message });
  }
});

/** طلب عميل: خدمة مدفوعة و/أو نقاط (من صفحة طلب أو من «حسابي» مع جلسة portal_sid) */
app.post('/api/client/service-requests', async (req, res) => {
  try {
    const portalHint =
      req.body?.portalToken != null
        ? String(req.body.portalToken)
        : req.body?.portalLink != null
          ? String(req.body.portalLink)
          : '';
    let portalTok = extractPortalTokenFromInput(portalHint);
    if (!portalTok || portalTok.length < 24) {
      const c = readPortalSidCookie(req).trim();
      if (c.length >= 24) portalTok = c;
    }

    let userId = null;
    let linkedViaPortal = false;
    let phone = '';

    if (portalTok.length >= 24) {
      const u = await User.findOne({ portalToken: portalTok }).select('_id phone').lean();
      if (u) {
        userId = u._id;
        linkedViaPortal = true;
        const pn = normalizeSignupPhone(u.phone);
        if (pn.error) {
          return res.status(400).json({ error: 'لا يمكن ربط الطلب بحسابك — رقم الجوال غير مكتمل في السجل.' });
        }
        phone = pn.phone;
      }
    }

    if (!phone) {
      const ph = normalizeSignupPhone(req.body?.phone);
      if (ph.error) return res.status(400).json({ error: ph.error });
      phone = ph.phone;
    } else {
      const ph = normalizeSignupPhone(req.body?.phone);
      if (!ph.error && ph.phone !== phone) {
        return res.status(403).json({ error: 'رقم الجوال لا يطابق حسابك المسجّل دخولك.' });
      }
    }

    const name = req.body?.name != null ? String(req.body.name).trim().slice(0, 120) : '';
    const kinds = ['paid_service', 'points', 'both', 'other'];
    let requestKind = String(req.body?.requestKind || '').trim();
    if (!kinds.includes(requestKind)) requestKind = 'other';
    const rsRaw = req.body?.requestedServices;
    let requestedServices = [];
    if (Array.isArray(rsRaw)) {
      requestedServices = [...new Set(rsRaw.map((x) => String(x).trim().toLowerCase()))].filter((id) =>
        SIGNUP_SERVICE_ID_SET.has(id)
      );
    }
    const svcOfferFilterReq = await getEnabledClientServiceIdFilterSet();
    if (svcOfferFilterReq != null && requestedServices.some((id) => !svcOfferFilterReq.has(id))) {
      return res.status(400).json({
        error: 'إحدى الخدمات المطلوبة غير متاحة حالياً — حدّث الصفحة واختر من الخيارات المعروضة فقط.',
      });
    }
    const title =
      req.body?.title != null ? String(req.body.title).replace(/\r\n/g, ' ').trim().slice(0, 200) : '';
    if (title.length < 2) {
      return res.status(400).json({ error: 'أدخل عنواناً للطلب (حرفان على الأقل)' });
    }
    const details =
      req.body?.details != null ? String(req.body.details).replace(/\r\n/g, '\n').trim().slice(0, 2500) : '';
    if (details.length < 8) {
      return res.status(400).json({ error: 'أضف وصفاً لطلبك (٨ أحرف على الأقل)' });
    }

    const serviceQuantities = normalizeServiceQuantitiesBody(req.body?.serviceQuantities);
    const pricingBuild = buildQtyPricingForRequest(requestedServices, serviceQuantities);
    if (!pricingBuild.ok) {
      return res.status(400).json({ error: pricingBuild.error });
    }

    const persistedQty = {};
    for (const line of pricingBuild.lines) {
      persistedQty[line.serviceId] = line.quantity;
    }

    await ClientServiceRequest.create({
      phone,
      name,
      requestKind,
      requestedServices,
      serviceQuantities: persistedQty,
      pricingEstimateLines: pricingBuild.lines,
      estimatedTotalSar: pricingBuild.estimatedTotalSar,
      estimatedTotalPoints: pricingBuild.estimatedTotalPoints,
      pricingNoteAr: pricingBuild.lines.length ? QTY_PRICING_NOTE_AR : '',
      title,
      details,
      userId,
      linkedViaPortal,
    });
    res.status(201).json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** قائمة طلبات العملاء (خدمات/نقاط) — لوحة الفريق */
app.get('/api/admin/client-service-requests', async (_req, res) => {
  try {
    const rows = await ClientServiceRequest.find({})
      .sort({ createdAt: -1 })
      .limit(80)
      .populate('userId', 'instagramUsername socialPlatform phone city name')
      .lean();
    const out = rows.map((r) => ({
      id: String(r._id),
      createdAt: r.createdAt,
      phone: r.phone,
      name: r.name || '',
      requestKind: r.requestKind,
      requestedServices: r.requestedServices || [],
      requestedServiceLabels: (r.requestedServices || []).map(
        (id) => SIGNUP_SERVICE_LABEL_BY_ID[id] || id
      ),
      pricingHintsAr: [
        ...new Set(
          (r.requestedServices || []).map((id) => SIGNUP_SERVICE_PRICING_HINT_AR[id]).filter(Boolean)
        ),
      ],
      serviceQuantities: r.serviceQuantities && typeof r.serviceQuantities === 'object' ? r.serviceQuantities : {},
      pricingEstimateLines: Array.isArray(r.pricingEstimateLines) ? r.pricingEstimateLines : [],
      estimatedTotalSar: r.estimatedTotalSar ?? null,
      estimatedTotalPoints: r.estimatedTotalPoints ?? null,
      pricingNoteAr: r.pricingNoteAr || '',
      title: r.title || '',
      details: r.details || '',
      linkedViaPortal: !!r.linkedViaPortal,
      userId: r.userId ? String(r.userId._id || r.userId) : '',
      userUsername: r.userId?.instagramUsername || '',
      userPlatform: r.userId?.socialPlatform || '',
      fulfillmentStatus: r.fulfillmentStatus || 'pending',
      fulfillmentStatusAr: clientServiceFulfillmentLabelAr(r.fulfillmentStatus),
    }));
    res.json({ ok: true, rows: out });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** تصدير نسخة احتياطية JSON لكل مجموعات MongoDB (لوحة الفريق، ملف للتنزيل — لا يشمل ملفات public/uploads) */
app.get('/api/admin/database-backup.json', async (_req, res) => {
  try {
    const payload = await buildDatabaseBackupPayload();
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const fn = `roaed-db-backup-${stamp}.json`;
    const body = JSON.stringify(payload, null, 2);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fn}"`);
    res.send(body);
  } catch (err) {
    console.error('[ERR] /api/admin/database-backup.json', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * استعادة البيانات من ملف JSON صادر من هذا الخادم (يُفرَّغ كل مجموعة مذكورة في الملف ثم تُعاد كتابتها).
 * لا يحذف مجموعات غير موجودة في الملف.
 */
app.post('/api/admin/database-restore', dbRestoreUpload, async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        error: 'MongoDB غير متصل. تحقق من سلسلة الاتصال أو انتظر ثوانٍ ثم أعد المحاولة.',
      });
    }
    const confirm = String(req.body?.confirmText ?? '').trim();
    if (confirm !== DB_RESTORE_CONFIRM_PHRASE) {
      return res.status(400).json({
        error: `عبارة التأكيد غير صحيحة. اكتب بالضبط: ${DB_RESTORE_CONFIRM_PHRASE}`,
      });
    }
    const file = req.file;
    if (!file?.buffer?.length) {
      return res.status(400).json({ error: 'أرفق ملف النسخة الاحتياطية باسم الحقل backup' });
    }
    let data;
    try {
      data = JSON.parse(file.buffer.toString('utf8'));
    } catch {
      return res.status(400).json({ error: 'محتوى الملف ليس JSON صالحاً' });
    }
    const cols = data.collections;
    if (!cols || typeof cols !== 'object' || Array.isArray(cols)) {
      return res.status(400).json({ error: 'الملف لا يحتوي على كائن collections صالحاً' });
    }
    const db = mongoose.connection.db;
    const names = Object.keys(cols).filter((n) => n && !String(n).startsWith('system.'));
    names.sort();
    let restoredCollections = 0;
    let insertedDocuments = 0;
    const CHUNK = 1000;
    for (const name of names) {
      const arr = cols[name];
      if (!Array.isArray(arr)) continue;
      const coll = db.collection(name);
      await coll.deleteMany({});
      const docs = arr.map((d) => deserializeMongoValueFromBackup(d));
      for (let i = 0; i < docs.length; i += CHUNK) {
        const slice = docs.slice(i, i + CHUNK);
        if (slice.length) await coll.insertMany(slice, { ordered: false });
      }
      restoredCollections += 1;
      insertedDocuments += docs.length;
    }
    res.json({
      ok: true,
      restoredCollections,
      insertedDocuments,
      noteAr: 'المجموعات غير المذكورة في الملف لم تُمسّ.',
    });
  } catch (err) {
    console.error('[ERR] /api/admin/database-restore', err);
    res.status(500).json({ error: err.message });
  }
});

/** أرشيف ZIP: database.json + مجلد public/uploads (إن وُجد) */
app.get('/api/admin/full-backup.zip', async (_req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        error: 'MongoDB غير متصل. تحقق من سلسلة الاتصال أو انتظر ثوانٍ ثم أعد المحاولة.',
      });
    }
    const payload = await buildDatabaseBackupPayload();
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const fn = `roaed-full-backup-${stamp}.zip`;
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${fn}"`);
    const archive = new ZipArchive({ zlib: { level: 6 } });
    archive.on('error', (err) => {
      console.error('[ERR] full-backup archive', err);
      if (!res.headersSent) res.status(500).json({ error: err.message });
    });
    archive.pipe(res);
    archive.append(JSON.stringify(payload, null, 2), { name: 'database.json' });
    const uploadsRoot = path.join(__dirname, 'public', 'uploads');
    if (fs.existsSync(uploadsRoot)) {
      archive.directory(uploadsRoot, 'uploads');
    }
    await archive.finalize();
  } catch (err) {
    console.error('[ERR] /api/admin/full-backup.zip', err);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

/** تحديث حالة تنفيذ طلب عميل — لوحة الفريق */
app.patch('/api/admin/client-service-requests/:requestId', async (req, res) => {
  try {
    const { requestId } = req.params;
    if (!mongoose.isValidObjectId(requestId)) {
      return res.status(400).json({ error: 'معرّف الطلب غير صالح' });
    }
    const allowed = new Set(['pending', 'completed', 'cancelled']);
    const st = String(req.body?.fulfillmentStatus ?? '').trim();
    if (!allowed.has(st)) {
      return res.status(400).json({ error: 'الحالة يجب أن تكون: pending أو completed أو cancelled' });
    }
    const updated = await ClientServiceRequest.findByIdAndUpdate(
      requestId,
      { $set: { fulfillmentStatus: st } },
      { new: true }
    ).lean();
    if (!updated) return res.status(404).json({ error: 'الطلب غير موجود' });
    res.json({
      ok: true,
      fulfillmentStatus: updated.fulfillmentStatus,
      fulfillmentStatusAr: clientServiceFulfillmentLabelAr(updated.fulfillmentStatus),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** حذف طلب عميل — لوحة الفريق */
app.delete('/api/admin/client-service-requests/:requestId', async (req, res) => {
  try {
    const { requestId } = req.params;
    if (!mongoose.isValidObjectId(requestId)) {
      return res.status(400).json({ error: 'معرّف الطلب غير صالح' });
    }
    const deleted = await ClientServiceRequest.findByIdAndDelete(requestId).lean();
    if (!deleted) return res.status(404).json({ error: 'الطلب غير موجود' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** مرجع لوحة الفريق: كل خيارات الطلب + ما إذا كانت معروضة للعميل */
app.get('/api/admin/client-service-catalog', async (_req, res) => {
  try {
    await ensureSiteSettingsDoc();
    const doc = await SiteSettings.findById('main').select('enabledClientServiceIds').lean();
    const raw = doc?.enabledClientServiceIds;
    const cleanedRaw =
      Array.isArray(raw) && raw.length
        ? [
            ...new Set(
              raw.map((id) => String(id).trim().toLowerCase()).filter((id) => SIGNUP_SERVICE_ID_SET.has(id))
            ),
          ]
        : [];
    const restricted = cleanedRaw.length > 0;
    const enabledIds = restricted ? cleanedRaw : null;
    const allowedSet = restricted ? new Set(cleanedRaw) : null;
    const rows = SIGNUP_SERVICE_OPTIONS.map((o) => ({
      ...serviceRequestOptionPayload(o),
      shownToClient: allowedSet == null || allowedSet.has(o.id),
    }));
    res.json({
      ok: true,
      restricted,
      enabledClientServiceIds: enabledIds,
      rows,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** حفظ خدمات طلب الخدمة / حسابي المعروضة للعميل */
app.patch('/api/admin/client-service-catalog', async (req, res) => {
  try {
    const body = req.body || {};
    if (body.restricted === false || body.mode === 'all') {
      await SiteSettings.updateOne({ _id: 'main' }, { $unset: { enabledClientServiceIds: '' } }, { upsert: true });
      return res.json({ ok: true, restricted: false, enabledClientServiceIds: null });
    }
    const arr = body.enabledClientServiceIds;
    if (!Array.isArray(arr)) {
      return res.status(400).json({
        error:
          'أرسل enabledClientServiceIds كمصفوفة معرفات صالحة، أو restricted:false لإظهار كل الخدمات للعميل.',
      });
    }
    const cleaned = [
      ...new Set(arr.map((x) => String(x).trim().toLowerCase()).filter((id) => SIGNUP_SERVICE_ID_SET.has(id))),
    ];
    if (!cleaned.length) {
      return res.status(400).json({
        error: 'اختر خدمة واحدة على الأقل في الوضع المحدد، أو انتقل إلى «كل الخدمات».',
      });
    }
    await SiteSettings.updateOne(
      { _id: 'main' },
      { $set: { enabledClientServiceIds: cleaned } },
      { upsert: true }
    );
    res.json({ ok: true, restricted: true, enabledClientServiceIds: cleaned });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** ملخص حساب العميل — يحميه المعامل السري t (portalToken) */
app.get('/api/portal/summary', async (req, res) => {
  try {
    const t = portalTokenFromReq(req);
    if (!t || t.length < 24) {
      return res.status(400).json({ error: 'أعد الدخول من صفحة «دخول حسابي»' });
    }
    const user = await User.findOne({ portalToken: t }).lean();
    if (!user) return res.status(404).json({ error: 'الرابط غير صالح' });

    const userId = user._id;
    const phoneNorm = String(user.phone || '').trim();
    const srOr = [{ userId }];
    if (phoneNorm) srOr.push({ phone: phoneNorm });

    const [interactionRows, interactionsTotal, payments, pointsGrants, serviceRequests, linkClickRows] = await Promise.all([
      Interaction.find({ userId })
        .sort({ createdAt: -1 })
        .limit(40)
        .populate('campaignId', 'title type destinationKind billingKind')
        .lean(),
      Interaction.countDocuments({ userId }),
      SubscriberPayment.find({ userId }).sort({ createdAt: -1 }).limit(80).lean(),
      SubscriberPointsGrant.find({ userId }).sort({ createdAt: -1 }).limit(80).lean(),
      ClientServiceRequest.find({ $or: srOr }).sort({ createdAt: -1 }).limit(40).lean(),
      LinkClick.find({ userId }).sort({ createdAt: -1 }).limit(35).populate('campaignId', 'title billingKind').lean(),
    ]);

    const interactions = interactionRows.map((row) => ({
      campaignTitle: row.campaignId?.title || '—',
      campaignType: row.campaignId?.type || '',
      campaignTypeAr: campaignInteractionTypeAr(row.campaignId?.type),
      campaignBillingKind: row.campaignId?.billingKind || '',
      campaignBillingHintAr: campaignBillingSubscriberHintAr(row.campaignId?.billingKind),
      pointsEarned: interactionPointsStored(row),
      createdAt: row.createdAt,
    }));

    const paymentsOut = payments.map((p) => ({
      amountSar: p.amountSar,
      label: p.label || '',
      note: p.note || '',
      createdAt: p.createdAt,
    }));
    const totalPaidSar = paymentsOut.reduce((s, p) => s + (Number(p.amountSar) || 0), 0);

    const serviceRequestsOut = serviceRequests.map((sr) => ({
      requestKind: sr.requestKind,
      titleAr: PORTAL_SERVICE_REQUEST_KIND_AR[sr.requestKind] || sr.requestKind,
      requestTitle: String(sr.title || '').trim(),
      requestedServiceLabels: (sr.requestedServices || []).map(
        (id) => SIGNUP_SERVICE_LABEL_BY_ID[id] || id
      ),
      detailsPreview: String(sr.details || '').trim().slice(0, 220),
      linkedViaPortal: !!sr.linkedViaPortal,
      createdAt: sr.createdAt,
      estimatedTotalSar: sr.estimatedTotalSar ?? null,
      estimatedTotalPoints: sr.estimatedTotalPoints ?? null,
      pricingEstimateLines: Array.isArray(sr.pricingEstimateLines) ? sr.pricingEstimateLines : [],
      fulfillmentStatus: sr.fulfillmentStatus || 'pending',
      fulfillmentStatusAr: clientServiceFulfillmentLabelAr(sr.fulfillmentStatus),
    }));

    /** سجل واحد يوفّق بين مدفوع لك، ومشاركات مجانية لك، وطلبات، وزيارات روابط */
    const portalActivities = [];

    portalActivities.push({
      id: `signup:${String(user._id)}`,
      at: user.createdAt,
      bucketAr: 'تسجيل',
      headlineAr: 'انضمامك إلى قائمة مشتركي المنصة',
      detailAr: user.city ? `المدينة: ${user.city}` : 'تم إنشاء حسابك في المنصة',
      pointsDelta: null,
      amountSar: null,
    });

    for (const row of interactionRows) {
      const camp = row.campaignId;
      const title = camp?.title || '—';
      const typeAr = campaignInteractionTypeAr(camp?.type);
      portalActivities.push({
        id: `interaction:${String(row._id)}`,
        at: row.createdAt,
        bucketAr: 'مشاركة (مجانية لك)',
        headlineAr: 'تسجيل تفاعل في حملة',
        detailAr: `${title} · ${typeAr} · ${campaignBillingSubscriberHintAr(camp?.billingKind)}`,
        pointsDelta: interactionPointsStored(row),
        amountSar: null,
      });
    }

    for (const p of payments) {
      const bits = [p.label, p.note].map((x) => String(x || '').trim()).filter(Boolean);
      portalActivities.push({
        id: `payment:${String(p._id)}`,
        at: p.createdAt,
        bucketAr: 'مدفوع لك',
        headlineAr: 'دفعة مسجّلة لصالحك من الفريق',
        detailAr: bits.length ? bits.join(' — ') : '—',
        pointsDelta: null,
        amountSar: Number(p.amountSar) || 0,
      });
    }

    for (const g of pointsGrants) {
      const pts = Math.floor(Number(g.points)) || 0;
      const noteTr = String(g.note || '').trim();
      const detailAr =
        noteTr ?
          [`+${pts} نقطة`, noteTr].join(' — ')
        : `+${pts} نقطة — استلمت مكافئة من الفريق وأُضيفت إلى رصيدك.`;
      portalActivities.push({
        id: `points-grant:${String(g._id)}`,
        at: g.createdAt,
        bucketAr: 'مكافئة',
        headlineAr: 'استلمت مكافئة نقاط',
        detailAr,
        pointsDelta: pts,
        amountSar: null,
      });
    }

    for (const sr of serviceRequests) {
      const labs = (sr.requestedServices || []).map((id) => SIGNUP_SERVICE_LABEL_BY_ID[id] || id);
      const shortTitle = String(sr.title || '').trim();
      const det = String(sr.details || '').trim();
      const labPart = labs.length ? `مجالات مرتبطة: ${labs.join('، ')}` : '';
      let pricingExtra = '';
      if (
        sr.estimatedTotalSar != null &&
        sr.estimatedTotalPoints != null &&
        Number(sr.estimatedTotalPoints) > 0
      ) {
        pricingExtra = `تقدير الكمية (حسب المنصة في الجدول): ~${sr.estimatedTotalSar} ر.س؛ نقاط مقترحة ⌈كمية÷2⌉ = ${sr.estimatedTotalPoints} نقطة — لا يُخصم من رصيدك حتى يعتمد الفريق التنفيذ.`;
      }
      const statusAr = clientServiceFulfillmentLabelAr(sr.fulfillmentStatus);
      const detailAr = [
        shortTitle ? `العنوان: ${shortTitle}` : '',
        PORTAL_SERVICE_REQUEST_KIND_AR[sr.requestKind] || sr.requestKind,
        `حالة الطلب: ${statusAr}`,
        labPart,
        pricingExtra,
        det.slice(0, 160),
      ]
        .filter(Boolean)
        .join(' — ');
      portalActivities.push({
        id: `service-request:${String(sr._id)}`,
        at: sr.createdAt,
        bucketAr: 'طلب أرسلته',
        headlineAr: 'طلب خدمة أو نقاط من حسابي',
        detailAr: detailAr || '—',
        pointsDelta: null,
        amountSar: null,
      });
    }

    for (const lc of linkClickRows) {
      const ct = lc.campaignId?.title || 'حملة';
      portalActivities.push({
        id: `link:${String(lc._id)}`,
        at: lc.createdAt,
        bucketAr: 'زيارة رابط',
        headlineAr: 'ضغط على رابط تتبّع حملة',
        detailAr: `${ct} · ${campaignBillingSubscriberHintAr(lc.campaignId?.billingKind)}`,
        pointsDelta: null,
        amountSar: null,
      });
    }

    portalActivities.sort((a, b) => new Date(b.at) - new Date(a.at));

    res.json({
      ok: true,
      profile: {
        displayName: user.name || '',
        city: user.city || '',
        phoneMasked: maskSaudiPhoneLast4(user.phone),
        /** جوال مخزَّن للنموذج الداخلي في حسابي فقط — لا يُعرَّض إلا ضمن جلسة الدخول */
        phoneNorm: user.phone ? String(user.phone).trim() : '',
        socialPlatformLabel: PLATFORM_META_BY_ID[user.socialPlatform || 'instagram']?.labelAr || user.socialPlatform,
        usernameOnPlatform: user.instagramUsername ? `@${user.instagramUsername}` : '',
        memberSince: user.createdAt,
        requestedServiceLabels: (user.requestedServices || []).map(
          (id) => SIGNUP_SERVICE_LABEL_BY_ID[id] || id
        ),
        signupNotes: user.signupNotes || '',
      },
      points: user.points ?? 0,
      interactionsTotal,
      interactions,
      payments: paymentsOut,
      totalPaidSar,
      pointsPerCampaignInteraction: POINTS_PER_INTERACTION,
      defaultPointsPerInteraction: POINTS_PER_INTERACTION,
      serviceRequests: serviceRequestsOut,
      activityLog: portalActivities.slice(0, 85),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** طلب رمز لدخول «حسابي» بالجوال (التجريبي: يُطبَع في سجل السيرفر؛ SMS في الإنتاج) */
app.post('/api/portal/login/send-code', async (req, res) => {
  try {
    const ph = normalizeSignupPhone(req.body?.phone);
    if (ph.error) return res.status(400).json({ error: ph.error });
    const user = await User.findOne({ phone: ph.phone }).select('_id phone').lean();
    const payload = {
      ok: true,
      message:
        'إذا كان الرقم مسجّلاً لدينا، يمكنك الآن إدخال رمز التحقق الذي يصل لهذا الرقم (في الوضع التجريبي يظهر الرمز في سجل الخادم فقط)',
    };
    if (!user) {
      return res.json(payload);
    }
    const code = randomOtp6();
    portalLoginOtpByPhone.set(ph.phone, {
      code,
      exp: Date.now() + 10 * 60 * 1000,
      userId: String(user._id),
    });
    console.log(`[PORTAL-LOGIN] phone=${ph.phone} user=${user._id} code=${code}`);
    if (String(process.env.DEV_OTP_HINT || '').trim() === '1') {
      payload.devCode = code;
    }
    res.json(payload);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** تأكيد الرمز والحصول على رمز الدخول لصفحة «حسابي» */
app.post('/api/portal/login/verify', async (req, res) => {
  try {
    const ph = normalizeSignupPhone(req.body?.phone);
    if (ph.error) return res.status(400).json({ error: ph.error });
    const code = String(req.body?.code ?? '').trim().replace(/\D/g, '');
    if (code.length !== 6) {
      return res.status(400).json({ error: 'أدخل رمز التحقق المكوّن من ٦ أرقام' });
    }
    const pending = portalLoginOtpByPhone.get(ph.phone);
    if (!pending || pending.exp < Date.now()) {
      return res.status(400).json({ error: 'انتهت صلاحية الرمز أو لم يُطلب بعد — اضغط «إرسال رمز» أولاً' });
    }
    if (code !== pending.code) {
      return res.status(400).json({ error: 'الرمز غير صحيح' });
    }
    portalLoginOtpByPhone.delete(ph.phone);
    const user = await User.findOne({ phone: ph.phone }).select('portalToken').lean();
    if (!user || !user.portalToken) {
      return res.status(404).json({ error: 'تعذّر إكمال الدخول' });
    }
    appendPortalSessionCookie(res, user.portalToken, req);
    res.json({ ok: true, portalToken: user.portalToken });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** ملخص حملة لصاحب العلامة — يحميه المعامل السري t (campaignPortalToken) */
app.get('/api/campaign-portal/summary', async (req, res) => {
  try {
    const t = String(req.query.t || '').trim();
    if (!t || t.length < 24) {
      return res.status(400).json({ error: 'أضف المعامل t من رابط التتبع' });
    }
    const c = await Campaign.findOne({ campaignPortalToken: t }).lean();
    if (!c) return res.status(404).json({ error: 'الرابط غير صالح' });

    const linkClicksTotal = await LinkClick.countDocuments({ campaignId: c._id });

    let linkedClientServiceRequestId = '';
    let linkedClientServiceRequestSummaryAr = '';
    if (c.linkedClientServiceRequestId) {
      linkedClientServiceRequestId = String(c.linkedClientServiceRequestId);
      const csr = await ClientServiceRequest.findById(c.linkedClientServiceRequestId)
        .select('title details fulfillmentStatus createdAt')
        .lean();
      if (csr) {
        const dt = csr.createdAt ? new Date(csr.createdAt).toLocaleDateString('ar-SA') : '';
        const titleLine = String(csr.title || '').trim() || String(csr.details || '').trim().slice(0, 80);
        const statusMap = { pending: 'قيد المعالجة', completed: 'تم التنفيذ', cancelled: 'ملغاة' };
        const st = statusMap[csr.fulfillmentStatus] || csr.fulfillmentStatus || '';
        linkedClientServiceRequestSummaryAr = [titleLine ? `«${titleLine}»` : '', dt ? `تاريخ الطلب: ${dt}` : '', st ? `حالة الطلب: ${st}` : '']
          .filter(Boolean)
          .join(' — ');
      }
    }

    const bk = c.billingKind || 'unspecified';
    const billingKindAr =
      bk === 'paid' ? 'مدفوعة (بحسب تصنيف المنصة)' : bk === 'free' ? 'مجانية أو شراكة غير مدفوعة' : 'غير محدد — للتوضيح مع فريق المنصة';

    res.json({
      ok: true,
      campaign: {
        title: c.title || '',
        status: c.status || '',
        targetCount: c.targetCount ?? null,
        currentCount: c.currentCount ?? 0,
        interactionType: c.type || '',
        destinationKind: c.destinationKind || 'social',
        billingKind: bk,
        billingKindAr,
        linkedClientServiceRequestId,
        linkedClientServiceRequestSummaryAr,
      },
      stats: {
        linkClicksTotal,
      },
      disclaimer:
        'التقدّم يعتمد على تسجيل المشاركات في منصة «رواد الأعمال» وعلى ضغطات رابط التتبع؛ لا يثبت ذلك وحده كل تفاعل على شبكة خارجية أو متجر بدون تكامل إضافي.',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** تسجيل دفعة للمشترك (لوحة الفريق — يدوي حتى ربط بوابة دفع) */
app.post('/api/admin/users/:id/payments', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'معرّف المشترك غير صالح' });
    }
    const amountSar = Number(req.body?.amountSar);
    if (!Number.isFinite(amountSar) || amountSar <= 0 || amountSar > 1e7) {
      return res.status(400).json({ error: 'amountSar يجب أن يكون رقماً موجباً بالريال السعودي (مثال: 99.5)' });
    }
    const label = req.body?.label != null ? String(req.body.label).trim().slice(0, 120) : '';
    const note = req.body?.note != null ? String(req.body.note).trim().slice(0, 500) : '';
    const u = await User.findById(id).lean();
    if (!u) return res.status(404).json({ error: 'المشترك غير موجود' });
    const payment = await SubscriberPayment.create({
      userId: id,
      amountSar,
      label,
      note,
    });
    res.status(201).json({ ok: true, payment });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** إضافة نقاط للمشترك (مكافئة فقط — تراكمية وليست تعويضاً بنقاط سالبة) */
app.post('/api/admin/users/:id/points-grants', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'معرّف المشترك غير صالح' });
    }
    const n = Math.floor(Number(req.body?.points));
    if (!Number.isFinite(n) || n < 1 || n > 100000) {
      return res.status(400).json({
        error: 'عدد النقاط يجب أن يكون عدداً صحيحاً بين 1 و 100000',
      });
    }
    const note = req.body?.note != null ? String(req.body.note).trim().slice(0, 500) : '';
    const uExists = await User.findById(id).select('_id').lean();
    if (!uExists) return res.status(404).json({ error: 'المشترك غير موجود' });

    const grant = await SubscriberPointsGrant.create({
      userId: id,
      points: n,
      note,
    });
    try {
      const u = await User.findByIdAndUpdate(id, { $inc: { points: n } }, { new: true }).lean();
      if (!u) {
        await SubscriberPointsGrant.deleteOne({ _id: grant._id });
        return res.status(404).json({ error: 'المشترك غير موجود' });
      }
      res.status(201).json({
        ok: true,
        grant: { id: String(grant._id), points: n, note, createdAt: grant.createdAt },
        pointsTotal: u.points ?? 0,
      });
    } catch (err) {
      await SubscriberPointsGrant.deleteOne({ _id: grant._id });
      throw err;
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** تسجيل دفعة من عميل الحملة (وارد للمنصة — داخلي) */
app.post('/api/admin/advertiser-payments', async (req, res) => {
  try {
    const rawCamp = req.body?.campaignId;
    let campaignId = null;
    if (rawCamp != null && String(rawCamp).trim()) {
      const cid = String(rawCamp).trim();
      if (!mongoose.isValidObjectId(cid)) {
        return res.status(400).json({
          error: 'معرّف الحملة غير صالح — اتركه فارغاً أو الصق معرّفاً صحيحاً من الجدول',
        });
      }
      const c = await Campaign.findById(cid).select('_id').lean();
      if (!c) return res.status(404).json({ error: 'الحملة غير موجودة' });
      campaignId = c._id;
    }
    const amountSar = Number(req.body?.amountSar);
    if (!Number.isFinite(amountSar) || amountSar <= 0 || amountSar > 1e9) {
      return res.status(400).json({ error: 'amountSar يجب أن يكون رقماً موجباً بالريال السعودي' });
    }
    const clientLabel =
      req.body?.clientLabel != null ? String(req.body.clientLabel).trim().slice(0, 160) : '';
    const label = req.body?.label != null ? String(req.body.label).trim().slice(0, 120) : '';
    const note = req.body?.note != null ? String(req.body.note).trim().slice(0, 500) : '';
    const payment = await AdvertiserPayment.create({
      campaignId,
      clientLabel,
      amountSar,
      label,
      note,
    });
    res.status(201).json({ ok: true, payment });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/advertiser-payments', async (_req, res) => {
  try {
    const rows = await AdvertiserPayment.find()
      .sort({ createdAt: -1 })
      .limit(150)
      .populate('campaignId', 'title type dealSummary')
      .lean();
    const sumAgg = await AdvertiserPayment.aggregate([{ $group: { _id: null, t: { $sum: '$amountSar' } } }]);
    res.json({
      ok: true,
      totalReceivedSar: sumAgg.length ? sumAgg[0].t : 0,
      payments: rows.map((r) => ({
        _id: r._id,
        amountSar: r.amountSar,
        clientLabel: r.clientLabel || '',
        label: r.label || '',
        note: r.note || '',
        createdAt: r.createdAt,
        campaignId: r.campaignId && r.campaignId._id ? String(r.campaignId._id) : '',
        campaignTitle: r.campaignId?.title || '',
      })),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/campaigns', async (req, res) => {
  try {
    const {
      title,
      type,
      city,
      interest,
      targetCount,
      link,
      destinationKind,
      destinationLabel,
      dealSummary,
      billingKind: bkIn,
      pointsPerInteraction: ppiIn,
      targetUserId: targetUserIdRaw,
      linkedClientServiceRequestId: linkedReqRaw,
    } = req.body;
    const kinds = ['social', 'website', 'store', 'other'];
    const dk = kinds.includes(destinationKind) ? destinationKind : 'social';
    const dl =
      destinationLabel != null ? String(destinationLabel).trim().slice(0, 160) : '';
    const ds =
      dealSummary != null ? String(dealSummary).trim().slice(0, 280) : '';
    const billingKinds = ['paid', 'free', 'unspecified'];
    const billingKind = billingKinds.includes(bkIn) ? bkIn : 'unspecified';
    const parsedPpi = parsePointsPerInteractionInput(ppiIn);
    if (!parsedPpi.ok) return res.status(400).json({ error: parsedPpi.error });
    const pointsPerInteraction = parsedPpi.value;

    let targetUserId = null;
    const tuid =
      targetUserIdRaw != null && String(targetUserIdRaw).trim() ? String(targetUserIdRaw).trim() : '';
    if (tuid) {
      if (!mongoose.isValidObjectId(tuid)) {
        return res.status(400).json({ error: 'معرّف المشترك المستهدَف غير صالح' });
      }
      const tuExists = await User.exists({ _id: tuid });
      if (!tuExists) {
        return res.status(400).json({ error: 'المشترك المستهدَف غير موجود في المنصة' });
      }
      targetUserId = tuid;
    }

    const linkedResolved = await resolveLinkedClientServiceRequestId(linkedReqRaw, targetUserId);
    if (!linkedResolved.ok) return res.status(400).json({ error: linkedResolved.error });

    const statusRaw = req.body?.status;
    const status =
      statusRaw && ['active', 'completed'].includes(String(statusRaw).trim())
        ? String(statusRaw).trim()
        : 'active';

    const campaign = await createCampaignWithPortalToken({
      title,
      type,
      city,
      interest,
      targetCount,
      link: normalizeStoredLink(link),
      destinationKind: dk,
      destinationLabel: dl || undefined,
      dealSummary: ds || undefined,
      billingKind,
      status,
      pointsPerInteraction: pointsPerInteraction != null ? pointsPerInteraction : undefined,
      ...(targetUserId ? { targetUserId } : {}),
      ...(linkedResolved.value ? { linkedClientServiceRequestId: linkedResolved.value } : {}),
    });
    res.status(201).json({ ok: true, campaign });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * تحديث حقول حملة (جزئي): نقاط المشاركة، العنوان، الرابط، الحالة، …
 * لا يغيّر نقاط التفاعلات المسجّلة سابقاً عند تعديل pointsPerInteraction.
 */
app.patch('/api/campaigns/:campaignId', async (req, res) => {
  try {
    const { campaignId } = req.params;
    if (!mongoose.isValidObjectId(campaignId)) {
      return res.status(400).json({ error: 'معرّف الحملة غير صالح' });
    }
    const exists = await Campaign.exists({ _id: campaignId });
    if (!exists) return res.status(404).json({ error: 'الحملة غير موجودة' });

    const body = req.body || {};
    const $set = {};
    const $unset = {};

    if ('pointsPerInteraction' in body) {
      const parsed = parsePointsPerInteractionInput(body.pointsPerInteraction);
      if (!parsed.ok) return res.status(400).json({ error: parsed.error });
      if (parsed.value == null) $unset.pointsPerInteraction = '';
      else $set.pointsPerInteraction = parsed.value;
    }

    const kinds = ['social', 'website', 'store', 'other'];
    const billingKinds = ['paid', 'free', 'unspecified'];
    const typeAllow = new Set(['visit', 'like', 'follow', 'comment']);
    const statusAllow = new Set(['active', 'completed']);

    if ('title' in body) $set.title = String(body.title ?? '').trim();
    if ('type' in body) {
      const t = String(body.type ?? '').trim();
      if (!typeAllow.has(t)) return res.status(400).json({ error: 'نوع التفاعل غير صالح' });
      $set.type = t;
    }
    if ('city' in body) $set.city = String(body.city ?? '').trim();
    if ('interest' in body) $set.interest = String(body.interest ?? '').trim();
    if ('targetCount' in body) {
      const tc = Math.floor(Number(body.targetCount));
      if (!Number.isFinite(tc) || tc < 1) {
        return res.status(400).json({ error: 'الهدف (عدد) يجب أن يكون عدداً صحيحاً لا يقل عن 1' });
      }
      $set.targetCount = tc;
    }
    if ('link' in body) $set.link = normalizeStoredLink(body.link);
    if ('destinationKind' in body) {
      const dk = String(body.destinationKind ?? '').trim();
      if (!kinds.includes(dk)) return res.status(400).json({ error: 'وجهة الحملة غير صالحة' });
      $set.destinationKind = dk;
    }
    if ('destinationLabel' in body) {
      $set.destinationLabel = String(body.destinationLabel ?? '').trim().slice(0, 160);
    }
    if ('dealSummary' in body) {
      $set.dealSummary = String(body.dealSummary ?? '').trim().slice(0, 280);
    }
    if ('billingKind' in body) {
      const bk = String(body.billingKind ?? '').trim();
      if (!billingKinds.includes(bk)) return res.status(400).json({ error: 'التصنيف التجاري غير صالح' });
      $set.billingKind = bk;
    }
    if ('status' in body) {
      const st = String(body.status ?? '').trim();
      if (!statusAllow.has(st)) return res.status(400).json({ error: 'حالة الحملة غير صالحة (active أو completed)' });
      $set.status = st;
    }
    if ('targetUserId' in body) {
      const raw = body.targetUserId;
      const tuid = raw != null && String(raw).trim() ? String(raw).trim() : '';
      if (!tuid) {
        $unset.targetUserId = '';
      } else {
        if (!mongoose.isValidObjectId(tuid)) {
          return res.status(400).json({ error: 'معرّف المشترك المستهدَف غير صالح' });
        }
        const tuExists = await User.exists({ _id: tuid });
        if (!tuExists) {
          return res.status(400).json({ error: 'المشترك المستهدَف غير موجود في المنصة' });
        }
        $set.targetUserId = tuid;
      }
    }

    if ('linkedClientServiceRequestId' in body) {
      const raw = body.linkedClientServiceRequestId;
      const linkRaw = raw != null && String(raw).trim() ? String(raw).trim() : '';
      let tuForLink;
      if ('targetUserId' in body) {
        const tr = body.targetUserId;
        const tuid = tr != null && String(tr).trim() ? String(tr).trim() : '';
        tuForLink = tuid || undefined;
      } else {
        const campLean = await Campaign.findById(campaignId).select('targetUserId').lean();
        tuForLink = campLean?.targetUserId ? String(campLean.targetUserId) : undefined;
      }
      const resolved = await resolveLinkedClientServiceRequestId(linkRaw || null, tuForLink);
      if (!resolved.ok) return res.status(400).json({ error: resolved.error });
      if (resolved.value) $set.linkedClientServiceRequestId = resolved.value;
      else $unset.linkedClientServiceRequestId = '';
    }

    const mongoUp = {};
    if (Object.keys($set).length) mongoUp.$set = $set;
    if (Object.keys($unset).length) mongoUp.$unset = $unset;
    if (!mongoUp.$set && !mongoUp.$unset) {
      return res.status(400).json({ error: 'لا حقول للتحديث' });
    }

    const campaign = await Campaign.findByIdAndUpdate(campaignId, mongoUp, { new: true }).lean();
    if (!campaign) return res.status(404).json({ error: 'الحملة غير موجودة' });
    res.json({ ok: true, campaign });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** حذف حملة مع إزالة التفاعلات والأكواد والضغطات المرتبطة؛ دفعات عميل الحملة تُفصل (campaignId = null) */
app.delete('/api/campaigns/:campaignId', async (req, res) => {
  try {
    const { campaignId } = req.params;
    if (!mongoose.isValidObjectId(campaignId)) {
      return res.status(400).json({ error: 'معرّف الحملة غير صالح' });
    }
    const camp = await Campaign.findById(campaignId).select('_id').lean();
    if (!camp) return res.status(404).json({ error: 'الحملة غير موجودة' });
    const cid = camp._id;
    const interactions = await Interaction.find({ campaignId: cid }).lean();
    for (const ix of interactions) {
      const pts = interactionPointsStored(ix);
      if (!pts || !ix.userId) continue;
      await User.collection.updateOne(
        { _id: ix.userId },
        [{ $set: { points: { $max: [0, { $subtract: [{ $ifNull: ['$points', 0] }, pts] }] } } }]
      );
    }
    await Interaction.deleteMany({ campaignId: cid });
    await CampaignClaim.deleteMany({ campaignId: cid });
    await LinkClick.deleteMany({ campaignId: cid });
    await AdvertiserPayment.updateMany({ campaignId: cid }, { $set: { campaignId: null } });
    await Campaign.deleteOne({ _id: cid });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * تسجيل تفاعل مشترك في حملة — للوحة الفريق ولصفحة «حسابي»
 * @returns {{ ok: true, message: string } | { ok: false, status: number, message: string }}
 */
async function tryRegisterCampaignInteraction(userId, campaignId, verificationCode) {
  if (!mongoose.isValidObjectId(userId) || !mongoose.isValidObjectId(campaignId)) {
    return { ok: false, status: 400, message: 'معرّف المستخدم أو الحملة غير صالح' };
  }
  const vc = verificationCode != null ? String(verificationCode).trim().toUpperCase() : '';
  const claimRequired = await CampaignClaim.exists({ userId, campaignId });
  if (claimRequired) {
    if (!vc) {
      return {
        ok: false,
        status: 400,
        message: 'كود التحقق مطلوب لهذه الحملة — أدخل الكود الذي أصدره الفريق لحسابك.',
      };
    }
    const claim = await CampaignClaim.findOne({ userId, campaignId, code: vc }).lean();
    if (!claim) {
      return { ok: false, status: 400, message: 'كود التحقق لا يطابق هذا المشترك وهذه الحملة' };
    }
  } else if (vc) {
    const claim = await CampaignClaim.findOne({ userId, campaignId, code: vc }).lean();
    if (!claim) {
      return { ok: false, status: 400, message: 'كود التحقق لا يطابق هذا المشترك وهذه الحملة' };
    }
  }
  const campaign = await Campaign.findById(campaignId);
  if (!campaign || campaign.status === 'completed') {
    return { ok: false, status: 400, message: 'الحملة غير متاحة' };
  }

  const pts = effectiveCampaignPoints(campaign);

  let inserted;
  try {
    inserted = await Interaction.create({ userId, campaignId, pointsAwarded: pts });
  } catch (err) {
    if (err && err.code === 11000) {
      return { ok: false, status: 400, message: 'سبق التسجيل في هذه الحملة لهذا المستخدم' };
    }
    throw err;
  }

  try {
    const userUpdate = await User.findByIdAndUpdate(userId, { $inc: { points: pts } });
    if (!userUpdate) {
      await Interaction.deleteOne({ _id: inserted._id });
      return { ok: false, status: 400, message: 'المستخدم غير موجود' };
    }
    campaign.currentCount += 1;
    if (campaign.currentCount >= campaign.targetCount) {
      campaign.status = 'completed';
    }
    await campaign.save();
  } catch (err) {
    await Interaction.deleteOne({ _id: inserted._id });
    throw err;
  }

  return { ok: true, message: `تم التسجيل (+${pts} نقاط)` };
}

function portalCampaignDestinationAr(kind) {
  const m = {
    social: 'تواصل اجتماعي',
    website: 'موقع إلكتروني',
    store: 'متجر',
    other: 'أخرى',
  };
  return m[kind] || m.other;
}

/** حملات يمكن للمشترك إعلان مشاركته فيها من «حسابي» */
app.get('/api/portal/campaigns-for-participation', async (req, res) => {
  try {
    const t = portalTokenFromReq(req);
    if (!t || t.length < 24) {
      return res.status(400).json({ error: 'معامل الدخول مطلوب' });
    }
    const user = await User.findOne({ portalToken: t }).lean();
    if (!user) return res.status(404).json({ error: 'الجلسة غير صالحة' });

    const userId = user._id;
    const joined = await Interaction.find({ userId }).select('campaignId').lean();
    const joinedIds = new Set(joined.map((x) => String(x.campaignId)));

    /** «نشطة» فقط كانت تستثني وثائق قديمة بلا حقل status؛ $nin يضمّنها ما لم تُعلَم مكتملة */
    const camps = await Campaign.find({ status: { $nin: ['completed'] } })
      .sort({ _id: -1 })
      .limit(120)
      .populate('targetUserId', 'socialPlatform instagramUsername name')
      .lean();

    function campaignMatchesAudience(c) {
      const cCity = String(c.city || '').trim();
      const cInt = String(c.interest || '').trim();
      let cityOk = false;
      let interestOk = false;
      if (cCity && user.city) {
        cityOk = new RegExp(`^${escapeRegExp(cCity)}$`, 'i').test(String(user.city).trim());
      }
      if (cInt && Array.isArray(user.interests) && user.interests.length) {
        interestOk = user.interests.some((i) => new RegExp(escapeRegExp(cInt), 'i').test(String(i)));
      }
      return cityOk || interestOk;
    }

    const available = camps.filter((c) => {
      if (joinedIds.has(String(c._id))) return false;
      const tgt = Number(c.targetCount);
      if (Number.isFinite(tgt) && tgt > 0 && (c.currentCount ?? 0) >= tgt) return false;
      return true;
    });

    const availableIds = available.map((c) => c._id);
    const issuedClaims = await CampaignClaim.find({ userId, campaignId: { $in: availableIds } })
      .select('campaignId')
      .lean();
    const participationLinkLockedIds = new Set(issuedClaims.map((x) => String(x.campaignId)));

    const rows = available.map((c) => ({
      id: String(c._id),
      title: c.title || '',
      type: c.type || '',
      typeAr: campaignInteractionTypeAr(c.type),
      city: c.city || '',
      interest: c.interest || '',
      destinationKind: c.destinationKind || 'social',
      destinationKindAr: portalCampaignDestinationAr(c.destinationKind || 'social'),
      destinationLabel: (c.destinationLabel || '').trim(),
      link: participationLinkLockedIds.has(String(c._id)) ? '' : c.link || '',
      participationLinkLocked: participationLinkLockedIds.has(String(c._id)),
      participationUrl: participationLinkLockedIds.has(String(c._id))
        ? ''
        : participationTrackedPortalHref(req, c, userId),
      participationManualNoteAr: portalCompletionNoteArForCampaignType(c.type),
      participationOpenLabelAr: portalParticipationOpenLabelAr(c.type),
      participationReturnHintAr: portalParticipationReturnHintAr(c.type, c.destinationKind),
      targetSubscriberHint: portalCampaignTargetSubscriberHint(c.targetUserId),
      progressLabel: `${c.currentCount ?? 0} / ${Number.isFinite(Number(c.targetCount)) ? c.targetCount : '—'}`,
      recommended: campaignMatchesAudience(c),
      billingHintAr: campaignBillingSubscriberHintAr(c.billingKind),
      pointsAwarded: effectiveCampaignPoints(c),
    }));

    rows.sort((a, b) => Number(b.recommended) - Number(a.recommended));

    res.json({
      ok: true,
      defaultPointsPerInteraction: POINTS_PER_INTERACTION,
      campaigns: rows,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** تسجيل مشاركة من صفحة «حسابي» */
app.post('/api/portal/register-interaction', async (req, res) => {
  try {
    const t = portalTokenFromReq(req, req.body?.t);
    const campaignId = req.body?.campaignId;
    const verificationCode = req.body?.verificationCode;
    if (!t || t.length < 24) {
      return res.status(400).json({ error: 'رمز الدخول إلى حسابي مطلوب' });
    }
    const user = await User.findOne({ portalToken: t }).select('_id').lean();
    if (!user) return res.status(404).json({ error: 'الجلسة غير صالحة' });

    const result = await tryRegisterCampaignInteraction(user._id, campaignId, verificationCode);
    if (!result.ok) return res.status(result.status).json({ error: result.message });
    res.json({ ok: true, message: result.message });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** بعد إصدار الفريق كوداً لمشترك على حملة: التحقق من الكود ثم إرجاع رابط التفاعل (لا يُعرض في قائمة الحملات قبل التحقق) */
app.post('/api/portal/verify-participation-code', async (req, res) => {
  try {
    const t = portalTokenFromReq(req, req.body?.t);
    const campaignId = req.body?.campaignId;
    const verificationCode = req.body?.verificationCode;
    if (!t || t.length < 24) {
      return res.status(400).json({ error: 'رمز الدخول إلى حسابي مطلوب' });
    }
    if (!mongoose.isValidObjectId(campaignId)) {
      return res.status(400).json({ error: 'معرّف الحملة غير صالح' });
    }
    const vc = verificationCode != null ? String(verificationCode).trim().toUpperCase() : '';
    if (!vc) {
      return res.status(400).json({ error: 'أدخل كود التحقق' });
    }
    const user = await User.findOne({ portalToken: t }).select('_id').lean();
    if (!user) return res.status(404).json({ error: 'الجلسة غير صالحة' });

    const claim = await CampaignClaim.findOne({ userId: user._id, campaignId, code: vc }).lean();
    if (!claim) {
      return res.status(400).json({ error: 'الكود غير صحيح أو لم يُصدَر لك على هذه الحملة' });
    }
    const campaign = await Campaign.findById(campaignId)
      .populate('targetUserId', 'socialPlatform instagramUsername name')
      .lean();
    if (!campaign || campaign.status === 'completed') {
      return res.status(400).json({ error: 'الحملة غير متاحة' });
    }

    const participationUrl = participationTrackedPortalHref(req, campaign, user._id);
    res.json({ ok: true, participationUrl: participationUrl || '' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/interactions', async (req, res) => {
  try {
    const { userId, campaignId, verificationCode } = req.body;
    const result = await tryRegisterCampaignInteraction(userId, campaignId, verificationCode);
    if (!result.ok) return res.status(result.status).json({ message: result.message });
    res.json({ ok: true, message: result.message });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function digitsOnlyPhone(q) {
  let s = String(q ?? '').trim();
  s = s.replace(/[\u0660-\u0669]/g, (ch) => String(ch.charCodeAt(0) - 0x0660));
  s = s.replace(/[\u06f0-\u06f9]/g, (ch) => String(ch.charCodeAt(0) - 0x06f0));
  return s.replace(/\D/g, '');
}

/** أنماط بحث متعددة حتى يطابق التخزين 9665xxxxxxxx والإدخال 05… أو 966… أو 5… فقط */
function buildPhoneSearchCondition(rawQuery) {
  const digits = digitsOnlyPhone(rawQuery);
  if (digits.length < 2) return null;
  const candidates = new Set([digits]);
  let local = digits;
  if (local.startsWith('966')) local = local.slice(3);
  if (local.startsWith('0')) local = local.slice(1);
  candidates.add(local);
  if (local.length >= 2 && local.startsWith('5')) {
    candidates.add(`966${local}`);
  }
  const uniq = [...new Set([...candidates].filter((c) => c.length >= 2))];
  if (!uniq.length) return null;
  if (uniq.length === 1) return { phone: { $regex: uniq[0] } };
  return { $or: uniq.map((c) => ({ phone: { $regex: c } })) };
}

app.get('/api/users', async (req, res) => {
  try {
    const phoneCond = buildPhoneSearchCondition(req.query.phone);
    const filter = phoneCond ? phoneCond : {};
    const limit = phoneCond ? 200 : 50;
    const users = await User.find(filter).sort({ _id: -1 }).limit(limit).lean();
    res.json({ ok: true, users });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** تصدير مشتركين لـ Excel / تحليل — UTF-8 مع BOM */
app.get('/api/users/export.csv', async (req, res) => {
  try {
    const phoneCond = buildPhoneSearchCondition(req.query.phone);
    const filter = phoneCond ? phoneCond : {};
    const users = await User.find(filter).sort({ _id: -1 }).limit(5000).lean();
    const header = [
      'id',
      'portal_token',
      'social_platform',
      'instagram_username',
      'phone',
      'gender',
      'city',
      'interests',
      'points',
      'instagram_verified',
      'phone_verified',
      'name',
      'requested_services',
      'signup_notes',
      'created_at',
      'updated_at',
    ];
    const lines = [header.join(',')];
    for (const u of users) {
      lines.push(
        [
          csvEscapeCell(String(u._id)),
          csvEscapeCell(u.portalToken ?? ''),
          csvEscapeCell(u.socialPlatform || 'instagram'),
          csvEscapeCell(u.instagramUsername ?? ''),
          csvEscapeCell(u.phone ?? ''),
          csvEscapeCell(u.gender ?? ''),
          csvEscapeCell(u.city ?? ''),
          csvEscapeCell(Array.isArray(u.interests) ? u.interests.join(';') : ''),
          csvEscapeCell(u.points ?? 0),
          csvEscapeCell(u.instagramVerified ? 'yes' : 'no'),
          csvEscapeCell(u.phoneVerified ? 'yes' : 'no'),
          csvEscapeCell(u.name ?? ''),
          csvEscapeCell(Array.isArray(u.requestedServices) ? u.requestedServices.join(';') : ''),
          csvEscapeCell(u.signupNotes ?? ''),
          csvEscapeCell(u.createdAt ? new Date(u.createdAt).toISOString() : ''),
          csvEscapeCell(u.updatedAt ? new Date(u.updatedAt).toISOString() : ''),
        ].join(',')
      );
    }
    const csv = `\ufeff${lines.join('\n')}`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="users-roaed-export.csv"');
    res.send(csv);
  } catch (err) {
    res.status(500).type('text/plain').send(err.message);
  }
});

/** تحديث حقول تحقق يدوية (لوحة المشرف المبدئية — لاحقاً JWT) */
app.patch('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'معرّف غير صالح' });
    }
    const body = req.body || {};
    const patch = {};
    if (typeof body.instagramVerified === 'boolean') patch.instagramVerified = body.instagramVerified;
    if (typeof body.phoneVerified === 'boolean') patch.phoneVerified = body.phoneVerified;
    if (Object.keys(patch).length === 0) {
      return res.status(400).json({ error: 'أرسل instagramVerified أو phoneVerified (boolean)' });
    }
    const user = await User.findByIdAndUpdate(id, { $set: patch }, { new: true }).lean();
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ ok: true, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** حذف مشترك من لوحة الفريق — يزيل التفاعلات والأكواد والضغطات والمدفوعات المرتبطة به */
app.delete('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'معرّف غير صالح' });
    }
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ error: 'قاعدة البيانات غير متصلة' });
    }
    const user = await User.findById(id).select('phone').lean();
    if (!user) return res.status(404).json({ error: 'المشترك غير موجود' });

    const uid = user._id;
    await Promise.all([
      Interaction.deleteMany({ userId: uid }),
      CampaignClaim.deleteMany({ userId: uid }),
      LinkClick.deleteMany({ userId: uid }),
      SubscriberPayment.deleteMany({ userId: uid }),
      SubscriberPointsGrant.deleteMany({ userId: uid }),
    ]);
    await ClientServiceRequest.updateMany({ userId: uid }, { $set: { userId: null, linkedViaPortal: false } });

    if (user.phone) portalLoginOtpByPhone.delete(user.phone);
    phoneOtpPending.delete(id);

    await User.findByIdAndDelete(uid);
    res.json({ ok: true, message: 'تم حذف المشترك' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** طلب رمز تحقق جوال (تجريبي: يُسجَّل في الطرفية؛ ضع DEV_OTP_HINT=1 في .env لإظهاره في JSON) */
app.post('/api/users/:id/phone-otp/send', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'معرّف غير صالح' });
    }
    const user = await User.findById(id).lean();
    if (!user) return res.status(404).json({ error: 'غير موجود' });
    if (!user.phone) return res.status(400).json({ error: 'لا يوجد جوال مسجّل لهذا المشترك' });
    const code = randomOtp6();
    phoneOtpPending.set(id, { code, exp: Date.now() + 10 * 60 * 1000 });
    console.log(`[OTP] user=${id} phone=${user.phone} code=${code}`);
    const payload = {
      ok: true,
      message: 'في الإنتاج يُرسل الرمز عبر SMS — الآن يظهر في سجل السيرفر فقط',
    };
    if (String(process.env.DEV_OTP_HINT || '').trim() === '1') {
      payload.devCode = code;
    }
    res.json(payload);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users/:id/phone-otp/verify', async (req, res) => {
  try {
    const { id } = req.params;
    const { code } = req.body || {};
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'معرّف غير صالح' });
    }
    const pending = phoneOtpPending.get(id);
    if (!pending || pending.exp < Date.now()) {
      return res.status(400).json({ error: 'انتهت صلاحية الرمز أو لم يُطلب بعد — اضغط «إرسال رمز» أولاً' });
    }
    if (String(code ?? '').trim() !== pending.code) {
      return res.status(400).json({ error: 'الرمز غير صحيح' });
    }
    phoneOtpPending.delete(id);
    const user = await User.findByIdAndUpdate(id, { $set: { phoneVerified: true } }, { new: true }).lean();
    res.json({ ok: true, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/campaigns', async (req, res) => {
  try {
    const phoneCond = buildPhoneSearchCondition(req.query.phone);
    if (phoneCond) {
      const matchedUsers = await User.find(phoneCond).select('_id').lean();
      const uids = matchedUsers.map((u) => u._id);
      if (!uids.length) {
        return res.json({ ok: true, campaigns: [] });
      }
      const [fromClaims, fromIx] = await Promise.all([
        CampaignClaim.distinct('campaignId', { userId: { $in: uids } }),
        Interaction.distinct('campaignId', { userId: { $in: uids } }),
      ]);
      const idStrs = new Set([...fromClaims, ...fromIx].map((id) => String(id)));
      const ids = [...idStrs].filter((id) => mongoose.isValidObjectId(id));
      if (!ids.length) {
        return res.json({ ok: true, campaigns: [] });
      }
      const campaigns = await Campaign.find({ _id: { $in: ids } })
        .sort({ _id: -1 })
        .limit(100)
        .lean();
      return res.json({ ok: true, campaigns });
    }
    const campaigns = await Campaign.find().sort({ _id: -1 }).limit(50).lean();
    res.json({ ok: true, campaigns });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** حملة واحدة (لوحة الفريق — تعديل النموذج) */
app.get('/api/campaigns/:campaignId', async (req, res) => {
  try {
    const { campaignId } = req.params;
    if (!mongoose.isValidObjectId(campaignId)) {
      return res.status(400).json({ error: 'معرّف الحملة غير صالح' });
    }
    const campaign = await Campaign.findById(campaignId).lean();
    if (!campaign) return res.status(404).json({ error: 'الحملة غير موجودة' });
    res.json({ ok: true, campaign });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** إصدار أو إرجاع كود تحقق لمشترك على حملة (يظهر في لوحة الأكواد) */
app.post('/api/campaigns/:campaignId/verification-code', async (req, res) => {
  try {
    const { campaignId } = req.params;
    const { userId } = req.body || {};
    if (!mongoose.isValidObjectId(campaignId) || !mongoose.isValidObjectId(userId)) {
      return res.status(400).json({ error: 'معرّف الحملة أو المشترك غير صالح' });
    }
    const campaign = await Campaign.findById(campaignId).lean();
    if (!campaign || campaign.status === 'completed') {
      return res.status(400).json({ error: 'الحملة غير متاحة أو منتهية' });
    }
    const user = await User.findById(userId).lean();
    if (!user) return res.status(400).json({ error: 'المشترك غير موجود' });

    let claim = await CampaignClaim.findOne({ userId, campaignId });
    if (!claim) {
      let created = null;
      for (let i = 0; i < 8; i++) {
        const code = makeVerificationCode();
        try {
          created = await CampaignClaim.create({ userId, campaignId, code });
          break;
        } catch (err) {
          if (err.code !== 11000) throw err;
        }
      }
      if (!created) return res.status(500).json({ error: 'تعذّر إنشاء كود فريد' });
      claim = created;
    }

    res.json({
      ok: true,
      code: claim.code,
      campaignId: String(campaign._id),
      campaignTitle: campaign.title || '',
      destinationKind: campaign.destinationKind || 'social',
      postLink: campaign.link || '',
      instagramUsername: user.instagramUsername || '',
      socialPlatform: user.socialPlatform || 'instagram',
      socialPlatformLabel: PLATFORM_META_BY_ID[user.socialPlatform || 'instagram']?.labelAr || 'إنستغرام',
      instruction: verificationInstructionForCampaign(campaign),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** قائمة من طلبوا كوداً لحملة معيّنة */
app.get('/api/admin/campaigns/:campaignId/verification-codes', async (req, res) => {
  try {
    const { campaignId } = req.params;
    if (!mongoose.isValidObjectId(campaignId)) {
      return res.status(400).json({ error: 'معرّف حملة غير صالح' });
    }
    const claims = await CampaignClaim.find({ campaignId }).sort({ createdAt: -1 }).populate('userId').lean();
    const rows = claims.map((c) => {
      const u = c.userId;
      const plat = u?.socialPlatform || 'instagram';
      const handle = u?.instagramUsername ?? '';
      return {
        code: c.code,
        createdAt: c.createdAt,
        userId: u ? String(u._id) : '',
        instagramUsername: handle,
        socialPlatform: plat,
        socialPlatformLabel: PLATFORM_META_BY_ID[plat]?.labelAr || '',
        profileUrl: profileUrlForPlatform(plat, handle),
        city: u?.city ?? '',
        phone: u?.phone ?? '',
      };
    });
    res.json({ ok: true, claims: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** ضغطات مسار /go قبل التحويل لرابط الحملة */
app.get('/api/admin/campaigns/:campaignId/link-clicks', async (req, res) => {
  try {
    const { campaignId } = req.params;
    if (!mongoose.isValidObjectId(campaignId)) {
      return res.status(400).json({ error: 'معرّف حملة غير صالح' });
    }
    const clicks = await LinkClick.find({ campaignId })
      .sort({ createdAt: -1 })
      .limit(500)
      .populate('userId')
      .lean();
    const rows = clicks.map((row) => {
      const u = row.userId;
      const plat = u?.socialPlatform || 'instagram';
      const handle = u?.instagramUsername ?? '';
      return {
        createdAt: row.createdAt,
        userId: u ? String(u._id) : '',
        instagramUsername: handle,
        socialPlatform: plat,
        socialPlatformLabel: PLATFORM_META_BY_ID[plat]?.labelAr || '',
        profileUrl: profileUrlForPlatform(plat, handle),
        ip: row.ip || '',
        userAgent: row.userAgent || '',
      };
    });
    res.json({ ok: true, clicks: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** قالب نص عربي + رابط عام لتبليغ المشتركين يدوياً (واتساب، SMS خارجية…) */
app.get('/api/admin/campaigns/:campaignId/outreach', async (req, res) => {
  try {
    const { campaignId } = req.params;
    if (!mongoose.isValidObjectId(campaignId)) {
      return res.status(400).json({ error: 'معرّف حملة غير صالح' });
    }
    const camp = await Campaign.findById(campaignId).lean();
    if (!camp) return res.status(404).json({ error: 'الحملة غير موجودة' });

    const base = resolvedPublicBaseUrl(req);
    const genericUrl = `${base}/go?c=${campaignId}`;
    const safeTitle = String(camp.title || 'حملة').replace(/\r?\n/g, ' ').trim().slice(0, 220);
    const pts = effectiveCampaignPoints(camp);
    const messageTemplateAr =
      `مرحباً 👋\n\n` +
      `من منصة رواد الأعمال — فرصة مشاركة:\n«${safeTitle}»\n\n` +
      `• افتح الرابط التالي وتابع المطلوب على صفحة الحملة.\n` +
      `• بعد تنفيذ المشاركة، سيتحقق فريقنا منها؛ عند التسجيل تُضاف لك +${pts} نقطة في حسابك.\n\n` +
      `🔗 رابط المشاركة:\n${genericUrl}\n\n` +
      `📌 لمتابعة النقاط والمدفوعات استخدم صفحة «حسابي» عبر الرابط الخاص الذي وصلك عند التسجيل — لا تشاركه علناً.\n\n` +
      `شكراً لمشاركتك معنا`;

    const canAudienceCsv = !!(String(camp.city || '').trim() || String(camp.interest || '').trim());

    res.json({
      ok: true,
      campaignId,
      campaignTitle: safeTitle,
      city: camp.city || '',
      interest: camp.interest || '',
      genericTrackingUrl: genericUrl,
      pointsPerInteraction: pts,
      messageTemplateAr,
      canAudienceCsv,
      audienceCsvHint: canAudienceCsv
        ? 'يمكن تنزيل ملف CSV بالمشتركين الذين تطابق مدينتهم و/أو اهتمامهم حقول هذه الحملة لاستخدام أدوات إرسال جماعي.'
        : 'أضف «المدينة» أو «الاهتمام» للحملة لتفعيل تصدير قائمة بالمطابقين.',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * مشتركون مرشّحون حسب مدينة و/أو اهتمام الحملة — لتجهيز رسائل جماعية (لا إرسال تلقائي من الخادم)
 */
app.get('/api/admin/campaigns/:campaignId/matching-subscribers.csv', async (req, res) => {
  try {
    const { campaignId } = req.params;
    if (!mongoose.isValidObjectId(campaignId)) {
      return res.status(400).type('text/plain').send('Invalid campaign id');
    }
    const camp = await Campaign.findById(campaignId).lean();
    if (!camp) return res.status(404).type('text/plain').send('Campaign not found');

    const city = String(camp.city || '').trim();
    const interest = String(camp.interest || '').trim();
    const query = {};
    if (city) query.city = new RegExp(`^${escapeRegExp(city)}$`, 'i');
    if (interest) {
      query.interests = {
        $elemMatch: { $regex: new RegExp(escapeRegExp(interest), 'i') },
      };
    }
    if (!city && !interest) {
      return res
        .status(400)
        .type('text/plain; charset=utf-8')
        .send(
          'املأ حقلا «المدينة» و/أو «الاهتمام» في الحملة لتصفية المشتركين، أو استخدم تصدير المشتركين الكامل من الأعلى.'
        );
    }

    const users = await User.find(query).sort({ _id: -1 }).limit(2500).lean();
    const base = resolvedPublicBaseUrl(req);
    const header = [
      'user_id',
      'phone',
      'name',
      'city',
      'interests',
      'my_account_url',
      'personal_tracking_url',
    ];
    const lines = [header.join(',')];
    for (const u of users) {
      const uid = String(u._id);
      const tok = u.portalToken ? encodeURIComponent(u.portalToken) : '';
      const myAcc = tok ? `${base}/my-account?t=${tok}` : '';
      const personalGo = `${base}/go?c=${campaignId}&u=${uid}`;
      lines.push(
        [
          csvEscapeCell(uid),
          csvEscapeCell(u.phone ?? ''),
          csvEscapeCell(u.name ?? ''),
          csvEscapeCell(u.city ?? ''),
          csvEscapeCell(Array.isArray(u.interests) ? u.interests.join(';') : ''),
          csvEscapeCell(myAcc),
          csvEscapeCell(personalGo),
        ].join(',')
      );
    }
    const csv = `\ufeff${lines.join('\n')}`;
    const safeName = String(camp.title || 'campaign')
      .replace(/[^\w\u0600-\u06FF.-]+/g, '_')
      .slice(0, 40);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="audience-${safeName}-${campaignId}.csv"`
    );
    res.send(csv);
  } catch (err) {
    res.status(500).type('text/plain').send(err.message);
  }
});

app.get('/api/admin/stats', async (_req, res) => {
  const totalUsers = await User.countDocuments();
  const activeCampaigns = await Campaign.countDocuments({ status: 'active' });
  const totalInteractions = await Interaction.countDocuments();
  const agg = await User.aggregate([{ $group: { _id: null, total: { $sum: '$points' } } }]);
  const advAgg = await AdvertiserPayment.aggregate([{ $group: { _id: null, total: { $sum: '$amountSar' } } }]);
  res.json({
    totalUsers,
    activeCampaigns,
    totalInteractions,
    totalPointsCirculating: agg.length ? agg[0].total : 0,
    totalAdvertiserRevenueSar: advAgg.length ? advAgg[0].total : 0,
  });
});

const basePort = Number(process.env.PORT) || 5000;
const MAX_PORT_TRIES = 30;

function listenFrom(port, triesLeft) {
  const srv = http.createServer(app);
  srv.on('error', (err) => {
    if (err.code === 'EADDRINUSE' && triesLeft > 0) {
      console.warn(`[WARN] Port ${port} is busy — trying ${port + 1}...`);
      listenFrom(port + 1, triesLeft - 1);
    } else {
      console.error('[ERR]', err.message || err);
      process.exit(1);
    }
  });
  srv.listen(port, '0.0.0.0', () => {
    listeningPort = port;
    console.log(`[OK] Server: http://127.0.0.1:${port}`);
    if (TEAM_PANEL_SECRET_PATH) {
      console.log(`[OK] العملاء (الجذر → اشتراك): http://127.0.0.1:${port}/join`);
      console.log(`[OK] لوحة الطاقم — لا تنشر الرابط: http://127.0.0.1:${port}/${TEAM_PANEL_SECRET_PATH}`);
    } else {
      console.log(`[OK] اشتراك العملاء: http://127.0.0.1:${port}/join`);
      console.log(`[OK] لوحة الطاقم: http://127.0.0.1:${port}/ (أو /panel → نفس الصفحة)`);
    }
    if (TEAM_PANEL_PASSWORD) {
      console.log('[OK] TEAM_PANEL_PASSWORD: مفعّل — واجهات الإدارة والـ API الحساسة تتطلب تسجيل الدخول');
    }
    console.log(`[OK] اشتراك المشتركين: http://127.0.0.1:${port}/join`);
    console.log(`[OK] دخول المشترك فقط: http://127.0.0.1:${port}/subscriber-login`);
    console.log(`[OK] حسابي (جلسة المشترك بعد الدخول): http://127.0.0.1:${port}/my-account`);
    console.log(`[OK] تتبع حملة (للمعلن): http://127.0.0.1:${port}/campaign-track?t=<رمز_من_جدول_الحملات>`);
    console.log(`[OK] Health: http://127.0.0.1:${port}/health`);
    console.log('');
    console.log(`>>> انسخ هذا الرابط في المتصفح — الرقم بعد : هو المنفذ (${port})`);
    console.log(`>>> COPY THIS URL: http://127.0.0.1:${port}/`);
    console.log('');
    if (port !== basePort) {
      console.warn(`[NOTE] Port ${basePort} was busy; using ${port} instead.`);
    }
  });
}

listenFrom(basePort, MAX_PORT_TRIES);
