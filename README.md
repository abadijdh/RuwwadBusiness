# RuwwadBusiness — رواد الأعمال

منصة رواد الأعمال: لوحة تحكم للفريق، بوابة المشتركين، الحملات والنقاط وتتبع الأداء. خادم **Node.js (Express)** مع **MongoDB (Mongoose)** وواجهات ثابتة في المجلد `public/`.

## المتطلبات

- **Node.js** 18 أو أحدث (يُفضَّل 20 للتوافق مع Docker أدناه).
- اتصال بـ **MongoDB** (مثل MongoDB Atlas أو خادم محلي).

## التشغيل السريع (محلياً)

1. استنسخ المستودع ثم من جذر المشروع:
   ```bash
   npm ci
   ```
   (أو `npm install` للتطوير اليومي.)

2. أنشئ ملف البيئة من المثال ولا ترفع الأسرار إلى Git:
   ```bash
   copy .env.example .env
   ```
   على Linux/macOS: `cp .env.example .env`

3. عدّل `.env` على الأقل:
   - **`MONGO_URI`**: سلسلة اتصال MongoDB كاملة.
   - **`PORT`**: منفذ الخادم (افتراضي `5000` إن لم تُعرّفه).
   - **`PUBLIC_URL`**: عند النشر على دومين حقيقي، الرابط العام بدون شرطة مائلة أخيرة (مهم لروابط التبليغ وتصدير CSV).

4. التطوير مع إعادة التشغيل التلقائي:
   ```bash
   npm run dev
   ```

5. التشغيل بدون nodemon:
   ```bash
   npm start
   ```

ثم افتح المتصفح على العنوان الذي يطبعه الخادم (غالباً `http://127.0.0.1:5000`).

## أوامر مفيدة (`package.json`)

| الأمر | الوصف |
|--------|--------|
| `npm start` | تشغيل الإنتاج المحلي بـ `node server.js` |
| `npm run dev` | التطوير مع `nodemon` |
| `npm run pm2:start` | تشغيل عبر PM2 (`ecosystem.config.cjs`) |
| `npm run docker:build` | بناء صورة Docker |
| `npm run docker:run` | تشغيل الحاوية مع `--env-file .env` |

## Docker

```bash
docker build -t ruwwadbusiness .
docker run --rm -p 5000:5000 --env-file .env ruwwadbusiness
```

يتوقع الحاوية المتغيرات نفسها في `.env` (خصوصاً `MONGO_URI`).

## الأمان

- **لا ترفع** ملف `.env` أو `firebase-admin-sdk.json`؛ كلاهما مدرجان في `.gitignore`.
- أضف المتغيرات الجديدة إلى `.env.example` **بدون قيم سرية** مع تعليق يشرح الغرض.

## المساهمة والمزامنة

بعد التعديلات:

```bash
git status
git add .
git commit -m "وصف مختصر للتغيير"
git push
```

---

**Topics مقترحة على GitHub:** `nodejs`, `express`, `mongodb`, `mongoose`, `arabic-rtl`.
