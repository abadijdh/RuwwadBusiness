@echo off

chcp 65001 >nul

cd /d "%~dp0"

title رواد الاعمال - تشغيل PM2 خلفية



echo أوقف أي تشغيل عادي أولاً ^(npm start / nodemon في نافذة أخرى^) ثم تابع.
echo تشغيل السيرفر في الخلفية ^(يمكنك إغلاق هذه النافذة بعد ظهور online في الجدول^)

echo إذا ظهر خطأ "pm2 not found" شغّل من هذا المجلد مرة واحدة: npm install

echo.

call npm run pm2:start

echo.

echo ————————————————————————————

echo السيرفر يعمل تحت الاسم: roaed-api

echo السجلات:     npm run pm2:logs   أو   npx pm2 logs roaed-api

echo إيقاف:       إيقاف-خلفية.bat

echo الحالة:      npx pm2 status

echo ملاحظة: بعد إعادة تشغيل الجهاز لن يبدأ PM2 تلقائياً إلا إذا ضبطت جدولة المهام أو شغّلت هذا الملف من جديد.

echo ————————————————————————————

pause

