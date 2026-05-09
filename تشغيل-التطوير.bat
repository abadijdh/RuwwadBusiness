@echo off

chcp 65001 >nul

cd /d "%~dp0"

title رواد الاعمال - تطوير (إعادة تشغيل تلقائية)

echo.

echo [DEV] يعيد تشغيل السيرفر عند حفظ server.js أو أي ملف داخل مجلد public
echo [DEV] بعد تعديل .env: Ctrl+C ثم شغّل هذا الملف من جديد
echo [DEV] حدّث المتصفح F5 بعد تغيير الواجهة إن لزم

echo Stop: Ctrl+C

echo.

call npm run dev

pause


