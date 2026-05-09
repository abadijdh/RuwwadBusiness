@echo off

chcp 65001 >nul

cd /d "%~dp0"

title رواد الاعمال - إيقاف PM2



echo إيقاف السيرفر roaed-api في الخلفية...

call npm run pm2:stop

echo تم الطلب. تحقق: npx pm2 status

pause

