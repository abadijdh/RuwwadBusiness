@echo off
chcp 65001 >nul
cd /d "%~dp0"
title رواد الاعمال - السيرفر
echo Run folder: %CD%
echo مهم: في المتصفح استخدم نفس المنفذ الذي يطبعه السيرفر ^(:5000 أو :5001^) — عدم التطابق يسبب connection refused.
echo Mode: production-like ^(no auto-restart^). For auto-restart use: تشغيل-التطوير.bat
echo After start: copy URL from terminal lines COPY THIS URL / UI:
echo Editing public/*.html often needs only browser refresh ^(F5^), not restart.
echo Stop: Ctrl+C or close this window.
echo.
call npm start
pause
