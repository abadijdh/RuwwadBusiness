/** تشغيل السيرفر في الخلفية عبر PM2 — لا تعتمد على إبقاء نافذة CMD مفتوحة */
module.exports = {
  apps: [
    {
      name: 'roaed-api',
      script: 'server.js',
      cwd: __dirname,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '400M',
      env: {
        NODE_ENV: 'production',
      },
      /** ضع MONGO_URI وPUBLIC_URL في السيرفر أو عبر `pm2 ecosystem` بعد التعديل المحلي */
    },
  ],
};
