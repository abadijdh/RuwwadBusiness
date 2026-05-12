# تشغيل الإنتاج في حاوية — مثال: docker build -t roaed . && docker run -p 5000:5000 --env-file .env roaed
FROM node:20-alpine
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js ./
COPY instagram-oauth.js ./
COPY public ./public/

ENV NODE_ENV=production
EXPOSE 5000

CMD ["node", "server.js"]
