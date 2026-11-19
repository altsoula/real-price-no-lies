FROM node:24-alpine

WORKDIR /app

COPY package.json ./
COPY src ./src
COPY public ./public

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000
ENV TRUST_PROXY=true
ENV FORCE_HTTPS=true

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 3000) + '/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

RUN chown -R node:node /app

USER node

CMD ["node", "src/server.js"]

