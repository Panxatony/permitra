FROM node:22-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY index.html vite.config.js ./
COPY public ./public
COPY src ./src
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
# Generates the sign-in rate limit at startup (must run before default.conf is
# parsed, hence the lower number)
COPY ratelimit-entrypoint.sh /docker-entrypoint.d/10-ratelimit.sh
# Generates the trust list for X-Forwarded-For at startup (source IP in the audit log)
COPY realip-entrypoint.sh /docker-entrypoint.d/20-realip.sh
RUN chmod +x /docker-entrypoint.d/10-ratelimit.sh /docker-entrypoint.d/20-realip.sh
EXPOSE 80
