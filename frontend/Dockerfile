FROM node:26-alpine AS build
WORKDIR /app
# The lock file decides what gets installed. With package.json alone,
# `npm install` resolved the version ranges anew on every build, so the image
# held whatever was newest that day - not what CI had built, tested and audited.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
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
