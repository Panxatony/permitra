FROM node:22-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY index.html vite.config.js ./
COPY src ./src
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
# Generates the trust list for X-Forwarded-For at startup (source IP in the audit log)
COPY realip-entrypoint.sh /docker-entrypoint.d/20-realip.sh
RUN chmod +x /docker-entrypoint.d/20-realip.sh
EXPOSE 80
