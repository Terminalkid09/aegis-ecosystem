FROM node:22-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .

ARG VITE_API_URL=/api/v1
ENV VITE_API_URL=${VITE_API_URL}
RUN npm run build

FROM nginx:1.27-alpine
# Audit P3: upgrade al build time (prima i CVE Alpine con fix restavano
# nell'immagine runtime: Trivy HIGH/CRITICAL falliva).
RUN apk update && apk upgrade --no-cache
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

RUN addgroup -S aegis && adduser -S aegis -G aegis \
    && chown -R aegis:aegis /usr/share/nginx/html /var/cache/nginx /var/log/nginx /etc/nginx/conf.d \
    && touch /var/run/nginx.pid \
    && chown aegis:aegis /var/run/nginx.pid

USER aegis
EXPOSE 3000
CMD ["nginx", "-g", "daemon off;"]
