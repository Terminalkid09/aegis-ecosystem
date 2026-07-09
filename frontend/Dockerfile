FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install --legacy-peer-deps
COPY . .
# For a production build:
# RUN npm run build

# Stage 2: Runtime (Using a simple node server or nginx)
# For now, we'll keep using the node server but with a non-root user
FROM node:20-alpine
WORKDIR /app
COPY --from=build /app /app

# Security: Run as non-root user
RUN addgroup -S aegis && adduser -S aegis -G aegis
RUN chown -R aegis:aegis /app
USER aegis

ENV WATCHPACK_POLLING=true
EXPOSE 3000
CMD ["npm", "start"]
