# ---- Build stage: install everything and build the frontend ----
FROM node:24-alpine AS build
WORKDIR /app

# Install all workspace deps (dev included, needed to build the web bundle).
COPY package.json package-lock.json* ./
COPY server/package.json server/package.json
COPY web/package.json web/package.json
RUN npm install

# Copy sources and build the frontend.
COPY tsconfig.base.json ./
COPY shared ./shared
COPY server ./server
COPY web ./web
RUN npm run build

# ---- Runtime stage: prod deps only, run the server (serves web/dist) ----
FROM node:24-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8787

COPY package.json package-lock.json* ./
COPY server/package.json server/package.json
COPY web/package.json web/package.json
RUN npm install --omit=dev

COPY tsconfig.base.json ./
COPY shared ./shared
COPY server ./server
COPY --from=build /app/web/dist ./web/dist

# Run as the built-in non-root user.
USER node

EXPOSE 8787
CMD ["npm", "run", "start"]
