# Buyer API (NestJS) — multi-stage build
# Central Auth SDK (@central/auth-nestjs ใน packages/auth-nestjs) มาผ่าน build context เพิ่ม
# (compose: additional_contexts.auth-nestjs) แล้ว build ใน image — เครื่อง host ไม่ต้อง build เอง

# ── stage 1: build @central/auth-nestjs ──
FROM node:22-alpine AS sdk
COPY --from=auth-nestjs . /sdk/
WORKDIR /sdk
RUN npm ci && npm run build

# ── stage 2: build Buyer ──
FROM node:22-alpine AS build
# วาง SDK ตาม path สัมพัทธ์ที่ package.json ของ Buyer ชี้ (file:../../packages/auth-nestjs)
COPY --from=sdk /sdk/package.json /app/packages/auth-nestjs/package.json
COPY --from=sdk /sdk/dist /app/packages/auth-nestjs/dist
WORKDIR /app/services/buyer-api
# .npmrc (install-links=true) → ติดตั้ง SDK เป็นสำเนาจริงใน node_modules:
#   จำเป็น ไม่งั้น @nestjs/common ของ SDK จะเป็นคนละ instance กับของ service (401 จะกลายเป็น 500)
COPY package.json .npmrc ./
RUN npm install
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=3000
COPY --from=build /app/services/buyer-api/node_modules ./node_modules
COPY --from=build /app/services/buyer-api/dist ./dist
EXPOSE 3000
CMD ["node", "dist/main.js"]
