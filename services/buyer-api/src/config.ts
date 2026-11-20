// ค่า config ของ POC — ทุกค่ามาจาก env เท่านั้น
export const config = {
  port: Number(process.env.PORT ?? 3000),
  devMode: process.env.DEV_MODE === '1',

  realm: 'central',
  // ค่า iss ที่ต้องตรวจใน JWT — ต้องตรงกับ KC_HOSTNAME ที่ตั้งใน compose (localhost)
  keycloakIssuer:
    process.env.KEYCLOAK_ISSUER ?? 'http://localhost:8080/realms/central',
  // URL จริงสำหรับเรียก token/JWKS จาก "ใน" docker network (ต่างจาก issuer ที่ browser เห็น)
  keycloakInternalBase:
    process.env.KEYCLOAK_INTERNAL_BASE ?? 'http://keycloak:8080',

  // Token contract ของ Buyer API
  audience: 'buyer-api',
  clientId: 'buyer-web',
  allowedTenant: 'company_001',

  // จำลอง token เดิมของ Buyer ก่อน migration (HS256, ออกเอง)
  legacySecret:
    process.env.LEGACY_BUYER_JWT_SECRET ?? 'legacy-buyer-secret-poc',
  legacyIssuer: 'legacy-buyer',

  appFrontUrl: process.env.APP_FRONT_URL ?? 'http://localhost:3010',

  // shared secret ระหว่าง Kong กับ service — Kong แนบมาบน request ที่ตรวจ key แล้วเท่านั้น
  gatewaySecret: process.env.GATEWAY_SECRET ?? 'gateway-shared-secret-poc',
};

export const realmBaseUrl = `${config.keycloakInternalBase}/realms/${config.realm}`;
export const jwksUrl = `${realmBaseUrl}/protocol/openid-connect/certs`;
export const tokenUrl = `${realmBaseUrl}/protocol/openid-connect/token`;
