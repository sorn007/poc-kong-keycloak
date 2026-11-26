// จุดเดียวที่ Buyer "ต่อ" เข้า Central Auth SDK (@central/auth-nestjs — ADR-008)
// policy (การตรวจ token, scope, gateway-trust, ticket liveness, API key) อยู่ที่ SDK ทั้งหมด
// service ระบุเพียง "ตัวตนของตัวเอง": issuer/audience/JWKS + legacy secret ของ Buyer
import {
  ApiKeyVerifier,
  TicketGuard,
  createAuth,
} from '@central/auth-nestjs';
import { config, jwksUrl } from './config';

// ID Portal (SSO ticket broker + API key issuer) — เรียกภายใน docker network
const idPortal = process.env.IDPORTAL_INTERNAL_BASE ?? 'http://central-id:3000';

// สร้างครั้งเดียวตอน startup ของ process (JWKS client cache + key rotation)
export const auth = createAuth({
  central: {
    issuer: config.keycloakIssuer,
    audience: config.audience, // Token Contract — Buyer รับเฉพาะ token ของตัวเอง
    jwksUrl,
  },
  // ช่วง migration เท่านั้น (Dual Validation) — ถึงเป้าหมายแล้วลบ block นี้ออก
  // guard ของ legacy/dual จะหายไปด้วย (เส้นทาง /orders/dual, /orders/legacy ต้องลบด้วย)
  legacy: {
    issuer: config.legacyIssuer,
    secret: config.legacySecret,
    clientId: 'legacy-buyer',
    defaultScopes: ['orders.read'],
  },
});

// Logout กลาง propagate — ตรวจว่าตั๋ว SSO ที่ session ผูกไว้ยังไม่ถูก revoke
export const ticketGuard = new TicketGuard({ brokerUrl: idPortal });

// Central API Key (MCP) — ตรวจกับ ID Portal ทุก request, fail-closed
export const apiKeyVerifier = new ApiKeyVerifier({
  validationUrl: `${idPortal}/apikeys/validate`,
});
