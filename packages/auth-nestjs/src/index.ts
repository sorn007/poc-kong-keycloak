// @central/auth-nestjs — Central Auth SDK สำหรับ NestJS service (ADR-008)
//
// จุดเดียวของ "Authentication policy" ที่ทุก service ใช้ร่วมกัน — เดิม guard/verifier อยู่
// ในแต่ละ service จน policy ตกหล่นเมื่ออัปเดต ตอนนี้แก้ที่นี่ที่เดียว แล้ว service ติดตั้งรุ่นใหม่
//
//   • ตรวจ central token — RS256 allowlist + iss allowlist + aud ของ service + exp (+ tolerance 5s)
//   • ตรวจ legacy token (HS256) ช่วง migration — Dual Validation เลือก validator จาก allowlist
//   • gateway-trust — ยืนยันว่า request ผ่าน Kong (plugin central-apikey) มาจริง
//   • session/ticket liveness — ตรวจกับ ID Portal ว่าตั๋วที่ session ผูกไว้ยังไม่ถูก revoke
//   • Central API Key — ตรวจ key สำหรับ MCP / protocol ที่ไม่มี Bearer header
//
// ขอบเขต: แพ็กเกจนี้ทำเฉพาะ **Authentication** (ใครคือ principal + ถือ scope อะไร)
// Authorization ระดับ business (tenant, บริษัท, order/project ของใคร) ต้องอยู่ที่ service เองเสมอ
//
// ใช้งาน (สร้างครั้งเดียวตอน startup ของ service):
//   export const auth = createAuth({ central: {...}, legacy: {...} });
//   @UseGuards(auth.guards.central, auth.guards.scope) @RequireScope('orders.read')
import {
  CentralAuthGuard,
  DualAuthGuard,
  LegacyAuthGuard,
  RequireScope,
  ScopeGuard,
} from './guards';
import { LegacyVerifier, type LegacyVerifierOptions } from './legacy';
import { CentralVerifier, type CentralVerifierOptions } from './verifier';

/** Version — รุ่นของ SDK (service log ค่านี้ตอน startup เพื่อรู้ว่า deploy รุ่นใด) */
export const VERSION = '0.1.0';

export interface AuthOptions {
  central: CentralVerifierOptions;
  /** ไม่ส่ง = ปิด legacy path ของ service (เป้าหมายหลัง migration เสร็จ) */
  legacy?: LegacyVerifierOptions;
}

export interface CentralAuth {
  /** verify(token) → Principal (ใช้กับ session cookie หรือ endpoint ที่ไม่ผ่าน guard) */
  central: CentralVerifier;
  legacy?: LegacyVerifier;
  guards: {
    central: CentralAuthGuard;
    scope: ScopeGuard;
    dual?: DualAuthGuard;
    legacy?: LegacyAuthGuard;
  };
}

/** createAuth — สร้าง verifier + guard instances ของ service (JWKS client สร้างครั้งเดียวตรงนี้) */
export function createAuth(options: AuthOptions): CentralAuth {
  const central = new CentralVerifier(options.central);
  const centralGuard = new CentralAuthGuard(central);
  const scope = new ScopeGuard();
  if (!options.legacy) return { central, guards: { central: centralGuard, scope } };

  const legacy = new LegacyVerifier(options.legacy);
  const legacyGuard = new LegacyAuthGuard(legacy);
  return {
    central,
    legacy,
    guards: {
      central: centralGuard,
      scope,
      legacy: legacyGuard,
      dual: new DualAuthGuard(centralGuard, legacyGuard),
    },
  };
}

/** LegacyGuards — guard ของช่วง migration (มีเฉพาะเมื่อ createAuth ได้รับ option `legacy`) */
export interface LegacyGuards {
  legacy: LegacyAuthGuard;
  dual: DualAuthGuard;
}

/**
 * requireLegacy — คืน guard ของ legacy/dual แบบไม่ optional สำหรับ route ที่ยังต้องใช้
 * ถ้า service ปิด legacy ไปแล้ว (ไม่ส่ง option `legacy`) จะ throw ทันทีตอนโหลด module
 * พร้อมบอกสาเหตุ — ใช้แทนการ assert `!` ที่ปิดบัง type จนไปจบด้วย error
 * "Invalid guard passed to @UseGuards()" ของ Nest ตอนถอด legacy block โดยลืมลบ route
 */
export function requireLegacy(auth: CentralAuth): LegacyGuards {
  if (!auth.guards.legacy || !auth.guards.dual) {
    throw new Error(
      'central-auth: a route needs the legacy/dual guards, but createAuth() was called without a "legacy" option — remove the legacy routes or re-enable the option',
    );
  }
  return { legacy: auth.guards.legacy, dual: auth.guards.dual };
}

// ── token verification ──
export { CentralVerifier, type CentralVerifierOptions } from './verifier';
export { LegacyVerifier, type LegacyVerifierOptions } from './legacy';
export { normalizePrincipal, type Principal, type TokenClaims } from './principal';
// ── Nest guards ──
export { CentralAuthGuard, LegacyAuthGuard, DualAuthGuard, ScopeGuard, RequireScope } from './guards';
// ── gateway-trust ──
export { GATEWAY_HEADERS, verifyGatewayTrust, type GatewayPrincipal } from './gateway';
// ── ticket liveness ──
export {
  TicketGuard,
  clearSessionCookies,
  sessionCookieNames,
  SSO_COOKIE,
  SSO_BOUND_COOKIE,
  type TicketGuardOptions,
} from './ticket';
// ── Central API Key ──
export { ApiKeyVerifier, type ApiKeyPrincipal, type ApiKeyVerifierOptions } from './apikey';
