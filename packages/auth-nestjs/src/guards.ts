/// <reference types="reflect-metadata" />
import {
  ForbiddenException,
  SetMetadata,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import type { LegacyVerifier } from './legacy';
import type { Principal } from './principal';
import type { CentralVerifier } from './verifier';

const REQUIRED_SCOPE_KEY = 'requiredScope';

/** RequireScope — ประกาศ scope ที่ endpoint ต้องการ (Authorization) ใช้คู่กับ ScopeGuard */
export const RequireScope = (scope: string) =>
  SetMetadata(REQUIRED_SCOPE_KEY, scope);

interface AuthedRequest {
  headers: { authorization?: string };
  auth?: Principal;
}

function bearerToken(req: AuthedRequest): string | null {
  const header = req.headers.authorization;
  const match =
    typeof header === 'string' ? /^Bearer ([^\s]+)$/i.exec(header) : null;
  return match ? match[1] : null;
}

function unauthorized(req: AuthedRequest): never {
  throw new UnauthorizedException({ error: 'missing_access_token' });
}

/**
 * Guards ของ Central Auth SDK — ใช้โดยส่ง "instance" ให้ @UseGuards
 * (สร้างผ่าน createAuth ตอน startup ของ service — ไม่ต้องลงทะเบียน provider ใน Nest module)
 * ลำดับของ route: guard ตรวจ token (Authentication) → ScopeGuard (Authorization ระดับ API) → handler
 * สิทธิ์ระดับ tenant/business ตรวจที่ handler ของ service เอง
 */

/** CentralAuthGuard — ตรวจ token ที่ออกโดย ID แล้วตั้ง req.auth */
export class CentralAuthGuard implements CanActivate {
  constructor(readonly verifier: CentralVerifier) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req: AuthedRequest = context.switchToHttp().getRequest();
    const token = bearerToken(req);
    if (!token) unauthorized(req);
    try {
      req.auth = await this.verifier.verify(token);
      return true;
    } catch {
      throw new UnauthorizedException({ error: 'invalid_access_token' });
    }
  }
}

/** LegacyAuthGuard — จำลอง middleware เดิมของ service (JWT ที่ออกเองด้วย shared secret) */
export class LegacyAuthGuard implements CanActivate {
  constructor(readonly verifier: LegacyVerifier) {}

  canActivate(context: ExecutionContext): boolean {
    const req: AuthedRequest = context.switchToHttp().getRequest();
    const token = bearerToken(req);
    if (!token) unauthorized(req);
    try {
      req.auth = this.verifier.verify(token);
      return true;
    } catch {
      throw new UnauthorizedException({ error: 'invalid_legacy_token' });
    }
  }
}

/**
 * DualAuthGuard — รองรับทั้ง central token (เป้าหมาย) และ legacy token (ช่วง migration)
 * ความสัมพันธ์ iss → validator ต้องเป็น "allowlist คงที่" เท่านั้น — peek iss/alg แบบไม่ verify
 * เพื่อเลือก validator แล้วจึง verify แบบเข้ม · ห้าม fallback จาก central ไป legacy
 * (กัน Cross-Issuer Token Confusion)
 */
export class DualAuthGuard implements CanActivate {
  constructor(
    private readonly central: CentralAuthGuard,
    private readonly legacy: LegacyAuthGuard,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req: AuthedRequest = context.switchToHttp().getRequest();
    const token = bearerToken(req);
    if (!token) unauthorized(req);

    // Peek — อ่านอย่างเดียว ยังไม่เชื่ออะไรจาก payload
    let iss: string | undefined;
    let alg: string | undefined;
    try {
      const decoded = jwt.decode(token, { complete: true }) as
        | { header?: { alg?: string }; payload?: { iss?: string } }
        | null;
      iss = decoded?.payload?.iss;
      alg = decoded?.header?.alg;
    } catch {
      throw new UnauthorizedException({ error: 'unsupported_token' });
    }

    // allowlist: iss → validator + alg ที่โปรไฟล์นั้นต้องใช้
    const validators: Record<string, { kind: 'central' | 'legacy'; alg: string }> = {
      [this.central.verifier.issuer]: { kind: 'central', alg: 'RS256' },
      [this.legacy.verifier.issuer]: { kind: 'legacy', alg: 'HS256' },
    };
    const validator = iss ? validators[iss] : undefined;
    if (!validator || alg !== validator.alg) {
      // iss ไม่อยู่ใน allowlist หรือ alg ไม่ตรงโปรไฟล์ → ปฏิเสธทันที
      throw new UnauthorizedException({ error: 'unsupported_token' });
    }

    return validator.kind === 'central'
      ? this.central.canActivate(context)
      : this.legacy.canActivate(context);
  }
}

/** ScopeGuard — Authorization ระดับ API: ตรวจ scope ตาม @RequireScope ของ endpoint */
export class ScopeGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const required = Reflect.getMetadata(
      REQUIRED_SCOPE_KEY,
      context.getHandler(),
    ) as string | undefined;
    if (!required) return true;

    const req: AuthedRequest = context.switchToHttp().getRequest();
    const scopes: string[] = req.auth?.scopes ?? [];
    if (!scopes.includes(required)) {
      throw new ForbiddenException({ error: 'insufficient_scope', required });
    }
    return true;
  }
}
