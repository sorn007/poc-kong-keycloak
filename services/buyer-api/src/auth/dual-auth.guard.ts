import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { config } from '../config';
import { CentralAuthGuard } from './central-auth.guard';
import { LegacyAuthGuard } from './legacy-auth.guard';

// ความสัมพันธ์ iss → validator ต้องเป็น "allowlist คงที่" เท่านั้น
// ห้ามใช้ค่าจาก token สร้าง key/URL แบบ dynamic และห้าม fallback จาก central ไป legacy
// (กัน Cross-Issuer Token Confusion — ดู CLAUDE.md Security Rules)
type ValidatorKind = 'central' | 'legacy';

const TRUSTED_VALIDATORS: Record<string, { kind: ValidatorKind; alg: string }> = {
  [config.keycloakIssuer]: { kind: 'central', alg: 'RS256' },
  [config.legacyIssuer]: { kind: 'legacy', alg: 'HS256' },
};

// Dual Validation Guard — รองรับทั้ง central token (เป้าหมาย) และ legacy token (ช่วง migration)
// วิธี: peek iss/alg แบบ "ไม่ verify" เพื่อเลือก validator จาก allowlist แล้วค่อย verify แบบเข้ม
@Injectable()
export class DualAuthGuard implements CanActivate {
  constructor(
    private readonly central: CentralAuthGuard,
    private readonly legacy: LegacyAuthGuard,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const header = req.headers.authorization;

    const match =
      typeof header === 'string' ? /^Bearer ([^\s]+)$/i.exec(header) : null;
    if (!match) {
      throw new UnauthorizedException({ error: 'missing_access_token' });
    }

    // Peek — อ่านอย่างเดียว ยังไม่เชื่ออะไรจาก payload
    let iss: string | undefined;
    let alg: string | undefined;
    try {
      const decoded = jwt.decode(match[1], { complete: true }) as
        | { header?: { alg?: string }; payload?: { iss?: string } }
        | null;
      iss = decoded?.payload?.iss;
      alg = decoded?.header?.alg;
    } catch {
      throw new UnauthorizedException({ error: 'unsupported_token' });
    }

    const validator = iss ? TRUSTED_VALIDATORS[iss] : undefined;
    if (!validator || alg !== validator.alg) {
      // iss ไม่อยู่ใน allowlist หรือ alg ไม่ตรงโปรไฟล์ → ปฏิเสธทันที
      throw new UnauthorizedException({ error: 'unsupported_token' });
    }

    return validator.kind === 'central'
      ? this.central.canActivate(context)
      : this.legacy.canActivate(context);
  }
}
