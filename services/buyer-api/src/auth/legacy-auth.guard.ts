import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { config } from '../config';

// Legacy Guard — จำลอง middleware เดิมของ Buyer ที่ออก/ตรวจ JWT เองด้วย shared secret (HS256)
// ใช้เฉพาะช่วง migration (Dual Validation) และจะถูกปิดใน Phase สุดท้าย
@Injectable()
export class LegacyAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest();
    const header = req.headers.authorization;

    const match =
      typeof header === 'string' ? /^Bearer ([^\s]+)$/i.exec(header) : null;
    if (!match) {
      throw new UnauthorizedException({ error: 'missing_access_token' });
    }

    try {
      const payload = jwt.verify(match[1], config.legacySecret, {
        algorithms: ['HS256'],
      }) as jwt.JwtPayload;

      if (payload.iss !== config.legacyIssuer) {
        throw new Error('legacy_issuer_mismatch');
      }

      req.auth = {
        subject: payload.sub,
        clientId: 'legacy-buyer',
        principalType: 'user',
        scopes: typeof payload.scope === 'string' ? payload.scope.split(' ') : ['orders.read'],
        tokenId: payload.jti ?? null,
        tenantId: payload.tenant_id ?? null,
        issuer: payload.iss,
      };
      return true;
    } catch {
      throw new UnauthorizedException({ error: 'invalid_legacy_token' });
    }
  }
}
