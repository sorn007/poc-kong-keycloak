import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { normalizePrincipal, verifyCentralToken } from './verify-central';

// Central Authentication Guard — ตรวจ token ที่ออกโดย ID (Keycloak)
// แยก Authentication (guard นี้) ออกจาก Authorization (ScopeGuard) ชัดเจน
@Injectable()
export class CentralAuthGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const header = req.headers.authorization;

    const match =
      typeof header === 'string' ? /^Bearer ([^\s]+)$/i.exec(header) : null;
    if (!match) {
      throw new UnauthorizedException({ error: 'missing_access_token' });
    }

    try {
      const payload = await verifyCentralToken(match[1]);
      req.auth = normalizePrincipal(payload);
      return true;
    } catch {
      throw new UnauthorizedException({ error: 'invalid_access_token' });
    }
  }
}
