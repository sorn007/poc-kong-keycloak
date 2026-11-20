import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

export const RequireScope = (scope: string) =>
  SetMetadata('requiredScope', scope);

// API Authorization — ตรวจว่า token มี scope ที่ endpoint ต้องการหรือไม่
// ความสัมพันธ์: scope = "อนุญาตให้เรียก API ประเภทนี้" ไม่ได้แปลว่าเข้าถึงข้อมูลทุก tenant
@Injectable()
export class ScopeGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.get<string>(
      'requiredScope',
      context.getHandler(),
    );
    if (!required) return true;

    const req = context.switchToHttp().getRequest();
    const scopes: string[] = req.auth?.scopes ?? [];
    if (!scopes.includes(required)) {
      throw new ForbiddenException({
        error: 'insufficient_scope',
        required,
      });
    }
    return true;
  }
}
