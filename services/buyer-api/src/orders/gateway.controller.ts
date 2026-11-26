// Gateway-trust endpoints — ทางเข้าสำหรับ **Central API Key** (ผูก scope จาก ID Portal)
// การเดินทาง: client —(apikey header)→ Kong (plugin central-apikey ตรวจกับ ID Portal
// แล้วแนบ X-Gateway-Auth + X-Central-Scopes/Owner) → ที่นี่เชื่อถือเฉพาะ request ที่
// มาพร้อม header ลับของ gateway (shared secret ระหว่าง Kong กับ service เท่านั้น)
// การตรวจ secret + อ่าน header เป็นของ SDK (@central/auth-nestjs) — service เหลือเฉพาะ
// "ประกาศว่า endpoint นี้ต้องการ scope ใด" ซึ่งเป็นกฎเฉพาะของ Buyer:
//   GET → orders.read · POST → orders.write
import {
  Controller,
  ForbiddenException,
  Get,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { verifyGatewayTrust, type GatewayPrincipal } from '@central/auth-nestjs';
import type { Request } from 'express';
import { config } from '../config';

@Controller('openapi/apikey')
export class GatewayApiController {
  // principal จาก gateway ที่เชื่อถือได้ — ไม่ผ่าน = ไม่มีหลักฐานว่า request ผ่าน Kong จริง
  private principal(req: Request): GatewayPrincipal {
    const principal = verifyGatewayTrust(req.headers, config.gatewaySecret);
    if (!principal) {
      throw new UnauthorizedException(
        'request did not come through the trusted gateway',
      );
    }
    return principal;
  }

  @Get('orders')
  list(@Req() req: Request) {
    const { owner, scopes } = this.principal(req);
    if (!scopes.includes('orders.read')) {
      throw new ForbiddenException('api key lacks orders.read');
    }
    return {
      ok: true,
      via: 'central-api-key',
      owner: owner || 'unknown',
      scopes,
      orders: [
        { orderId: 'ORD-001', company: 'company_001', total: 1500, status: 'success' },
      ],
    };
  }

  @Post('orders')
  create(@Req() req: Request) {
    const { owner, scopes } = this.principal(req);
    if (!scopes.includes('orders.write')) {
      throw new ForbiddenException('api key lacks orders.write');
    }
    return {
      ok: true,
      created: true,
      via: 'central-api-key',
      owner: owner || 'unknown',
      scopes,
    };
  }
}
