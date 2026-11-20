import {
  Controller,
  ForbiddenException,
  Get,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import { config } from '../config';

// Gateway-trust endpoints — ทางเข้าสำหรับ **Central API Key** (ผูก scope จาก ID Portal)
// การเดินทาง: client —(apikey header)→ Kong (plugin central-apikey ตรวจกับ ID Portal
// แล้วแนบ X-Gateway-Auth + X-Central-Scopes/Owner) → ที่นี่เชื่อถือเฉพาะ request ที่
// มาพร้อม header ลับของ gateway (shared secret ระหว่าง Kong กับ service เท่านั้น)
// และบังคับ scope ตามที่ key ถือ — ตามหลัก zero-trust ระหว่าง gateway กับ upstream:
// ไม่เชื่อ header scopes หากไม่มีหลักฐานว่าผ่าน gateway ที่ลับตรงกัน
//
// scope ที่ key ถือมาจาก ID Portal (ไม่ใช่ JWT) — ตรวจที่นี่ตาม method:
//   GET → orders.read · POST → orders.write

@Controller('openapi/apikey')
export class GatewayApiController {
  private assertGateway(req: Request) {
    const got = req.headers['x-gateway-auth'];
    const expected = config.gatewaySecret;
    if (!expected || got !== expected) {
      throw new UnauthorizedException('request did not come through the trusted gateway');
    }
  }

  private scopes(req: Request): string[] {
    const raw = req.headers['x-central-scopes'];
    return typeof raw === 'string' ? raw.split(',').map((s) => s.trim()) : [];
  }

  @Get('orders')
  list(@Req() req: Request) {
    this.assertGateway(req);
    const scopes = this.scopes(req);
    if (!scopes.includes('orders.read')) {
      throw new ForbiddenException('api key lacks orders.read');
    }
    const owner = String(req.headers['x-central-owner'] ?? 'unknown');
    return {
      ok: true,
      via: 'central-api-key',
      owner,
      scopes,
      orders: [
        { orderId: 'ORD-001', company: 'company_001', total: 1500, status: 'success' },
      ],
    };
  }

  @Post('orders')
  create(@Req() req: Request) {
    this.assertGateway(req);
    const scopes = this.scopes(req);
    if (!scopes.includes('orders.write')) {
      throw new ForbiddenException('api key lacks orders.write');
    }
    const owner = String(req.headers['x-central-owner'] ?? 'unknown');
    return {
      ok: true,
      created: true,
      via: 'central-api-key',
      owner,
      scopes,
    };
  }
}
