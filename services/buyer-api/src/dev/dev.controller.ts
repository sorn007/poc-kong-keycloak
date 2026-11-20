import {
  Controller,
  ForbiddenException,
  Post,
} from '@nestjs/common';
import { randomUUID } from 'crypto';
import * as jwt from 'jsonwebtoken';
import { config } from '../config';

// DEV ONLY — mint legacy token เพื่อให้ test script จำลอง "token เดิมของ Buyer"
// เปิดใช้เมื่อ DEV_MODE=1 เท่านั้น — ห้าม deploy โค้ดส่วนนี้ขึ้น production
@Controller('dev')
export class DevController {
  @Post('mint-legacy-token')
  mint() {
    if (!config.devMode) {
      throw new ForbiddenException('dev_mode_disabled');
    }
    const token = jwt.sign(
      {
        iss: config.legacyIssuer,
        sub: 'legacy-buyer-user',
        scope: 'orders.read orders.write',
        jti: randomUUID(),
      },
      config.legacySecret,
      { algorithm: 'HS256', expiresIn: '5m' },
    );
    return { token, note: 'DEV ONLY — legacy HS256 token จำลอง' };
  }
}
