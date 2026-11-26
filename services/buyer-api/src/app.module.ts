import { Module } from '@nestjs/common';
import { HomeController } from './auth/home.controller';
import { OidcController } from './auth/oidc.controller';
import { SttController } from './auth/stt.controller';
import { DevController } from './dev/dev.controller';
import { OrdersController } from './orders/orders.controller';
import { GatewayApiController } from './orders/gateway.controller';
import { McpController } from './mcp/mcp.controller';

// Guards ของ auth ไม่ต้องลงทะเบียนเป็น provider อีกแล้ว — controller ใช้ "instance" จาก
// createAuth() ใน src/central-auth.ts ผ่าน @UseGuards(auth.guards.central, auth.guards.scope)
// (JWKS client สร้างครั้งเดียวตอนโหลด module — ไม่ผูกกับ lifecycle ของ Nest DI)
@Module({
  controllers: [
    HomeController,
    OidcController,
    SttController,
    OrdersController,
    GatewayApiController,
    McpController,
    DevController,
  ],
})
export class AppModule {}
