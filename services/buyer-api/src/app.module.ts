import { Module } from '@nestjs/common';
import { HomeController } from './auth/home.controller';
import { CentralAuthGuard } from './auth/central-auth.guard';
import { LegacyAuthGuard } from './auth/legacy-auth.guard';
import { OidcController } from './auth/oidc.controller';
import { SttController } from './auth/stt.controller';
import { ScopeGuard } from './auth/scope.guard';
import { DualAuthGuard } from './auth/dual-auth.guard';
import { DevController } from './dev/dev.controller';
import { OrdersController } from './orders/orders.controller';
import { GatewayApiController } from './orders/gateway.controller';
import { McpController } from './mcp/mcp.controller';

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
  // Guards ที่ถูก inject เข้าหากัน (DualAuthGuard ใช้ Central/Legacy) ต้องประกาศ providers
  providers: [CentralAuthGuard, LegacyAuthGuard, DualAuthGuard, ScopeGuard],
})
export class AppModule {}
