import 'reflect-metadata';
import cookieParser from 'cookie-parser';
import { NestFactory } from '@nestjs/core';
import type { NextFunction, Request, Response } from 'express';
import { AppModule } from './app.module';
import { config } from './config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  // POC only — หน้าจอ demo เรียก API ด้วย cookie session: ยก cookie ขึ้นเป็น Authorization
  // header (จำลองพฤติกรรม BFF) เมื่อ request ไม่ได้แนบ header มาเอง
  // Guard ยังตรวจ token เต็มรูปแบบ (JWKS/iss/aud/exp/scope) เหมือนเดิม — ไม่มีการเชื่อถือค่าใหม่
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (!req.headers.authorization && req.cookies?.['buyer_session']) {
      req.headers.authorization = `Bearer ${req.cookies['buyer_session']}`;
    }
    next();
  });
  app.enableShutdownHooks();
  await app.listen(config.port);
  // eslint-disable-next-line no-console
  console.log(
    `buyer-api (NestJS) listening :${config.port} — audience=${config.audience} devMode=${config.devMode}`,
  );
}
void bootstrap();
