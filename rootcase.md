โดยเคสปัจจุบันคือ ตอนนี้คือ login buyer จะ redirect มา id แล้วถ้าไปเปิด cis กด login จะ redirect id ถ้าเจอ session จะ auto login ให้ แต่ปัญหาที่เจอคือ เมื่อจะทำ open api ที่จะ gen api key ไปใช้งาน ไม่สามารถทำได้เนื่องจากแต่ล่ะระบบเมื่อได้ token id ตอนredirectไปแล้วจะนำtokenนั้นไปgenเป็นtokenใหม่บนระบบของตัวเอง ตัว access token/refresh token ก็จะเกิดในระบบตัวเอง ทำให้บางครั้ง id หมดอายุไปแล้วต้อง login แต่ระบบอื่นๆยังทำงานได้อยู่ เกิดความไม่สัมพันธ์กันของระบบ login

\--------------------------------------

จากพฤติกรรมที่อธิบาย **คุณมี SSO แล้วครับ** เพราะ Buyer และ CIS ใช้ session ที่ Central ID เพื่อเข้าใช้งานโดยไม่ต้องกรอกรหัสผ่านซ้ำ แต่ **แต่ละระบบออก token และดูแล session ของตัวเอง** จึงทำให้อายุการเข้าใช้งานแยกจากกัน

ภาพปัจจุบันคือ:
```swift
                 Central ID — session กลาง
                      │
             Login / ยืนยันตัวตน
                      │
          ┌───────────┴───────────┐
        Buyer                    CIS
  access/refresh token     access/refresh token
      ของ Buyer                 ของ CIS
```

เมื่อ session ของ ID หมดอายุ Buyer และ CIS จึงยังทำงานต่อได้จาก token ของตัวเอง **อาการนี้ไม่จำเป็นต้องเป็นข้อผิดพลาดของ SSO** แต่หมายความว่ายังไม่ได้กำหนดให้ session และการเพิกถอนสิทธิ์ของทุกระบบสัมพันธ์กัน

ส่วน **Open API / API key เป็นอีกเรื่องหนึ่งที่เกี่ยวข้องกัน แต่ไม่ใช่สิ่งเดียวกัน** การมี token แยกต่อระบบไม่ได้ทำให้สร้าง API key ไม่ได้โดยตรง สิ่งที่ขาดคือข้อตกลงกลางว่า **ใครออก credential และแต่ละ API จะตรวจสอบและยอมรับ credential นั้นอย่างไร**

ผมจะแยกการแก้เป็น 2 งาน:

| งาน                           | สิ่งที่ต้องกำหนด                                                                    |
| ----------------------------- | ----------------------------------------------------------------------------------- |
| **Login ของคนผ่าน SSO**       | อายุ session, การ refresh, logout, การระงับบัญชี และผลต่อทุกระบบ                    |
| **Open API สำหรับระบบภายนอก** | ตัวตนของแอปที่เรียก, สิทธิ์ API, บริษัทที่เข้าถึงได้, อายุ credential และการ revoke |

สำหรับรูปแบบสถาปัตยกรรมเป้าหมาย ควรพิจารณาให้มี **ผู้ให้บริการยืนยันตัวตนและออกสิทธิ์ส่วนกลาง** แล้วให้ Buyer, CIS และ API อื่นตรวจสอบ token ตามมาตรฐานเดียวกัน โดยแต่ละระบบยังมี session ภายในสำหรับหน้าเว็บได้ ไม่จำเป็นต้องใช้ access token ตัวเดียวร่วมกันทุกระบบ

ตัวอย่างเส้นทาง Open API:
```
แอปของ Partner
      │ credential ของแอป
      ▼
ศูนย์กลางออก Token
      │ access token ที่ระบุสิทธิ์และ API ปลายทาง
      ▼
Buyer API / CIS API / API อื่น
      │
ตรวจ token + ตรวจสิทธิ์เข้าถึงข้อมูล
```

สำหรับ Buyer และ CIS ที่ปัจจุบันมี Middleware ตรวจสอบ `Authorization` Header ด้วย JWT ที่แต่ละระบบออกเอง เมื่อเปลี่ยนมาใช้ Centralized OAuth 2.0 / OIDC ผ่าน Central ID สิ่งที่ต้องแก้หลัก ๆ คือ เปลี่ยนจาก Local JWT Validation เป็น Central Token Validation โดยไม่จำเป็นต้องแก้ Middleware ทั้งหมดใหม่

ผมแนะนำให้ออกแบบเป็น Authentication Middleware กลางที่รองรับหลาย Issuer ในช่วง Migration และแยก Authorization ออกจาก Authentication ให้ชัดเจน

# 1. เปรียบเทียบ Middleware ปัจจุบันกับระบบใหม่

### Current Middleware

```
HTTP Request
     |
     v
Authorization: Bearer <buyer_token>
     |
     v
Buyer Middleware
     |
     +-- Verify JWT Signature (Buyer Secret)
     +-- Check Expiration
     +-- Decode User ID
     |
     v
Buyer Controller
```

ปัจจุบัน Buyer อาจมีโค้ดลักษณะนี้

```
const token = req.headers.authorization?.split(" ")[1];

const payload = jwt.verify(
  token,
  process.env.BUYER_JWT_SECRET
);

req.user = payload;
next();
```

ปัญหาคือ Middleware เชื่อถือ Token ที่ Buyer ออกเอง และไม่มีข้อมูลว่า Token นี้ถูกยกเลิกจาก Central ID หรือไม่

### Target Middleware

HTTP Request

Authorization: Bearer Access Token

Authentication Middleware

1. Extract Bearer Token
2. Validate JWT Signature ด้วย JWKS
3. Validate Issuer (`iss`)
4. Validate Audience (`aud`)
5. Validate Expiration (`exp`) และ Not Before (`nbf`)
6. สร้าง Principal / Request Context

Authorization Middleware

Scope · Role · Tenant · Resource Permission

Buyer / CIS Controller

ความแตกต่างคือ Middleware ไม่ต้องรู้ Secret ของ Central ID เพราะใช้ Public Key จาก JWKS ในการตรวจสอบ JWT ที่ลงลายเซ็นแบบ Asymmetric

# 2. ตัวอย่าง Implementation จริง (Node.js / Express)

สมมติว่า Central ID มี Endpoint ดังนี้

```
Issuer:
https://id.central.example

JWKS:
https://id.central.example/.well-known/jwks.json

Buyer API Audience:
buyer-api

CIS API Audience:
cis-api
```

ตัวอย่างนี้ใช้ Library `jose` ซึ่งรองรับ JWT Verification และ Remote JWKS

### Step 1 — Central Authentication Middleware

```
import {
  createRemoteJWKSet,
  jwtVerify
} from "jose";

const issuer = "https://id.central.example";

const JWKS = createRemoteJWKSet(
  new URL(`${issuer}/.well-known/jwks.json`)
);

export function authenticate(audience: string) {
  return async (req, res, next) => {
    try {
      const authorization = req.headers.authorization;

      if (!authorization?.startsWith("Bearer ")) {
        return res.status(401).json({
          error: "missing_access_token"
        });
      }

      const token = authorization.slice(7);

      const { payload } = await jwtVerify(token, JWKS, {
        issuer,
        audience,
        algorithms: ["RS256"]
      });

      req.auth = {
        userId: payload.sub,
        clientId: payload.client_id,
        scopes:
          typeof payload.scope === "string"
            ? payload.scope.split(" ")
            : [],
        tokenId: payload.jti
      };

      next();
    } catch {
      return res.status(401).json({
        error: "invalid_access_token"
      });
    }
  };
}
```

สิ่งที่ Middleware นี้ตรวจสอบ

- Token ต้องถูกออกโดย Central ID
- Signature ต้องถูกต้อง
- Audience ต้องตรงกับ API
- Token ต้องยังไม่หมดอายุ
- Algorithm ต้องอยู่ในรายการที่อนุญาต

JWKS จะช่วยให้ Central ID สามารถ Rotate Signing Key ได้โดยไม่ต้องนำ Secret ไป Deploy ทุก Application

ข้อควรระวัง: `jwtVerify` ไม่ได้ตรวจ Revocation โดยอัตโนมัติ และโค้ดนี้สมมติว่า Token เป็น JWT เท่านั้น ถ้า Central ID ออก Opaque Token จะต้องใช้ Introspection แทน

### Step 2 — Authorization Middleware

```
export function requireScope(requiredScope: string) {
  return (req, res, next) => {
    const scopes = req.auth?.scopes ?? [];

    if (!scopes.includes(requiredScope)) {
      return res.status(403).json({
        error: "insufficient_scope"
      });
    }

    next();
  };
}
```

### Step 3 — ใช้กับ Buyer API

```
router.get(
  "/orders",
  authenticate("buyer-api"),
  requireScope("orders.read"),
  getOrders
);
```

### Step 4 — ใช้กับ CIS API

```
router.get(
  "/projects",
  authenticate("cis-api"),
  requireScope("projects.read"),
  getProjects
);
```

ทั้ง Buyer และ CIS สามารถใช้ Middleware Library เดียวกันได้ แต่กำหนด Audience และ Scope ต่างกัน

# 3. แล้ว Middleware เดิมที่อ่าน User ID จาก Token ต้องแก้ไหม?

ต้องปรับบางส่วนครับ โดยเฉพาะถ้า Business Logic อ้างอิง Payload ของ JWT เดิมโดยตรง

ตัวอย่างเดิม:

```
req.user.id
req.user.companyId
req.user.role
```

เมื่อเปลี่ยนเป็น Central Token ควรสร้าง Standard Principal Context

```
req.auth = {
  subject: "user_123",
  clientId: "buyer-web",
  actorType: "user",
  scopes: ["orders.read"],
  tenantId: "company_001"
};
```

อย่างไรก็ตาม `tenantId` และ `actorType` ต้องมาจาก Claims ที่ตรวจสอบแล้วหรือ Trusted Authorization Lookup เท่านั้น ห้ามนำค่าจาก Header ที่ Client ส่งมาแล้วเชื่อถือทันที

ตัวอย่างการ Mapping:

| เดิม                   | ใหม่                        | วิธีจัดการ              |
| ---------------------- | --------------------------- | ----------------------- |
| `req.user.id`          | `req.auth.subject`          | Mapping Central User ID |
| `req.user.role`        | Business Permission         | Query จาก Buyer/CIS     |
| `req.user.companyId`   | Authorized Tenant           | ตรวจ Tenant Membership  |
| `req.user.permissions` | Scope + Business Permission | ตรวจสองระดับ            |
| `req.user.tokenId`     | `req.auth.tokenId`          | ใช้ Audit / Revocation  |

ผมแนะนำให้เพิ่ม Principal Adapter Layer เพื่อให้ Controller เดิมยังใช้ Interface ที่คุ้นเคยได้ในช่วง Migration โดยไม่ต้องแก้ทุก Endpoint พร้อมกัน

# 4. Middleware ต้องรองรับทั้ง User Token และ Partner Token

สำหรับ Open API จะมี Token สองประเภทหลักที่เข้ามาที่ Buyer/CIS

User Token

ผู้ใช้ Login ผ่าน SSO

M2M Token

Partner Backend เรียก API

Unified Authentication Middleware

ตรวจ Token และสร้าง Principal ตาม Token Profile

Authorization Policy

ตรวจ Actor Type + Scope + Tenant + Resource

ตัวอย่าง Token Context:

```
type Principal =
  | {
      type: "user";
      userId: string;
      clientId: string;
      scopes: string[];
    }
  | {
      type: "service";
      clientId: string;
      partnerId: string;
      scopes: string[];
    };
```

อย่าใช้เพียงการมีหรือไม่มี `sub` เพื่อตัดสินว่าเป็น User หรือ Service เพราะ Client Credentials Token ก็สามารถมี `sub` ได้เช่นกัน ควรใช้ Token Profile และ Claims ที่ Authorization Server กำหนดไว้อย่างชัดเจน

# 5. Migration Middleware โดยไม่กระทบ Production

ช่วงแรกยังต้องรองรับ Token เดิมจาก Buyer/CIS จึงควรใช้ Dual Validation

```
async function authenticateDuringMigration(req, res, next) {
  const token = extractBearerToken(req);

  // เลือก Validator จาก Issuer/Token Profile
  // ที่อยู่ใน Allowlist เท่านั้น
  const validator = selectTrustedValidator(token);

  if (!validator) {
    return res.status(401).json({
      error: "unsupported_token"
    });
  }

  const principal = await validator.verify(token);

  req.auth = normalizePrincipal(principal);

  next();
}
```

`selectTrustedValidator()` ต้องไม่เชื่อถือ `iss`, `kid` หรือ `alg` ที่ยังไม่ได้ Verify เพื่อเลือก Key หรือ URL แบบอิสระ ให้ใช้ค่าจาก Token เป็นเพียงตัวช่วยเลือก Configuration ที่กำหนดไว้ล่วงหน้าเท่านั้น และต้องป้องกัน Cross-Issuer / Cross-Audience Token Confusion

### Rollout Plan

| Phase   | Middleware Behavior                               |
| ------- | ------------------------------------------------- |
| Phase 1 | เพิ่ม Central Token Validator แต่ยังไม่เปิดใช้งาน |
| Phase 2 | รองรับ Legacy + Central Token                     |
| Phase 3 | Buyer Login เริ่มรับ Central Token                |
| Phase 4 | CIS Login เริ่มรับ Central Token                  |
| Phase 5 | Open API รับเฉพาะ Central Token                   |
| Phase 6 | ปิด Legacy Token Validator                        |

ควรเก็บ Metrics แยกตาม Token Issuer, Client ID และ Endpoint เพื่อให้ทราบว่ายังมี Consumer ใช้ Legacy Token อยู่หรือไม่ก่อนปิดระบบเดิม

# 6. ประเด็นสำคัญ: Middleware จะรู้ได้อย่างไรว่า User ถูก Logout หรือ Disable แล้ว?

ถ้า Middleware ตรวจ JWT ด้วย JWKS เพียงอย่างเดียว จะไม่รู้ว่า Token ถูก Revoke หลังจากออกไปแล้ว

มี 3 แนวทางหลัก

| วิธี                     | ข้อดี                            | ข้อจำกัด                                        |
| ------------------------ | -------------------------------- | ----------------------------------------------- |
| Short-lived JWT          | เร็ว ไม่ต้องเรียก ID ทุก Request | Revocation มี Delay ตาม Token Lifetime          |
| Token Introspection      | ตรวจสถานะ Token จากส่วนกลาง      | เพิ่ม Network Latency และ Dependency            |
| Revocation Cache / Event | เร็วและรองรับการระงับตาม SLA     | ต้องจัดการ Event Delivery และ Cache Consistency |

สำหรับ Central ผมแนะนำแนวทางผสม:

- ใช้ Short-lived JWT สำหรับ API ปกติ
- ใช้ Revocation Event เพื่อกระจายสถานะ Disable/Logout
- ใช้ Introspection หรือ Online Authorization Check กับ Operation ที่มีความเสี่ยงสูง
- ใช้ Refresh Token Rotation ที่ Central ID
- กำหนด Maximum Revocation Delay เป็น Security SLA

ไม่แนะนำให้ Middleware เรียก Central ID ทุก HTTP Request โดยไม่มีเหตุผล เพราะจะเพิ่ม Latency และทำให้ Buyer/CIS พึ่งพา Availability ของ ID มากเกินไป

# 7. สรุปว่า Developer ต้องแก้ Code ส่วนไหน

| Component                 | การเปลี่ยนแปลง                             |
| ------------------------- | ------------------------------------------ |
| Login Controller          | เปลี่ยนเป็น OIDC Authorization Code + PKCE |
| Token Exchange            | เลิกออก API Token เองหลัง Migration        |
| Refresh Endpoint          | เปลี่ยนไปใช้ Central Token Endpoint        |
| Authentication Middleware | เพิ่ม JWKS / Central Token Validation      |
| Authorization Middleware  | แยก Scope และ Business Permission          |
| Request Context           | สร้าง Standard Principal                   |
| Logout Handler            | รองรับ Back-Channel Logout                 |
| API Gateway               | ตรวจ Token, Rate Limit, Routing            |
| Configuration             | เพิ่ม Issuer, Audience, JWKS URL           |
| Monitoring                | เก็บ Token Validation / Revocation Metrics |

## Recommendation สำหรับทีมพัฒนา

ผมแนะนำให้สร้าง Shared Authentication Package เช่น `@central/auth-middleware` เพื่อให้ Buyer, CIS และระบบใหม่ใช้มาตรฐานเดียวกัน โดย Package นี้รับผิดชอบ Token Validation, Principal Normalization และ Error Handling

แต่ไม่ควรนำ Business Authorization ของ Buyer/CIS เข้า Shared Package ทั้งหมด เพราะแต่ละ Domain มีเงื่อนไขสิทธิ์ต่างกัน

คำถามสำคัญที่จะกำหนด Implementation ต่อไป: ปัจจุบัน Backend ของ Buyer และ CIS พัฒนาด้วยภาษาและ Framework อะไร เช่น Node.js (Express/NestJS), Java Spring Boot, .NET หรือ Go?

ถ้ารู้ Tech Stack ผมสามารถออกแบบ Middleware แบบ Production-ready ให้ตรงกับโครงสร้างจริง รวมถึง JWKS Cache, Token Revocation, Dual Validation, Dependency Injection และ Error Handling ได้ครับ

สำหรับ Buyer (NestJS) และ CIS (Go Fiber) ผมแนะนำให้ทำ Authentication Middleware แยก Implementation ตาม Framework แต่ใช้ Security Contract เดียวกัน จาก Central ID

ไม่จำเป็นต้องสร้าง Middleware Service กลางที่ทุก Request ต้องวิ่งไปหา เพราะจะเพิ่ม Latency และเป็น Single Point of Failure

แนวทางที่เหมาะคือ:

- Buyer (NestJS): ใช้ `Guard` สำหรับ Authentication และ Authorization
- CIS (Go Fiber): ใช้ `Middleware` สำหรับ Authentication และ Authorization
- Central ID: เป็น Authorization Server ที่ออก Access Token และเผยแพร่ Public Key ผ่าน JWKS
- Buyer/CIS: ตรวจ JWT ด้วย Public Key จาก Central ID และตรวจสิทธิ์ทางธุรกิจของตัวเอง

## 1. Target Architecture สำหรับ Tech Stack นี้

Central ID — OAuth 2.0 / OIDC

Access Token · Refresh Token · JWKS · Revocation

Buyer API

NestJS

AuthGuard

JWKS + JWT Verify

ScopeGuard

Business Permission

CIS API

Go Fiber

Auth Middleware

JWKS + JWT Verify

Scope Middleware

Business Permission

แต่ละ API ตรวจ Token ด้วย JWKS ที่ Cache ไว้ ไม่จำเป็นต้องเรียก Central ID ทุก Request

## 2. กำหนด Token Contract ร่วมกันก่อน

สมมติว่า Central ID ออก JWT Access Token แบบ RS256 โดยมี Claims ดังนี้

```
{
  "iss": "https://id.central.example",
  "sub": "user_123",
  "aud": "buyer-api",
  "client_id": "buyer-web",
  "scope": "orders.read orders.write",
  "principal_type": "user",
  "iat": 1794460000,
  "exp": 1794460900,
  "jti": "token_abc123"
}
```

ค่าตัวอย่างนี้ต้องตกลงกับทีม Central ID ก่อน Implementation โดยเฉพาะ `aud`, `scope`, `client_id` และ `principal_type` ซึ่งไม่ใช่ Claims ที่ทุก Authorization Server จะออกให้เหมือนกัน

| Claim            | Buyer           | CIS             |
| ---------------- | --------------- | --------------- |
| `iss`            | Central ID      | Central ID      |
| `aud`            | `buyer-api`     | `cis-api`       |
| `sub`            | Central User ID | Central User ID |
| `scope`          | `orders.read`   | `projects.read` |
| `principal_type` | user / service  | user / service  |

ห้ามให้ CIS ยอมรับ Token ที่ออกสำหรับ Buyer API เพียงเพราะ Signature ถูกต้อง ต้องตรวจ Audience เสมอ

## 3. Buyer — NestJS Authentication Guard

ใช้ `jose` สำหรับตรวจ JWT และดึง Public Key จาก JWKS

```
npm install jose
```

`central-auth.guard.ts`

```

import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import {
  createRemoteJWKSet,
  jwtVerify,
} from 'jose';

const issuer = 'https://id.central.example';

const jwks = createRemoteJWKSet(
  new URL(`${issuer}/.well-known/jwks.json`),
);

@Injectable()
export class CentralAuthGuard implements CanActivate {
  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {
    const req = context.switchToHttp().getRequest();

    const header = req.headers.authorization;

    const match =
      typeof header === 'string'
        ? /^Bearer ([^\s]+)$/i.exec(header)
        : null;

    if (!match) {
      throw new UnauthorizedException(
        'missing_access_token',
      );
    }

    try {
      const { payload } = await jwtVerify(
        match[1],
        jwks,
        {
          issuer,
          audience: 'buyer-api',
          algorithms: ['RS256'],
          clockTolerance: 5,
        },
      );

      if (
        typeof payload.sub !== 'string' ||
        !payload.sub
      ) {
        throw new Error('missing_subject');
      }

      req.auth = {
        subject: payload.sub,
        clientId: payload.client_id,
        principalType: payload.principal_type,
        scopes:
          typeof payload.scope === 'string'
            ? payload.scope.split(' ').filter(Boolean)
            : [],
        tokenId: payload.jti,
      };

      return true;
    } catch {
      throw new UnauthorizedException(
        'invalid_access_token',
      );
    }
  }
}

```

ตัวอย่างนี้ตรวจ Signature, Issuer, Audience, Algorithm และเวลาหมดอายุผ่าน `jwtVerify` พร้อมตรวจว่ามี Subject ตาม Contract

สำหรับ Production ควรเพิ่มการตรวจ Token Profile, Claims ที่จำเป็น, Logging, Error Classification และ Revocation Policy ด้วย

### ใช้กับ Buyer Controller

```

import {
  Controller,
  Get,
  UseGuards,
  Req,
} from '@nestjs/common';

@Controller('orders')
export class OrdersController {
  @Get()
  @UseGuards(CentralAuthGuard)
  getOrders(@Req() req) {
    return {
      userId: req.auth.subject,
      scopes: req.auth.scopes,
    };
  }
}

```

ในระบบจริงควรใช้ `@UseGuards(CentralAuthGuard, ScopeGuard)` ร่วมกัน และให้ Service Layer ตรวจสิทธิ์บริษัทและ Order อีกชั้นหนึ่ง

## 4. CIS — Go Fiber Authentication Middleware

สำหรับ Go สามารถใช้ `github.com/golang-jwt/jwt/v5` ร่วมกับ JWKS Library ที่รองรับ Cache และ Key Rotation เช่น `github.com/MicahParks/keyfunc/v3`

ตัวอย่างด้านล่างใช้ Fiber v2 และสมมติว่า JWKS Endpoint อยู่ที่ URL ตาม Contract

```
go get github.com/gofiber/fiber/v2
go get github.com/golang-jwt/jwt/v5
go get github.com/MicahParks/keyfunc/v3
```

`auth_middleware.go`

```

package middleware

import (
    "strings"
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/golang-jwt/jwt/v5"
    "github.com/MicahParks/keyfunc/v3"
)

type AuthClaims struct {
    Scope         string `json:"scope"`
    ClientID      string `json:"client_id"`
    PrincipalType string `json:"principal_type"`
    jwt.RegisteredClaims
}

func NewAuthMiddleware() (fiber.Handler, error) {
    jwks, err := keyfunc.NewDefault(
        []string{
            "https://id.central.example/.well-known/jwks.json",
        },
    )
    if err != nil {
        return nil, err
    }

    return func(c *fiber.Ctx) error {
        header := c.Get("Authorization")
        parts := strings.Fields(header)

        if len(parts) != 2 ||
            !strings.EqualFold(parts[0], "Bearer") {
            return c.SendStatus(fiber.StatusUnauthorized)
        }

        claims := new(AuthClaims)

        token, err := jwt.ParseWithClaims(
            parts[1],
            claims,
            jwks.Keyfunc,
            jwt.WithValidMethods([]string{"RS256"}),
            jwt.WithIssuer("https://id.central.example"),
            jwt.WithAudience("cis-api"),
            jwt.WithExpirationRequired(),
            jwt.WithLeeway(5*time.Second),
        )

        if err != nil || !token.Valid ||
            claims.Subject == "" {
            return c.SendStatus(fiber.StatusUnauthorized)
        }

        c.Locals("auth", claims)
        return c.Next()
    }, nil
}

```

ตัวอย่างการใช้งานกับ Fiber:

```

authMiddleware, err := middleware.NewAuthMiddleware()
if err != nil {
    log.Fatal(err)
}

api := app.Group("/api", authMiddleware)

api.Get("/projects", func(c *fiber.Ctx) error {
    claims := c.Locals("auth").(*middleware.AuthClaims)

    return c.JSON(fiber.Map{
        "userId": claims.Subject,
        "scope":  claims.Scope,
    })
})

```

ควรสร้าง JWKS Client ครั้งเดียวตอน Startup ไม่ใช่สร้างใหม่ทุก HTTP Request และควรกำหนด Timeout, Cache Policy, Allowed Host และการจัดการกรณี JWKS Endpoint ล่มให้ชัดเจน

หมายเหตุ: ถ้า CIS ใช้ Fiber v3 ต้องปรับ API ของ Handler และ Context ให้ตรงกับเวอร์ชันนั้น

## 5. Authorization Middleware ต้องแยกจาก Authentication

ทั้ง NestJS และ Go Fiber ควรใช้ Authorization Contract เดียวกัน

ตัวอย่าง:

```
GET /orders
  → authenticate()
  → requireScope("orders.read")
  → requireTenantAccess(companyId)
  → Controller
```

การมี Scope `orders.read` หมายความว่า Token ได้รับอนุญาตให้เรียก API ประเภทนี้ แต่ไม่ได้หมายความว่าเข้าถึง Order ของทุกบริษัทได้

| Layer                  | ตรวจอะไร                            | ผู้รับผิดชอบ        |
| ---------------------- | ----------------------------------- | ------------------- |
| Authentication         | Token ถูกต้องหรือไม่                | Shared Auth Library |
| API Authorization      | มี Scope ที่ต้องการหรือไม่          | Guard / Middleware  |
| Tenant Authorization   | มีสิทธิ์เข้าถึงบริษัทหรือไม่        | Buyer / CIS         |
| Resource Authorization | เข้าถึง Order/Project นี้ได้หรือไม่ | Business Service    |

สำหรับ M2M Token ต้องตรวจว่า `client_id` ผูกกับ Partner และ Tenant ที่ได้รับอนุญาตจริง ไม่ควรเชื่อ `company_id` จาก Request Header เพียงอย่างเดียว

## 6. Migration จาก Token เดิมไป Central Token

ผมไม่แนะนำให้เปลี่ยน Middleware ของ Buyer และ CIS พร้อมกันทั้งหมด เพราะอาจกระทบ Production

HTTP Request

Authentication Compatibility Layer

เลือก Trusted Validator ตาม Token Profile

Legacy Validator

Buyer / CIS Token

Temporary

Central Validator

Central ID Token

Target

Normalized Principal

User / Service / Tenant / Scope

ข้อควรระวังคือ Dual Validation ต้องมี Trust Configuration แยกกัน ห้ามนำ Token ที่ตรวจไม่ผ่าน Central Validator ไปลอง Legacy Validator โดยไม่มีเงื่อนไข เพราะอาจเปิดช่อง Token Confusion ได้

### Migration Backlog

| ลำดับ | Buyer (NestJS)            | CIS (Go Fiber)                |
| ----- | ------------------------- | ----------------------------- |
| 1     | สร้าง Central AuthGuard   | สร้าง Central Auth Middleware |
| 2     | เพิ่ม JWKS Cache          | เพิ่ม JWKS Cache              |
| 3     | เพิ่ม ScopeGuard          | เพิ่ม Scope Middleware        |
| 4     | สร้าง Principal Adapter   | สร้าง Principal Adapter       |
| 5     | เพิ่ม Dual Validation     | เพิ่ม Dual Validation         |
| 6     | ปรับ Login/Refresh Flow   | ปรับ Login/Refresh Flow       |
| 7     | เพิ่ม Revocation Handling | เพิ่ม Revocation Handling     |
| 8     | ปิด Legacy Validator      | ปิด Legacy Validator          |

## 7. Revocation และ Session Synchronization

นี่คือส่วนที่ Middleware อย่างเดียวแก้ไม่ได้ทั้งหมด

เมื่อ Central ID Disable User หรือ Global Logout ควรมีกลไกกระจาย Security Event ไปยัง Buyer และ CIS เพื่อยุติ Local Session ที่เกี่ยวข้อง

ตัวอย่าง Event:

```
{
  "event_type": "USER_DISABLED",
  "event_id": "evt_123",
  "subject": "user_123",
  "occurred_at": "2026-11-12T06:00:00Z"
}
```

ตัวอย่างนี้เป็น Custom Security Event Contract ไม่ใช่ OIDC Back-Channel Logout Token มาตรฐาน

สำหรับ Production ควรเพิ่มการยืนยันแหล่งที่มาของ Event, Idempotency, Retry, Audit และ Revocation Store โดยมีตัวเลือก เช่น Redis หรือ Database ตาม SLA ที่ต้องการ

สิ่งที่ต้องแยกให้ชัด: การลบ Local Web Session ไม่ได้ทำให้ JWT Access Token ที่ออกไปแล้วใช้ไม่ได้ทันที หากต้องการปฏิเสธ Token ก่อนหมดอายุ ต้องให้ Middleware ตรวจ Revocation State หรือใช้ Token Introspection เพิ่มเติม

## 8. Test Cases ที่ทีม Developer ควรทำ

| Test                       | Expected                    |
| -------------------------- | --------------------------- |
| ไม่มี Authorization Header | 401                         |
| Token หมดอายุ              | 401                         |
| Signature ไม่ถูกต้อง       | 401                         |
| Issuer ไม่ตรง              | 401                         |
| Buyer Token เรียก CIS      | 401                         |
| Scope ไม่เพียงพอ           | 403                         |
| ไม่มีสิทธิ์ Tenant         | 403 หรือ 404                |
| JWKS Key Rotation          | ตรวจ Token ด้วย Key ใหม่ได้ |
| Refresh Token ถูก Revoke   | ขอ Token ใหม่ไม่ได้         |
| User ถูก Disable           | ถูกระงับตาม Security SLA    |
| Partner Client ถูก Revoke  | ไม่สามารถขอ Token ใหม่      |
| Legacy Token หลัง Cutover  | 401                         |

## 9. สิ่งที่ควรให้ทีมพัฒนาทำก่อน

ผมแนะนำให้เริ่มจาก Authentication Contract ระหว่าง Central ID, Buyer และ CIS ก่อนเขียน Middleware จริง โดยตกลงร่วมกันใน 6 เรื่อง:

1. JWT Claims Contract — `iss`, `aud`, `sub`, `scope`, `client_id`, `principal_type`
2. JWKS Endpoint และ Signing Algorithm
3. Token Expiration และ Refresh Policy
4. User / Service Principal Mapping
5. Global Logout และ Revocation SLA
6. Legacy Token Migration Strategy

เมื่อ Contract เหล่านี้ชัดแล้ว ทีม NestJS และ Go Fiber สามารถพัฒนา Middleware ขนานกันได้ และทดสอบกับ Token ชุดเดียวกัน

### มีอีกหนึ่งจุดที่ต้องตรวจสอบในระบบปัจจุบัน

Buyer และ CIS มี Frontend แยกจาก Backend ใช่ไหม และปัจจุบัน Frontend เก็บ Access Token / Refresh Token ไว้ที่ไหน?

เช่น `localStorage`, `Cookie (HttpOnly)` หรือ Backend Session

เรื่องนี้สำคัญเพราะจะกำหนดว่าเราควรใช้ BFF (Backend for Frontend) หรือให้ Frontend จัดการ OAuth Flow เอง ซึ่งมีผลต่อการปรับ Login, Refresh Token และ Middleware โดยตรง
ใช้ได้ทั้ง Kong Gateway (Free/Open Source) และ Keycloak (Free/Open Source) ครับ และสำหรับ Architecture ของ Central ID + Buyer (NestJS) + CIS (Go Fiber) ผมแนะนำให้พิจารณา ใช้ Keycloak และ Kong ร่วมกัน เพราะทั้งสองตัวแก้ปัญหาคนละส่วน

- Keycloak: จัดการ Authentication, SSO, OAuth 2.0 / OIDC, Access Token, Refresh Token และ Session
- Kong Gateway: เป็น API Gateway สำหรับตรวจสอบ Request, Routing, Rate Limiting และควบคุมการเข้าถึง Open API
- Buyer / CIS: รับผิดชอบ Business Authorization เช่น Company, Role, Project และ Resource Permission

ข้อดีคือไม่ต้องพัฒนา OAuth Authorization Server เองทั้งหมด และสามารถลดงาน Custom Middleware ของทั้ง NestJS และ Go Fiber ได้

แต่มีประเด็นสำคัญคือ Kong OSS ไม่ได้มีความสามารถ OIDC Plugin แบบเดียวกับ Kong Enterprise ดังนั้นต้องออกแบบการตรวจ JWT ให้เหมาะกับข้อจำกัดของ Free Edition

## 1. เปรียบเทียบ Kong Free กับ Keycloak Free

| ความสามารถ                      | Keycloak Free         | Kong Gateway OSS                  |
| ------------------------------- | --------------------- | --------------------------------- |
| SSO / Login                     |                       |                                   |
| OAuth 2.0 / OIDC Server         |                       |                                   |
| Access / Refresh Token          |                       | ไม่ใช่หน้าที่หลัก                 |
| Client Credentials              |                       | ไม่ใช่หน้าที่หลัก                 |
| User / Session Management       |                       |                                   |
| Token Introspection             |                       | ต้องเสริมเอง                      |
| JWT Verification                | ผ่าน API Middleware   | มี JWT Plugin                     |
| Automatic OIDC/JWKS Integration | เป็นผู้ให้บริการ OIDC | ไม่มี Official OIDC Plugin ใน OSS |
| API Routing                     |                       |                                   |
| Rate Limiting                   |                       |                                   |
| API Key Authentication          | ไม่ใช่หน้าที่หลัก     | มี Key Auth Plugin                |

Keycloak เป็น Open Source Identity and Access Management ส่วน Kong OIDC Plugin อย่างเป็นทางการระบุว่าเป็น Enterprise Only ขณะที่ JWT Plugin มีให้ใช้งานใน Gateway OSS&#x20;

[image](https://www.google.com/s2/favicons?domain=https://www.keycloak.org\&sz=32)

Keycloak+2



ทั้งสองตัวใช้งานแบบ Self-hosted ได้โดยไม่มีค่า License สำหรับรุ่น Open Source แต่ยังมีค่า Infrastructure, Monitoring, Maintenance และ Security Operations

## 2. Architecture ที่ผมแนะนำสำหรับ Central

Central ID

Existing User Database / Business Identity

Keycloak

OIDC · OAuth · SSO · JWT · Refresh · Revocation

Buyer

NestJS

OIDC Client + JWT Guard

CIS

Go Fiber

OIDC Client + JWT Middleware

Partner / External System

Client Credentials → Keycloak Token

Kong Gateway OSS

Routing · Rate Limiting · Logging · API Protection

Buyer Open API

CIS Open API

Logical Architecture — การเชื่อม Central ID กับ Keycloak ต้องเลือกรูปแบบ User Federation, Identity Brokering หรือ Migration ตามความสามารถของระบบเดิม

### จุดสำคัญ: ไม่จำเป็นต้องทิ้ง Central ID

มีสองทางเลือกสำหรับเชื่อม Central ID กับ Keycloak

Option A — Keycloak เป็น Identity Provider หลัก

ย้ายการจัดการ Authentication ไป Keycloak และให้ Central ID ทำหน้าที่ User Profile / Business Identity หรือเชื่อมผ่าน User Federation

เหมาะกับการปรับ Architecture ระยะยาว แต่มี Migration Impact สูงกว่า

Option B — Keycloak เป็น Identity Broker

ให้ Keycloak เชื่อมกับ Central ID ผ่าน OIDC หรือ SAML โดย Central ID ยังเป็นระบบ Login เดิม ส่วน Keycloak ออก Token ให้ Buyer/CIS และ Open API

เหมาะกับการลดผลกระทบช่วงแรก แต่ Central ID ต้องรองรับมาตรฐานที่ Keycloak ใช้เชื่อมต่อ และต้องออกแบบการ Sync Logout/Disable ระหว่างสองระบบ

Keycloak รองรับ Identity Brokering และ User Federation อยู่แล้ว&#x20;

[image](https://www.google.com/s2/favicons?domain=https://www.keycloak.org\&sz=32)

Keycloak+1



สำหรับสถานการณ์ของคุณ ผมจะเริ่มประเมิน Option B ก่อน หาก Central ID รองรับ OIDC มาตรฐานอยู่แล้ว เพราะสามารถรักษา Login Experience ปัจจุบันไว้ได้

## 3. ถ้าใช้ Kong Free แล้ว Middleware ยังต้องตรวจ Token หรือไม่?

ยังต้องตรวจครับ โดยเฉพาะถ้าใช้ Kong OSS + Keycloak

เหตุผลคือ Kong OSS JWT Plugin ไม่ได้ทำหน้าที่เหมือน OIDC Resource Server แบบเต็มรูปแบบโดยอัตโนมัติ

JWT Plugin ของ Kong OSS รองรับการตรวจ Signature และบาง Registered Claims เช่น `exp` และ `nbf` แต่ไม่ได้ให้การตรวจ `iss`, `aud`, `scope`, JWKS Discovery/Rotation และ Revocation แบบครบวงจรเหมือน OIDC Plugin&#x20;

[image](https://www.google.com/s2/favicons?domain=https://developer.konghq.com\&sz=32)

Kong Docs+1



ผมจึงแนะนำการแบ่ง Responsibility ดังนี้

| Layer                 | สิ่งที่ตรวจสอบ                                    |
| --------------------- | ------------------------------------------------- |
| Kong OSS              | Routing, Rate Limit, Request Size, IP Restriction |
| NestJS AuthGuard      | Signature, Issuer, Audience, Expiration           |
| Fiber Auth Middleware | Signature, Issuer, Audience, Expiration           |
| Authorization Layer   | Scope, Partner, Tenant, Business Permission       |
| Keycloak              | ออก Token, Refresh, Revoke, Session Management    |

ถ้าต้องการให้ Gateway ตรวจ JWT จาก Keycloak เพิ่มด้วยก็ทำได้ แต่ต้องจัดการ Public Key และ Key Rotation ให้ถูกต้อง และไม่ควรถือว่าการผ่าน Kong JWT Plugin เพียงอย่างเดียวเพียงพอสำหรับ OAuth Authorization

## 4. ตัวอย่าง Open API Flow เมื่อใช้ Keycloak + Kong

1. Partner ขอ Access Token จาก Keycloak
   ```
   POST /realms/central/protocol/openid-connect/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=client_credentials
   &client_id=partner_001
   &client_secret=********
   ```
2. Keycloak ออก Access Token

   Token มี `client_id`, `scope`, `aud` และ Claims ตามที่กำหนด
3. Partner เรียก Open API ผ่าน Kong
   ```
   GET /open-api/v1/orders
   Authorization: Bearer <access_token>
   ```
4. Kong ส่ง Request ไป Buyer API

   ใช้ Routing และ Rate Limiting ที่กำหนดไว้
5. Buyer NestJS Guard ตรวจ Token

   ตรวจ Keycloak JWKS, Issuer, Audience, Expiration และ Scope
6. Buyer Service ตรวจ Business Authorization

   ตรวจว่า Partner นี้มีสิทธิ์เข้าถึง Company และ Order ที่ร้องขอหรือไม่

Keycloak มี Token, JWKS, Introspection และ Revocation Endpoints ตามมาตรฐานที่ใช้ใน Flow นี้&#x20;

[image](https://www.google.com/s2/favicons?domain=https://www.keycloak.org\&sz=32)

Keycloak



## 5. แล้ว API Key ที่ Business ต้องการ Generate จะทำอย่างไร?

มีสองแนวทางที่สามารถเลือกใช้ได้

Option 1 — Generate OAuth Client Credential

แนะนำ

ให้ Partner Portal สร้าง Client ใน Keycloak แล้วออก `client_id` และ `client_secret` เพื่อแลก Short-lived Access Token

เหมาะกับ Open API ที่ต้องการ Scope, Revocation, Audit และมาตรฐานสำหรับ Partner Integration

Option 2 — Generate API Key ผ่าน Kong

ให้ Partner ส่ง API Key ใน Header แล้ว Kong ตรวจผ่าน Key Auth Plugin

เหมาะกับ Integration ที่เรียบง่าย แต่ต้องพัฒนา Credential Lifecycle, Tenant Binding, Scope Policy และการป้องกัน Key รั่วให้ครบ หากต้องการ Security Model ระดับเดียวกับ OAuth

สำหรับ Buyer/CIS ที่มีข้อมูลหลายบริษัท ผมเลือก Option 1 เป็นหลัก เพราะต้องควบคุมว่า Partner ใดเข้าถึงข้อมูลของบริษัทใดได้บ้าง

## 6. ประเมินความเหมาะสมสำหรับ Central

| ทางเลือก                   | ความเหมาะสม                       | ข้อจำกัด                                        |
| -------------------------- | --------------------------------- | ----------------------------------------------- |
| Keycloak Free อย่างเดียว   | สูง สำหรับแก้ SSO/Token Lifecycle | ยังต้องมี API Routing/Rate Limit และ Middleware |
| Kong OSS อย่างเดียว        | สูง สำหรับ Open API Gateway       | ไม่ได้แก้ SSO/Refresh Token ส่วนกลาง            |
| Keycloak + Kong OSS        | สูง สำหรับ Architecture รวม       | ต้องดูแลสองระบบและเขียน JWT Validation          |
| Keycloak + Kong Enterprise | สูง สำหรับการรวม OIDC ที่ Gateway | มีค่า License/Subscription                      |

## 7. Migration Plan ที่ผมแนะนำ

| Phase | งาน                                       | ผลลัพธ์                                   |
| ----- | ----------------------------------------- | ----------------------------------------- |
| 1     | Deploy Keycloak ใน Dev/UAT                | ทดลอง OIDC, JWKS, Client Credentials      |
| 2     | เชื่อม Central ID กับ Keycloak            | Login เดิมยังใช้งานได้                    |
| 3     | เพิ่ม Keycloak JWT Guard ใน NestJS        | Buyer รองรับ Central Token                |
| 4     | เพิ่ม Keycloak JWT Middleware ใน Go Fiber | CIS รองรับ Central Token                  |
| 5     | เพิ่ม Kong OSS หน้า Open API              | Routing, Rate Limit, API Exposure         |
| 6     | พัฒนา Partner Portal                      | Generate/Rotate/Revoke Client Credentials |
| 7     | เพิ่ม Global Logout และ Revocation        | ควบคุม Session ตาม SLA                    |
| 8     | ปิด Legacy Token Exchange                 | ลด Token Issuer ที่กระจายอยู่             |

ข้อเสนอของผม: เริ่ม Proof of Concept ด้วย Keycloak Free ก่อน แล้วเพิ่ม Kong OSS ใน Phase ของ Open API เพราะ Keycloak แก้ปัญหาหลักเรื่อง Token Issuance และ Session Lifecycle ได้ตรงกว่า ส่วน Kong ช่วยเรื่อง API Management ไม่ใช่ตัวแก้ปัญหา SSO โดยตรง

ก่อนเลือกว่าจะให้ Keycloak แทน Central ID หรือทำงานร่วมกัน มีคำถามสำคัญเพียงข้อเดียว:

Central ID ปัจจุบันพัฒนาขึ้นเอง (Custom Authentication) หรือใช้ Identity Provider เช่น Keycloak, Auth0 หรือระบบอื่นอยู่แล้ว?

คำตอบนี้จะกำหนดว่าเราควรใช้ Keycloak เป็น Identity Broker, เปลี่ยนเป็น Authorization Server หลัก หรืออาจไม่จำเป็นต้องเพิ่ม Keycloak เลยก็ได้