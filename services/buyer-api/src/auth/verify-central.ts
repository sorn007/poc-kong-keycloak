import { JWTPayload, createRemoteJWKSet, jwtVerify } from 'jose';
import { config, jwksUrl } from '../config';

// JWKS client สร้าง "ครั้งเดียว" ต่อ process (cache + รองรับ key rotation ผ่าน kid)
const jwks = createRemoteJWKSet(new URL(jwksUrl));

// ตรวจ central token ของ ID (Keycloak) ตาม Token Contract
// - signature ผ่าน JWKS (RS256 เท่านั้น)
// - iss / aud / exp (+ nbf) / clockTolerance
export async function verifyCentralToken(
  token: string,
  audience: string = config.audience,
): Promise<JWTPayload> {
  const { payload } = await jwtVerify(token, jwks, {
    issuer: config.keycloakIssuer,
    audience,
    algorithms: ['RS256'],
    clockTolerance: 5,
  });
  if (typeof payload.sub !== 'string' || !payload.sub) {
    throw new Error('missing_subject');
  }
  return payload;
}

// Principal Context มาตรฐานของทุกระบบ (ดู CLAUDE.md สถาปัตยกรรม)
export function normalizePrincipal(p: JWTPayload) {
  return {
    subject: p.sub,
    clientId: p.client_id ?? p.azp ?? null,
    principalType: p.principal_type ?? 'user',
    scopes:
      typeof p.scope === 'string' ? p.scope.split(' ').filter(Boolean) : [],
    tokenId: p.jti ?? null,
    tenantId: p.tenant_id ?? null,
    issuer: p.iss,
  };
}
