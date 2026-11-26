// IdP จำลองสำหรับ unit test ของ SDK: JWKS server จริง (RSA 2048) + ตัวเซ็น token
const http = require('node:http');
const crypto = require('node:crypto');
const { SignJWT } = require('jose');

const KID = 'test-key-1';

async function newIdP() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  const jwk = publicKey.export({ format: 'jwk' });
  const body = JSON.stringify({
    keys: [{ ...jwk, kid: KID, use: 'sig', alg: 'RS256' }],
  });
  const server = http.createServer((req, res) => {
    if (req.url !== '/realms/central/protocol/openid-connect/certs') {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' }).end(body);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const issuer = 'https://idp.test/realms/central';
  return {
    issuer,
    audience: 'svc-api',
    jwksUrl: `http://127.0.0.1:${server.address().port}/realms/central/protocol/openid-connect/certs`,
    // claims มาตรฐานที่ผ่านทุกเงื่อนไข (ผู้เรียบ override field ที่จะทดสอบ)
    claims: () => ({
      iss: issuer,
      sub: 'user-1',
      aud: 'svc-api',
      azp: 'buyer-web',
      exp: Math.floor(Date.now() / 1000) + 300,
      scope: 'orders.read',
      principal_type: 'user',
    }),
    // เซ็นด้วย RS256 + kid (หรือ alg/key อื่นเพื่อสร้าง token ที่ต้องถูกปฏิเสธ)
    sign: (claims, { alg = 'RS256', kid = KID, key } = {}) =>
      new SignJWT(claims).setProtectedHeader({ alg, kid }).sign(key ?? privateKey),
    publicKey,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

// http server สั้น ๆ สำหรับจำลอง ID Portal (อ่าน form body ให้แล้ว)
async function newServer(handler) {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => handler(req, new URLSearchParams(body), res));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

module.exports = { newIdP, newServer };
