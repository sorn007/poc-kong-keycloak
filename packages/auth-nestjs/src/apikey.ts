/**
 * Central API Key — ตรวจ key กับ ID Portal (POST /apikeys/validate)
 * contract เดียวกับ Kong plugin central-apikey: { active, owner, scopes }
 * ใช้กับ protocol ที่ไม่มี Bearer header (เช่น MCP: header `apikey` หรือ `Authorization: Bearer central_…`)
 */

export interface ApiKeyVerifierOptions {
  /** URL ของ validate endpoint เช่น http://central-id:3000/apikeys/validate */
  validationUrl: string;
  /** timeout ต่อการตรวจ — default 8000 ms */
  timeoutMs?: number;
}

export interface ApiKeyPrincipal {
  owner: string;
  scopes: string[];
}

type Headers = Record<string, string | string[] | undefined>;

export class ApiKeyVerifier {
  constructor(private readonly options: ApiKeyVerifierOptions) {}

  /**
   * extractKey — อ่าน API key จาก request: header `apikey` ก่อน แล้ว `Authorization: Bearer central_…`
   * (ไม่รับ Bearer ปกติ — กันสับสนระหว่าง API key กับ JWT)
   */
  extractKey(headers: Headers): string | undefined {
    const headerKey = headers.apikey;
    if (typeof headerKey === 'string' && headerKey) return headerKey;
    const authz = headers.authorization;
    if (typeof authz === 'string' && authz.startsWith('Bearer central_')) {
      return authz.slice('Bearer '.length);
    }
    return undefined;
  }

  /**
   * verify — ตรวจ key กับ ID Portal **ทุก request** (ไม่ cache → revoke มีผลทันที)
   * fail-closed: ตรวจไม่ได้/key ไม่ active/owner ว่าง → คืน null
   */
  async verify(key: string | undefined): Promise<ApiKeyPrincipal | null> {
    if (!key) return null;
    try {
      const r = await fetch(this.options.validationUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ key }),
        signal: AbortSignal.timeout(this.options.timeoutMs ?? 8000),
      });
      const out = (await r.json()) as {
        active?: boolean;
        owner?: string;
        scopes?: string[];
      };
      if (!r.ok || out.active !== true || !out.owner) return null;
      return { owner: out.owner, scopes: out.scopes ?? [] };
    } catch {
      return null;
    }
  }
}
