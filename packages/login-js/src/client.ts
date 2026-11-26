import { base64UrlEncode, utf8 } from './base64.js';
import { LoginError } from './errors.js';
import type { KeyValueStore, LoginEnv } from './env.js';
import { JwksClient } from './jwks.js';
import { decodeJwt, decodeUnverified } from './jwt.js';
import { createPkcePair } from './pkce.js';
import { LoopGuard, MAX_REDIRECTS, TransactionStore, type Transaction } from './storage.js';
import { currentPath, parseCallbackParams, sanitizeReturnTo, type CallbackParams } from './url.js';

const SESSION_KEY = 'central-login.session';
const DEFAULT_SCOPES = ['openid', 'profile', 'email'];

export interface LoginOptions {
  /** issuer ที่ยอมรับ — ค่าเดียว (allowlist) เช่น http://localhost:8080/realms/central */
  issuer: string;
  /** client_id ของแอป — public client ที่บังคับ PKCE S256 ฝั่ง Keycloak */
  clientId: string;
  /** redirect URI ที่ลงทะเบียนกับ Keycloak — ต้องอยู่ origin เดียวกับแอป (verifier เก็บใน sessionStorage ของ origin นั้น) */
  redirectUri: string;
  /** scope ที่ขอเพิ่มจากค่า default ของ client — 'openid' ถูกใส่ให้เสมอ */
  scopes?: string[];
  /** clock skew ที่ยอมรับตอนตรวจ exp/iat ของ id_token (วินาที) — default 5 */
  leewaySeconds?: number;
  /** post-logout redirect URI — default = origin ของ redirectUri (ต้องลงทะเบียนเป็น Valid Post Logout Redirect URIs) */
  postLogoutRedirectUri?: string;
  /**
   * เก็บ token ข้ามการ reload (ส่ง sessionStorage เข้ามา) — default: ไม่เก็บ (token อยู่ในหน่วยความจำเท่านั้น)
   * ⚠️ ข้อมูลใน storage ใด ๆ ถูก XSS อ่านได้ — เปิดเมื่อยอมรับความเสี่ยงนั้น
   */
  tokenStore?: KeyValueStore | null;
}

export interface LoginRedirectOptions {
  /** path ในแอปที่จะกลับมาหลัง login — ค่าอื่นนอกจาก path เดียวกันถูกเปลี่ยนเป็น '/' */
  returnTo?: string;
  prompt?: 'login';
  /** ส่ง ui_locales ให้หน้า login ของ OP (เช่น 'th' / 'en') */
  locale?: string;
}

export interface InitOptions {
  /** false = ไม่พยายาม silent login ตอน init — เฉพาะจัดการ callback (default true) */
  silent?: boolean;
}

export type InitResult = { status: 'authenticated' } | { status: 'unauthenticated'; error?: LoginError };

export interface UserProfile {
  subject: string;
  username?: string;
  name?: string;
  email?: string;
  emailVerified?: boolean;
  /** claims ทั้งหมดของ id_token (ผ่านการตรวจแล้ว) */
  claims: Record<string, unknown>;
}

/** TokenInfo — ข้อมูลจาก access token แบบ decode โดยไม่ verify (แสดงผลเท่านั้น — ผู้ตรวจจริงคือ API ปลายทาง) */
export interface TokenInfo {
  /** เวลาหมดอายุตามนาฬิกาเครื่อง (ms) — คำนวณจาก expires_in ตอนรับ token */
  expiresAt: number;
  expiresIn: number;
  audiences: string[];
  scopes: string[];
  claims: Record<string, unknown>;
}

export type LoginEventName = 'authenticated' | 'signedOut' | 'tokenRefreshed';
export type LoginEventHandler = (payload: { reason?: string }) => void;

interface TokenSet {
  access_token?: unknown;
  refresh_token?: unknown;
  id_token?: unknown;
  expires_in?: unknown;
  [name: string]: unknown;
}

interface Session {
  accessToken: string;
  refreshToken?: string;
  idToken: string;
  expiresAt: number;
  profile: UserProfile;
  claims: Record<string, unknown>;
}

function audienceList(aud: unknown): string[] {
  if (typeof aud === 'string') return [aud];
  return Array.isArray(aud) ? aud.filter((a): a is string => typeof a === 'string') : [];
}

function profileFrom(payload: Record<string, unknown>): UserProfile {
  const text = (name: string): string | undefined => {
    const v = payload[name];
    return typeof v === 'string' && v ? v : undefined;
  };
  return {
    subject: payload.sub as string,
    username: text('preferred_username'),
    name: text('name'),
    email: text('email'),
    emailVerified: payload.email_verified === true,
    claims: payload,
  };
}

type ResolvedOptions = Required<Omit<LoginOptions, 'tokenStore'>> & { tokenStore: KeyValueStore | null };

function parseAbsoluteUrl(value: string, name: string): URL {
  try {
    return new URL(value);
  } catch {
    throw new LoginError('invalid_configuration', `${name} must be an absolute URL`);
  }
}

/** parseOptions — ตรวจ config ตอนสร้าง client: ผิด = throw ทันที (ไม่รอให้พังตอน login) */
function parseOptions(input: LoginOptions, env: LoginEnv): { options: ResolvedOptions; redirect: URL } {
  if (!input.clientId) throw new LoginError('invalid_configuration', 'clientId is required');
  const issuer = parseAbsoluteUrl(input.issuer, 'issuer');
  const redirect = parseAbsoluteUrl(input.redirectUri, 'redirectUri');
  if (!/^https?:$/.test(issuer.protocol) || issuer.search || issuer.hash) {
    throw new LoginError('invalid_configuration', 'issuer must be an http(s) URL without a query or fragment');
  }
  if (redirect.origin !== env.location.origin) {
    throw new LoginError('invalid_configuration', `redirectUri (${redirect.origin}) must be on the same origin as the app (${env.location.origin})`);
  }
  const postLogout = parseAbsoluteUrl(input.postLogoutRedirectUri ?? redirect.origin, 'postLogoutRedirectUri');
  return {
    redirect,
    options: {
      issuer: issuer.href.replace(/\/+$/, ''),
      clientId: input.clientId,
      redirectUri: redirect.href,
      scopes: [...new Set([...DEFAULT_SCOPES, ...(input.scopes ?? [])])],
      leewaySeconds: input.leewaySeconds ?? 5,
      postLogoutRedirectUri: postLogout.href.replace(/\/+$/, ''),
      tokenStore: input.tokenStore ?? null,
    },
  };
}

/**
 * LoginClient — OIDC Authorization Code + PKCE (S256) สำหรับ SPA
 * สร้างผ่าน createLogin() หนึ่งครั้งต่อหน้า · token อยู่ในหน่วยความจำของ tab นี้เท่านั้น
 */
export class LoginClient {
  private readonly options: ResolvedOptions;
  private readonly redirectOriginAndPath: string;
  private readonly endpoints: { authorize: string; token: string; logout: string; jwks: string };
  private readonly transactions: TransactionStore;
  private readonly guard: LoopGuard;
  private readonly jwks: JwksClient;
  private readonly listeners = new Map<LoginEventName, Set<LoginEventHandler>>();
  private session: Session | null = null;
  private refreshing: Promise<boolean> | null = null;
  private initResult: Promise<InitResult> | null = null;

  constructor(input: LoginOptions, private readonly env: LoginEnv) {
    const { options, redirect } = parseOptions(input, env);
    this.options = options;
    this.redirectOriginAndPath = redirect.origin + redirect.pathname;
    const base = options.issuer;
    this.endpoints = {
      authorize: `${base}/protocol/openid-connect/auth`,
      token: `${base}/protocol/openid-connect/token`,
      logout: `${base}/protocol/openid-connect/logout`,
      jwks: `${base}/protocol/openid-connect/certs`,
    };
    this.transactions = new TransactionStore(env.transactionStore);
    this.guard = new LoopGuard(env.transactionStore);
    this.jwks = new JwksClient(env, this.endpoints.jwks);
  }

  // ───────────────────────── lifecycle ─────────────────────────

  /**
   * init — เรียกครั้งเดียวตอนหน้าโหลด
   * • อยู่ที่ redirect URI และมี code/state/error → จบ flow การ login (แลก code, ตรวจ id_token, เก็บ token, ลบพารามิเตอร์ออกจาก URL)
   * • มี session ใน tokenStore → 'authenticated'
   * • ไม่มี session → silent login (prompt=none): ถ้าเบราว์เซอร์ยังมี SSO session จะกลับมาแบบ login แล้ว
   *   ระหว่างนี้ promise จะไม่ resolve เพราะหน้ากำลังเปลี่ยน (กันแอป render สถานะ "ยังไม่ login" ก่อนหน้าเปลี่ยน)
   * • OP ตอบ error (เช่น login_required หรือ access_denied) → 'unauthenticated' + error
   */
  init(options: InitOptions = {}): Promise<InitResult> {
    if (!this.initResult) {
      this.initResult = this.doInit(options).catch((e: unknown) => this.failure(e));
    }
    return this.initResult;
  }

  private async doInit(options: InitOptions): Promise<InitResult> {
    this.restoreSession();
    const location = this.env.location;
    const params = parseCallbackParams(location.search);
    if (location.origin + location.pathname === this.redirectOriginAndPath) {
      return this.handleCallback(params);
    }
    // กลับมาจาก logout: OP ส่ง state (path ที่ขอกลับมา) กลับมาให้ — เอาพารามิเตอร์ออกจาก URL
    if (!params.code && !params.error && params.state !== undefined) {
      location.replaceState(sanitizeReturnTo(params.state));
    }
    if (this.session) return { status: 'authenticated' };
    const now = this.env.now();
    if (options.silent === false || !this.guard.allowsAutomaticRedirect(now)) return { status: 'unauthenticated' };
    await this.startAuthorization({ prompt: 'none', silent: true, returnTo: currentPath(location) });
    return new Promise<InitResult>(() => {});
  }

  private async handleCallback(params: CallbackParams): Promise<InitResult> {
    // อ่าน transaction ของ state นี้แล้วลบทันที (ใช้ได้ครั้งเดียว) — และลบ code/state ออกจาก URL "ก่อน" I/O ใด ๆ
    // เพื่อไม่ให้ code ถูก reload/ย้อนกลับมาใช้ซ้ำ หรือหลุดไปทาง referrer/history
    const transaction = this.transactions.take(params.state);
    this.env.location.replaceState(sanitizeReturnTo(transaction?.returnTo));
    const now = this.env.now();

    if (params.error) {
      this.guard.noteError(now);
      return this.failure(new LoginError('authorization_failed', 'the identity provider rejected the login request', `${params.error}${params.error_description ? `: ${params.error_description}` : ''}`));
    }
    if (params.iss !== undefined && params.iss !== this.options.issuer) {
      this.guard.noteError(now);
      return this.failure(new LoginError('issuer_mismatch', 'the callback "iss" is not the configured issuer', params.iss));
    }
    if (!transaction) {
      // callback ไม่ตรงกับการ login ที่ tab นี้เริ่ม (อีก tab / เปิดซ้ำ / sessionStorage ถูกล้าง) — ไม่แลก code และไม่ redirect ตามอัตโนมัติ
      this.guard.noteError(now);
      return this.failure(new LoginError('unrecognized_state', 'no login request matches this callback (started in another tab, or already used)'));
    }
    try {
      const tokens = await this.tokenRequest({
        grant_type: 'authorization_code',
        code: params.code ?? '',
        redirect_uri: this.options.redirectUri,
        code_verifier: transaction.verifier,
      });
      this.session = await this.buildSession(tokens, transaction.nonce);
    } catch (e) {
      this.guard.noteError(now);
      return this.failure(e);
    }
    this.guard.reset();
    this.persistSession();
    this.emit('authenticated', {});
    return { status: 'authenticated' };
  }

  /** login — พาผู้ใช้ไปหน้า login ของ ID (Authorization Code + PKCE) — promise ไม่ resolve เพราะหน้าเปลี่ยน */
  async login(options: LoginRedirectOptions = {}): Promise<never> {
    this.guard.clearMarkers(); // ผู้ใช้กดเอง → ลืมว่าเพิ่ง logout / เพิ่งเจอ error
    return this.startAuthorization({ prompt: options.prompt, silent: false, returnTo: options.returnTo ?? currentPath(this.env.location), locale: options.locale });
  }

  /**
   * silentLogin — login ด้วย SSO session ที่มีอยู่ในเบราว์เซอร์โดยไม่แสดงหน้า login (prompt=none)
   * ใช้หลัง updateToken() ล้มเหลวเพื่อกู้ session: ถ้า SSO session ยังอยู่จะกลับมาแบบ login แล้ว ถ้าไม่ → init() คืน 'unauthenticated'
   */
  async silentLogin(options: LoginRedirectOptions = {}): Promise<never> {
    return this.startAuthorization({ prompt: 'none', silent: true, returnTo: options.returnTo ?? currentPath(this.env.location), locale: options.locale });
  }

  /** logout — RP-initiated logout (id_token_hint) → OP จบ SSO session แล้วพากลับแอป · เคลียร์ token ในเครื่องก่อน navigate */
  async logout(options: { returnTo?: string } = {}): Promise<never> {
    const returnTo = sanitizeReturnTo(options.returnTo);
    const idToken = this.session?.idToken;
    this.clearSession();
    this.guard.noteLogout(this.env.now());
    if (!idToken || !this.isOwnIdToken(idToken)) {
      // ไม่มี id_token ที่ใช้เป็น hint ได้ → ออกจากระบบเฉพาะในเครื่อง (ไม่ส่ง hint ที่ใช้ไม่ได้ให้ OP)
      this.env.navigate(this.env.location.origin + returnTo);
      return new Promise<never>(() => {});
    }
    const query = new URLSearchParams({
      id_token_hint: idToken,
      client_id: this.options.clientId,
      post_logout_redirect_uri: this.options.postLogoutRedirectUri,
      state: returnTo,
    });
    this.env.navigate(`${this.endpoints.logout}?${query}`);
    return new Promise<never>(() => {});
  }

  /**
   * updateToken — คืน true ถ้าได้ token ใหม่ · false ถ้า token เดิมยังอายุเหลือมากกว่า minTtlSeconds
   * เรียกก่อนใช้ token ทุกครั้ง (ค่า default 20 วินาที · -1 = บังคับ refresh)
   * • เรียกพร้อมกันหลายที่ → refresh จริงครั้งเดียว (กันใช้ refresh token ซ้ำจนโดน replay detection)
   * • ถูกปฏิเสธ → เคลียร์ session, emit 'signedOut' และ throw (ลอง silentLogin() เพื่อกู้)
   * • network error → ทิ้ง refresh token (ไม่รู้ว่า server ใช้ไปแล้วหรือยัง) แต่คง access token เดิมให้ใช้จนหมดอายุ
   */
  updateToken(minTtlSeconds = 20): Promise<boolean> {
    if (!this.session) return Promise.reject(new LoginError('not_authenticated', 'not logged in — call login() first'));
    if (this.refreshing) return this.refreshing;
    const remainingMs = this.session.expiresAt - this.env.now();
    if (minTtlSeconds >= 0 && remainingMs > minTtlSeconds * 1000) return Promise.resolve(false);
    if (!this.session.refreshToken) {
      this.clearSession();
      this.emit('signedOut', { reason: 'no_refresh_token' });
      return Promise.reject(new LoginError('refresh_rejected', 'the access token has expired and there is no refresh token'));
    }
    this.refreshing = this.refresh().finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private async refresh(): Promise<boolean> {
    let tokens: TokenSet;
    try {
      tokens = await this.tokenRequest({ grant_type: 'refresh_token', refresh_token: this.session?.refreshToken ?? '' });
    } catch (e) {
      if (!(e instanceof LoginError)) throw e;
      if (e.code === 'token_rejected') {
        // session ฝั่ง server จบแล้ว (ถูก rotate / หมดอายุ / replay detection)
        this.clearSession();
        this.emit('signedOut', { reason: 'refresh_rejected' });
        throw new LoginError('refresh_rejected', 'the refresh token was rejected — the session has ended', e.detail);
      }
      if (this.session) this.session.refreshToken = undefined;
      this.persistSession();
      throw e;
    }
    try {
      this.session = await this.buildSession(tokens);
    } catch (e) {
      // refresh token เดิมถูกใช้ไปแล้ว — session นี้ต่อไม่ได้
      this.clearSession();
      this.emit('signedOut', { reason: 'invalid_id_token' });
      throw e;
    }
    this.persistSession();
    this.emit('tokenRefreshed', {});
    return true;
  }

  /** clear — ลบ token ออกจากเครื่องเท่านั้น (ไม่แจ้ง OP) */
  clear(): void {
    this.clearSession();
  }

  // ───────────────────────── accessors ─────────────────────────

  isAuthenticated(): boolean {
    return this.session !== null;
  }

  getAccessToken(): string | undefined {
    return this.session?.accessToken;
  }

  getIdToken(): string | undefined {
    return this.session?.idToken;
  }

  /** getUser — โปรไฟล์จาก id_token ที่ผ่านการตรวจแล้ว (คืนสำเนา) */
  getUser(): UserProfile | null {
    return this.session ? { ...this.session.profile, claims: { ...this.session.profile.claims } } : null;
  }

  /** getTokenInfo — ข้อมูลของ access token สำหรับแสดงผล (decode โดยไม่ verify) */
  getTokenInfo(): TokenInfo | null {
    if (!this.session) return null;
    return {
      expiresAt: this.session.expiresAt,
      expiresIn: Math.max(0, Math.ceil((this.session.expiresAt - this.env.now()) / 1000)),
      audiences: audienceList(this.session.claims.aud),
      scopes: typeof this.session.claims.scope === 'string' ? this.session.claims.scope.split(' ').filter(Boolean) : [],
      claims: { ...this.session.claims },
    };
  }

  /** on — รับ event: 'authenticated' | 'signedOut' | 'tokenRefreshed' — คืนฟังก์ชันสำหรับเลิกฟัง */
  on(name: LoginEventName, handler: LoginEventHandler): () => void {
    const set = this.listeners.get(name) ?? new Set<LoginEventHandler>();
    set.add(handler);
    this.listeners.set(name, set);
    return () => {
      set.delete(handler);
    };
  }

  // ───────────────────────── internals ─────────────────────────

  private emit(name: LoginEventName, payload: { reason?: string }): void {
    for (const handler of this.listeners.get(name) ?? []) handler(payload);
  }

  private failure(e: unknown): InitResult {
    return { status: 'unauthenticated', error: e instanceof LoginError ? e : new LoginError('internal_error', 'unexpected error', e instanceof Error ? e.message : undefined) };
  }

  private async startAuthorization(input: { prompt?: 'none' | 'login'; silent: boolean; returnTo: string; locale?: string }): Promise<never> {
    if (this.guard.tooManyRedirects(this.env.now())) {
      throw new LoginError('loop_detected', `redirected to the identity provider ${MAX_REDIRECTS} times within 30 seconds — stopping to avoid a redirect loop`);
    }
    this.transactions.assertWritable();
    const { verifier, challenge } = await createPkcePair(this.env.crypto);
    const random = (): string => base64UrlEncode(this.env.crypto.randomBytes(32));
    const transaction: Transaction = {
      state: random(),
      nonce: random(),
      verifier,
      returnTo: sanitizeReturnTo(input.returnTo),
      silent: input.silent,
      createdAt: this.env.now(),
    };
    this.transactions.save(transaction);
    this.guard.noteRedirect(this.env.now());

    const query = new URLSearchParams({
      client_id: this.options.clientId,
      response_type: 'code',
      redirect_uri: this.options.redirectUri,
      scope: this.options.scopes.join(' '),
      state: transaction.state,
      nonce: transaction.nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256', // S256 เท่านั้น — ไม่รองรับ plain
    });
    if (input.prompt) query.set('prompt', input.prompt);
    if (input.locale) query.set('ui_locales', input.locale);
    this.env.navigate(`${this.endpoints.authorize}?${query.toString()}`);
    return new Promise<never>(() => {}); // หน้ากำลังเปลี่ยน — ไม่ resolve
  }

  private async tokenRequest(form: Record<string, string>): Promise<TokenSet> {
    let response: Response;
    try {
      response = await this.env.fetch(this.endpoints.token, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
        body: new URLSearchParams({ client_id: this.options.clientId, ...form }).toString(),
      });
    } catch {
      // เบราว์เซอร์รายงาน "Failed to fetch" เมื่อ OP ไม่ส่ง CORS header ให้ origin นี้ (webOrigins ของ client ไม่ครอบคลุม)
      throw new LoginError('network_error', 'cannot reach the token endpoint', 'if the browser console shows "Failed to fetch", check that the client webOrigins in Keycloak includes this app');
    }
    const out = (await response.json().catch(() => undefined)) as TokenSet | undefined;
    const error = typeof out?.error === 'string' ? out.error : response.ok ? undefined : `http ${response.status}`;
    if (error) {
      const description = typeof out?.error_description === 'string' ? out.error_description : undefined;
      throw new LoginError(
        error === 'invalid_grant' ? 'token_rejected' : 'token_request_failed',
        `the token endpoint rejected the request: ${error}`,
        description,
      );
    }
    return out ?? {};
  }

  private async buildSession(tokens: TokenSet, expectedNonce?: string): Promise<Session> {
    if (typeof tokens.access_token !== 'string' || !tokens.access_token) {
      throw new LoginError('token_request_failed', 'the token response has no access_token');
    }
    const profile = await this.validateIdToken(tokens.id_token, { expectedNonce, accessToken: tokens.access_token });
    // อายุ token นับจาก expires_in (เวลาสัมพัทธ์) ไม่ใช่ exp เทียบนาฬิกาเครื่อง — นาฬิกาเครื่องผู้ใช้เดินไม่ตรงก็ไม่กระทบ
    const expiresIn = typeof tokens.expires_in === 'number' && tokens.expires_in > 0 ? tokens.expires_in : 0;
    return {
      accessToken: tokens.access_token,
      refreshToken: typeof tokens.refresh_token === 'string' && tokens.refresh_token ? tokens.refresh_token : undefined,
      idToken: tokens.id_token as string,
      expiresAt: this.env.now() + expiresIn * 1000,
      profile,
      claims: decodeUnverified(tokens.access_token) ?? {},
    };
  }

  /** validateIdToken — ตรวจ id_token ตาม OIDC Core 3.1.3.7 ก่อนเชื่อ claims ใด ๆ */
  private async validateIdToken(token: unknown, ctx: { expectedNonce?: string; accessToken?: string }): Promise<UserProfile> {
    const invalid = (why: string): LoginError => new LoginError('invalid_id_token', why);
    const { header, payload, signingInput, signature } = decodeJwt(token, () => { throw invalid('the id_token is not a valid JWT'); });
    if (header.alg !== 'RS256') throw invalid(`unsupported alg "${String(header.alg)}"`); // algorithm allowlist — ห้ามเชื่อ alg จาก header
    if (typeof header.kid !== 'string' || !header.kid) throw invalid('the id_token has no kid');
    const key = await this.jwks.verificationKey(header.kid);
    if (!(await this.env.crypto.verifyRs256(key, signingInput, signature))) throw invalid('the id_token signature is invalid');

    const now = Math.floor(this.env.now() / 1000);
    if (payload.iss !== this.options.issuer) throw invalid('the id_token issuer is not the configured issuer');
    if (!audienceList(payload.aud).includes(this.options.clientId)) throw invalid('the id_token is not issued for this client');
    if (payload.azp !== undefined && payload.azp !== this.options.clientId) throw invalid('the id_token azp is not this client');
    if (typeof payload.sub !== 'string' || !payload.sub) throw invalid('the id_token has no subject');
    if (typeof payload.exp !== 'number' || payload.exp + this.options.leewaySeconds <= now) {
      throw invalid('the id_token has expired (according to this device clock)');
    }
    if (typeof payload.iat !== 'number' || !Number.isFinite(payload.iat)) throw invalid('the id_token has no iat');
    if (payload.iat - this.options.leewaySeconds > now) {
      throw invalid('the id_token was issued in the future — check that the device clock is correct');
    }
    if (ctx.expectedNonce !== undefined && payload.nonce !== ctx.expectedNonce) throw invalid('the id_token nonce does not match the login request');
    // at_hash (ถ้ามี): ผูก access token เข้ากับ id_token
    if (ctx.accessToken && typeof payload.at_hash === 'string') {
      const expected = base64UrlEncode(new Uint8Array(await this.env.crypto.digest('SHA-256', utf8(ctx.accessToken))).slice(0, 16));
      if (expected !== payload.at_hash) throw invalid('the id_token at_hash does not match the access token');
    }
    return profileFrom(payload);
  }

  /** ใช้ id_token เป็น logout hint ได้เมื่อเป็นของ issuer และ client นี้จริง (ตรวจจาก token ที่เคยผ่านการ verify แล้ว) */
  private isOwnIdToken(token: string): boolean {
    let payload: Record<string, unknown>;
    try {
      payload = decodeJwt(token, () => { throw new Error('malformed'); }).payload;
    } catch {
      return false;
    }
    return payload.iss === this.options.issuer && audienceList(payload.aud).includes(this.options.clientId);
  }

  private restoreSession(): void {
    if (!this.options.tokenStore) return;
    let raw: string | null = null;
    try {
      raw = this.options.tokenStore.getItem(SESSION_KEY);
    } catch {
      return;
    }
    if (!raw) return;
    try {
      const saved = JSON.parse(raw) as Session;
      if (typeof saved.accessToken === 'string' && typeof saved.idToken === 'string' && typeof saved.expiresAt === 'number' && saved.profile) {
        this.session = saved;
        return;
      }
    } catch {
      /* ข้อมูลเสีย — ลบทิ้ง */
    }
    this.clearSession();
  }

  private persistSession(): void {
    if (!this.options.tokenStore || !this.session) return;
    try {
      this.options.tokenStore.setItem(SESSION_KEY, JSON.stringify(this.session));
    } catch {
      /* เก็บไม่ได้ = ไม่มีผลต่อ session ในหน่วยความจำ */
    }
  }

  private clearSession(): void {
    this.session = null;
    if (!this.options.tokenStore) return;
    try {
      this.options.tokenStore.removeItem(SESSION_KEY);
    } catch {
      /* ลบไม่ได้ — restoreSession() จะลบทิ้งเมื่อเจอข้อมูลใช้ไม่ได้ */
    }
  }
}
