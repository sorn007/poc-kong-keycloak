import { LoginError } from './errors.js';
import type { KeyValueStore } from './env.js';

/** Transaction — ข้อมูลของการ login ครั้งหนึ่ง ๆ ที่ต้องรอดข้าม full-page redirect (เก็บใน sessionStorage) */
export interface Transaction {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
  /** true = silent login (prompt=none) — callback ที่ error ไม่ควรพาผู้ใช้ไปไหน */
  silent: boolean;
  createdAt: number;
}

const TRANSACTION_KEY = 'central-login.transaction';

/**
 * TransactionStore — เก็บ verifier/state/nonce ระหว่าง "ออกจากหน้า" ไป OP แล้วกลับมา
 * เก็บได้ทีละรายการ (การเริ่ม login ใหม่จะแทนที่รายการเก่า) และอ่านได้ครั้งเดียว
 */
export class TransactionStore {
  constructor(
    private readonly store: KeyValueStore,
    private readonly key = TRANSACTION_KEY,
  ) {}

  // assertWritable — ต้องเขียนได้ "ก่อน" redirect: ถ้า verifier หายไประหว่างทาง จะแลก code ไม่ได้
  // และจะกลายเป็น callback ที่ตรวจ state ไม่ผ่านซ้ำ ๆ — จึงหยุดตั้งแต่ต้น (fail-closed)
  assertWritable(): void {
    const probe = `${this.key}.probe`;
    try {
      this.store.setItem(probe, '1');
      this.store.removeItem(probe);
    } catch {
      throw new LoginError('storage_unavailable', 'sessionStorage is not writable — PKCE cannot be completed across the redirect');
    }
  }

  save(transaction: Transaction): void {
    this.store.setItem(this.key, JSON.stringify(transaction));
  }

  // take — อ่าน transaction ของ state นี้แล้ว "ลบทันที" ไม่ว่าจะตรงหรือไม่ (ใช้ได้ครั้งเดียว) — ไม่ตรงคืน null
  take(state: string | undefined): Transaction | null {
    let raw: string | null = null;
    try {
      raw = this.store.getItem(this.key);
    } catch {
      return null;
    }
    try {
      this.store.removeItem(this.key);
    } catch {
      /* storage อ่านได้แต่ลบไม่ได้ — transaction ยังถือว่าถูกใช้แล้วเพราะ state ถูกตรวจแล้ว */
    }
    if (!raw || !state) return null;
    try {
      const tx = JSON.parse(raw) as Transaction | null;
      return tx && tx.state === state ? tx : null;
    } catch {
      return null;
    }
  }
}

interface GuardState {
  lastErrorAt?: number;
  loggedOutAt?: number;
  redirects: number[];
}

const GUARD_KEY = 'central-login.guard';
const ERROR_COOLDOWN_MS = 60 * 1000; // หลังเจอ error จาก OP ไม่ redirect อัตโนมัติอีก 60 วินาที
const WINDOW_MS = 30 * 1000;
export const MAX_REDIRECTS = 3;

/**
 * LoopGuard — กัน redirect วนไม่รู้จบ (SDK เรียก redirect เองแล้วกลับมาเรียกอีก)
 * • เพิ่ง logout → ไม่ silent login อัตโนมัติ (จนกว่าผู้ใช้จะกด login เอง)
 * • เพิ่งได้รับ error จาก OP → เว้น 60 วินาที
 * • redirect ไป OP ≥ 3 ครั้งใน 30 วินาที → หยุด (throw loop_detected)
 */
export class LoopGuard {
  constructor(
    private readonly store: KeyValueStore,
    private readonly key = GUARD_KEY,
  ) {}

  private read(): GuardState {
    try {
      const parsed = JSON.parse(this.store.getItem(this.key) ?? '{}') as GuardState | null;
      return parsed && Array.isArray(parsed.redirects) ? parsed : { redirects: [] };
    } catch {
      return { redirects: [] };
    }
  }

  private write(state: GuardState): void {
    try {
      this.store.setItem(this.key, JSON.stringify(state));
    } catch {
      /* เขียนไม่ได้ = ไม่มี guard — การเริ่ม login จะโดน TransactionStore.assertWritable() กันอยู่แล้ว */
    }
  }

  private redirectsInWindow(state: GuardState, now: number): number {
    return state.redirects.filter((at) => now - at < WINDOW_MS).length;
  }

  noteError(now: number): void {
    const state = this.read();
    this.write({ ...state, lastErrorAt: now, redirects: state.redirects.filter((at) => now - at < WINDOW_MS) });
  }

  noteLogout(now: number): void {
    this.write({ ...this.read(), loggedOutAt: now });
  }

  /** จดว่ากำลัง redirect ไป OP (เก็บเฉพาะเวลาในหน้าต่าง 30 วินาทีล่าสุด) */
  noteRedirect(now: number): void {
    const state = this.read();
    const redirects = [...state.redirects.filter((at) => now - at < WINDOW_MS), now];
    this.write({ ...state, redirects });
  }

  tooManyRedirects(now: number): boolean {
    return this.redirectsInWindow(this.read(), now) >= MAX_REDIRECTS;
  }

  // allowsAutomaticRedirect — เงื่อนไขของ redirect อัตโนมัติ (silent login) เท่านั้น
  // การกด login เองไม่ถูกบล็อกด้วย marker 2 ตัวแรก (ถูกบล็อกแค่กรณี redirect ถี่เกิน)
  allowsAutomaticRedirect(now: number): boolean {
    const state = this.read();
    if (state.loggedOutAt !== undefined) return false;
    if (state.lastErrorAt !== undefined && now - state.lastErrorAt < ERROR_COOLDOWN_MS) return false;
    return this.redirectsInWindow(state, now) < MAX_REDIRECTS;
  }

  /** ผู้ใช้กด login เอง — ลืมว่าเพิ่ง logout / เพิ่งเจอ error (แต่ยังนับ redirect ถี่ ๆ ต่อ) */
  clearMarkers(): void {
    const state = this.read();
    this.write({ redirects: state.redirects });
  }

  /** login สำเร็จ — เริ่มนับใหม่ทั้งหมด */
  reset(): void {
    this.write({ redirects: [] });
  }
}
