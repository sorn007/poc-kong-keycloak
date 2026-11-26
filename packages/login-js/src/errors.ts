// LoginError — ข้อผิดพลาดที่ SDK โยนออกมาทั้งหมด (code เป็นค่าคงที่ให้แอปแยกทางเลือกได้)
export type LoginErrorCode =
  // การตั้งค่า / สภาพแวดล้อมของเบราว์เซอร์
  | 'invalid_configuration' // issuer/clientId/redirectUri ไม่ถูกต้อง
  | 'no_webcrypto'          // เบราว์เซอร์ไม่มี crypto.subtle (ไม่ใช่ secure context) — SDK ไม่ลดความปลอดภัยลงเพื่อทำงานต่อ
  | 'storage_unavailable'   // เขียน sessionStorage ไม่ได้ — ทำ PKCE ข้าม redirect แบบปลอดภัยไม่ได้ (fail-closed)
  // callback จาก OP
  | 'unrecognized_state'    // callback มาถึงแต่ไม่มี transaction ที่ตรงกับ state (login ข้ามแท็บ / เปิด callback ซ้ำ)
  | 'issuer_mismatch'       // iss ใน callback ไม่ใช่ issuer ที่กำหนด (mix-up attack)
  | 'authorization_failed'  // OP ตอบกลับด้วย error (เช่น login_required จาก silent login, access_denied)
  // token endpoint
  | 'token_request_failed'  // เรียก token endpoint แล้วไม่สำเร็จ
  | 'token_rejected'        // OP ตอบ invalid_grant (code หมดอายุ/ใช้แล้ว/verifier ไม่ตรง)
  | 'network_error'         // เชื่อมต่อไม่ได้ — มักเพราะ webOrigins ของ client ไม่ครอบคลุม origin ของแอป
  // token
  | 'invalid_id_token'      // id_token ไม่ผ่านการตรวจ (ลายเซ็น / alg / kid / iss / aud / azp / exp / nonce / at_hash)
  | 'not_authenticated'     // ยังไม่มี session
  | 'refresh_rejected'      // refresh token ถูกปฏิเสธ — session ฝั่ง server จบแล้ว
  // กันวน
  | 'loop_detected'         // redirect ไป OP บ่อยเกินไปในเวลาสั้น ๆ
  | 'internal_error';        // ข้อผิดพลาดที่ SDK ไม่ได้คาด (เก็บไว้สำหรับ debug)

export class LoginError extends Error {
  readonly code: LoginErrorCode;
  /** รายละเอียดจาก OP หรือจาก SDK — ไม่มีความลับ แสดงกับผู้ใช้หรือใส่ log ได้ */
  readonly detail: string | undefined;

  constructor(code: LoginErrorCode, message: string, detail?: string) {
    super(detail ? `${message} (${detail})` : message);
    this.name = 'LoginError';
    this.code = code;
    this.detail = detail;
  }
}
