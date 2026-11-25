import {
  Controller,
  ForbiddenException,
  Get,
  Header,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { config } from '../config';
import { CentralAuthGuard } from '../auth/central-auth.guard';
import { DualAuthGuard } from '../auth/dual-auth.guard';
import { LegacyAuthGuard } from '../auth/legacy-auth.guard';
import { RequireScope, ScopeGuard } from '../auth/scope.guard';
import { page, readSession, toastScript } from '../ui';
import { clearSsoCookies, isTicketAlive } from '../auth/sso-guard';
import { langOf, t } from '../i18n';

@Controller()
export class OrdersController {
  // ปกติ — central token + scope (เส้นทางเป้าหมายหลัง migration)
  @Get('orders')
  @UseGuards(CentralAuthGuard, ScopeGuard)
  @RequireScope('orders.read')
  list(@Req() req: Request) {
    return { ok: true, auth: req.auth, orders: [orderDemo()] };
  }

  // ใช้ทดสอบ 403: partner-001 ไม่มี orders.write
  @Post('orders')
  @UseGuards(CentralAuthGuard, ScopeGuard)
  @RequireScope('orders.write')
  create(@Req() req: Request) {
    return { ok: true, created: true, by: req.auth?.subject };
  }

  // Dual Validation — รับทั้ง central และ legacy token (ช่วง migration)
  @Get('orders/dual')
  @UseGuards(DualAuthGuard)
  dual(@Req() req: Request) {
    return { ok: true, validatorResult: 'dual', auth: req.auth };
  }

  // Legacy เท่านั้น — พฤติกรรมระบบเดิมก่อน migration
  @Get('orders/legacy')
  @UseGuards(LegacyAuthGuard)
  legacy(@Req() req: Request) {
    return { ok: true, validatorResult: 'legacy', auth: req.auth };
  }

  // เส้นทาง Open API — ให้ Kong forward มา + ใช้เรียกตรงจาก script ได้
  // ตรวจ scope + tenant binding ของ principal (ผู้รับผิดชอบ tenant คือ Buyer เอง)
  @Get('open-api/orders')
  @UseGuards(CentralAuthGuard, ScopeGuard)
  @RequireScope('orders.read')
  openApi(@Req() req: Request) {
    const auth = req.auth;
    if (
      auth?.principalType === 'service' &&
      auth.tenantId !== config.allowedTenant
    ) {
      throw new ForbiddenException({ error: 'tenant_not_authorized' });
    }
    return {
      ok: true,
      principalType: auth?.principalType,
      tenantId: auth?.tenantId,
      orders: [orderDemo()],
    };
  }

  // หน้าจอ Orders ของ Buyer Portal — data มาจาก fetch('/orders') โดยใช้ cookie session
  // (cookie → Authorization header ผ่าน middleware ใน main.ts — จำลอง BFF, POC only)
  @Get('orders/page')
  @Header('Content-Type', 'text/html; charset=utf-8')
  async page(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const lang = langOf(req, res);
    const s = readSession(req);

    // Logout กลาง propagate — session ผูกกับตั๋ว SSO: ตั๋วตาย → เคลียร์ + กลับ landing
    // (เพิ่มความสม่ำเสมอกับหน้า Home — ทุกหน้า page-render ตรวจ liveness ของตั๋ว)
    if (s && req.cookies?.['sso_bound']) {
      const alive = await isTicketAlive(req.cookies['sso_bound']);
      if (!alive) {
        clearSsoCookies(res);
        return res.redirect('/auth/login');
      }
    }

    const body = `<div class="card">
  <h2>Orders <span class="sub" id="who"></span></h2>
  <p class="sub">${t(lang, 'ข้อมูลจาก', 'Data from')} <code>GET /orders</code> — ${t(lang, 'Guard ตรวจ central token (JWKS) + scope', 'the Guard verifies the central token (JWKS) + scope')} <code>orders.read</code> ${t(lang, 'ทุกครั้ง', 'every time')}</p>
  <div id="state"><p class="sub">${t(lang, 'กำลังโหลด…', 'Loading…')}</p></div>
  <table id="tbl" style="display:none">
    <thead><tr><th>Order ID</th><th>Company</th><th>${t(lang, 'ยอดรวม (บาท)', 'Total (THB)')}</th><th>${t(lang, 'สถานะ', 'Status')}</th></tr></thead>
    <tbody></tbody>
  </table>
  <div class="actions" style="margin-top:14px">
    <button class="btn btn-primary btn-sm" onclick="createOrder()">+ ${t(lang, 'สร้าง Order', 'Create order')}</button>
    <span class="sub" style="align-self:center">${t(lang, 'ต้องมี scope', 'Requires scope')} <code>orders.write</code> — ${t(lang, 'partner-001 (มีเฉพาะ read) จะได้ 403', 'partner-001 (read only) gets a 403')}</span>
  </div>
</div>
<script>
${toastScript()}
async function load() {
  const st = document.getElementById('state');
  const r = await fetch('/orders');
  if (r.status === 401 || r.status === 403) {
    st.outerHTML = '<div class="notice err"><b>${t(lang, 'ไม่ได้รับอนุญาต (', 'Not authorized (')}' + r.status + ')</b> — ${t(lang, 'session หมดอายุหรือ scope ไม่พอ', 'session expired or scope insufficient')} <a href="/auth/login">${t(lang, 'ล็อกอินใหม่', 'sign in again')}</a></div>';
    return;
  }
  const j = await r.json();
  st.textContent = '';
  document.getElementById('who').textContent = '— ${t(lang, 'ผู้ใช้:', 'user:')} ' + (j.auth?.subject ?? '?').slice(0,8) + '… (scope: ' + (j.auth?.scopes ?? []).join(', ') + ')';
  const tb = document.querySelector('#tbl tbody');
  tb.innerHTML = j.orders.map(o =>
    '<tr><td><b>' + o.orderId + '</b></td><td><code>' + o.companyId + '</code></td><td>' + o.total.toLocaleString() + '</td><td><span class="pill ok">${t(lang, 'สำเร็จ', 'Success')}</span></td></tr>').join('');
  document.getElementById('tbl').style.display = 'table';
}
async function createOrder() {
  const r = await fetch('/orders', { method: 'POST' });
  if (r.status === 201 || r.status === 200) { toast('${t(lang, 'สร้าง Order สำเร็จ — ผ่าน scope orders.write', 'Order created — passed the orders.write scope')}'); load(); }
  else if (r.status === 403) { toast('${t(lang, '403 — scope ไม่พอ (ต้องมี orders.write)', '403 — insufficient scope (orders.write required)')}'); }
  else { toast('${t(lang, 'ล้มเหลว HTTP ', 'Failed HTTP ')}' + r.status); }
}
load();
</script>`;
    res.send(
      page({
        title: 'Buyer Portal — Orders',
        body,
        activeStep: 2,
        doneUntil: 2,
        session: s,
        appName: 'Buyer Portal',
        dataPage: 'orders',
        otherAppUrl: 'http://localhost:3020',
        otherAppLabel: 'CIS Portal',
        lang,
      }),
    );
  }
}

function orderDemo() {
  return { orderId: 'ORD-001', companyId: config.allowedTenant, total: 1500 };
}
