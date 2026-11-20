import { All, Controller, Delete, Get, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { config } from '../config';

// MCP Server (remote HTTP — Streamable HTTP transport, JSON โหมด) ของ Buyer
// • ปลายทาง: POST /mcp (JSON-RPC 2.0) — initialize / tools/list / tools/call
// • Auth: Central API Key (header `apikey` หรือ `Authorization: Bearer central_…`)
//   ตรวจกับ ID Portal /apikeys/validate → ได้ owner + scopes ของ key
// • Tools ถูก "กรองตาม scope ของ key" — tools/list แสดงเฉพาะ tool ที่ scope ครอบ
//   (key ที่ไม่มี orders.write จะไม่เห็น create_order เลย)
// • Streamable HTTP โหมด stateless: transport/server ใหม่ต่อ request (ไม่มี SSE session)
//   GET/DELETE → 405 ตามข้ออนุญาตของ spec (server ไม่มี server→client stream)
// • ใช้ official SDK ผ่าน dynamic import (SDK เป็น ESM — โหลดตอน runtime บน Node 22)

const ID_PORTAL = process.env.IDPORTAL_INTERNAL_BASE ?? 'http://central-id:3000';

type KeyAuth = { ok: boolean; owner: string; scopes: string[] };

async function validateKey(req: Request): Promise<KeyAuth> {
  let key: string | undefined = req.headers['apikey'] as string | undefined;
  const authz = req.headers['authorization'] as string | undefined;
  if (!key && authz && authz.startsWith('Bearer central_')) {
    key = authz.slice('Bearer '.length);
  }
  if (!key) return { ok: false, owner: '', scopes: [] };
  try {
    const r = await fetch(`${ID_PORTAL}/apikeys/validate`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ key }),
      signal: AbortSignal.timeout(8000),
    });
    const out = (await r.json()) as {
      active?: boolean;
      owner?: string;
      scopes?: string[];
    };
    if (!r.ok || out.active !== true || !out.owner) {
      return { ok: false, owner: '', scopes: [] };
    }
    return { ok: true, owner: out.owner, scopes: out.scopes ?? [] };
  } catch {
    return { ok: false, owner: '', scopes: [] };
  }
}

const DEMO_ORDERS = [
  { orderId: 'ORD-001', company: 'company_001', total: 1500, status: 'success' },
];

// สร้าง McpServer — ลงทะเบียน tool ครบทุกตัว แต่ **บังคับ scope ตอน execute**
// (tools/list เห็น tool ได้ทุกตัว; การเรียกที่ scope ไม่พอ → isError + เหตุผลชัดเจน)
async function buildServer(scopes: string[]) {
  const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
  const server = new McpServer({ name: 'central-buyer-mcp', version: '1.0.0' });
  const text = (obj: unknown) => ({
    content: [{ type: 'text' as const, text: JSON.stringify(obj) }],
  });
  const denied = (scope: string) => ({
    isError: true,
    content: [
      {
        type: 'text' as const,
        text: `Forbidden: this api key lacks scope "${scope}" — create a new key with this scope at the ID Portal (/apikeys)`,
      },
    ],
  });
  const has = (s: string) => scopes.includes(s);

  // ไม่ต้องใช้ scope — แสดงตัวตนของ key
  server.registerTool(
    'whoami',
    { title: 'Who am I', description: 'Return the api key owner and its scopes' },
    async () => text({ scopes }),
  );

  server.registerTool(
    'list_orders',
    { title: 'List orders', description: 'List Buyer orders (requires scope: orders.read)' },
    async () => {
      if (!has('orders.read')) return denied('orders.read');
      return text({ orders: DEMO_ORDERS });
    },
  );

  server.registerTool(
    'create_order',
    { title: 'Create order', description: 'Create a demo Buyer order (requires scope: orders.write)' },
    async () => {
      if (!has('orders.write')) return denied('orders.write');
      return text({ created: true, orderId: 'ORD-' + Date.now() });
    },
  );

  return server;
}

@Controller('mcp')
export class McpController {
  // Streamable HTTP: POST /mcp — JSON-RPC เดี่ยว (โหมด stateless: transport ใหม่ต่อ request)
  @Post()
  async post(@Req() req: Request, @Res() res: Response) {
    const auth = await validateKey(req);
    if (!auth.ok) {
      return res.status(401).json({
        error: 'unauthorized',
        detail:
          'valid Central API Key required (apikey header or Authorization: Bearer central_…)',
      });
    }

    try {
      const [{ McpServer }, { StreamableHTTPServerTransport }] =
        await Promise.all([
          import('@modelcontextprotocol/sdk/server/mcp.js'),
          import('@modelcontextprotocol/sdk/server/streamableHttp.js'),
        ]);
      const server = await buildServer(auth.scopes);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined, // stateless
        enableJsonResponse: true, // JSON โหมดเดียว — ไม่เปิด SSE stream
      });
      res.on('close', () => {
        transport.close();
        server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req as unknown as import("http").IncomingMessage, res as unknown as import("http").ServerResponse, req.body);
    } catch (e) {
      const message = e instanceof Error ? e.message : 'mcp failure';
      if (!res.headersSent) {
        res.status(500).json({ error: 'mcp_failure', detail: message });
      } else {
        res.end();
      }
    }
  }

  // Streamable HTTP: GET /mcp ใช้สำหรับ server→client stream (SSE) — stateless ไม่เปิด
  @Get()
  get(@Res() res: Response) {
    res.status(405).json({ error: 'method not allowed (stateless server)' });
  }

  @Delete()
  delete(@Res() res: Response) {
    res.status(405).json({ error: 'method not allowed (stateless server)' });
  }
}
