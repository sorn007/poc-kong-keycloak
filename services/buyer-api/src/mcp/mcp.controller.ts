import { All, Controller, Delete, Get, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { apiKeyVerifier } from '../central-auth';
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
    // Central API Key — ตรวจกับ ID Portal ทุก request (fail-closed) ผ่าน SDK
    const principal = await apiKeyVerifier.verify(
      apiKeyVerifier.extractKey(req.headers),
    );
    if (!principal) {
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
      const server = await buildServer(principal.scopes);
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
