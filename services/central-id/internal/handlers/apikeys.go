// Central API Keys — หน้าจอ + API สำหรับออก API key ที่ผูก scope
// • หน้า UI: GET /apikeys (ต้อง login — cookie central_session)
// • สร้าง: POST /apikeys/create (form: name, scopes=comma list) — auth: session cookie หรือ Bearer
// • รายการ: GET /apikeys/list (JSON, เฉพาะของเจ้าของ — key mask)
// • ยกเลิก: POST /apikeys/revoke (form: id)
// • ตรวจสำหรับ Kong/MCP: POST /apikeys/validate (form: key) → {active, owner, scopes}
//   ← endpoint เดียวกันคือ "contract" ที่ MCP server ใช้ได้ทันที (key คือความลับ — ไม่ต้อง auth เพิ่ม)
package handlers

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"

	"central/central-id/internal/apikeys"
	"central/central-id/internal/auth"
	"central/central-id/internal/sso"
	"central/central-id/internal/web"
)

// ownerFromRequest — หา username จาก session cookie หรือ Bearer token (issuer-only verify)
func ownerFromRequest(c *fiber.Ctx, k auth.Keyfunc, cfg auth.Config) string {
	if s := currentSession(k, cfg, c); s != nil {
		return s.Username
	}
	authz := c.Get("Authorization")
	if strings.HasPrefix(authz, "Bearer ") {
		token := strings.TrimPrefix(authz, "Bearer ")
		if claims, err := auth.VerifyIssuerOnly(k, cfg.Issuer, token); err == nil {
			if claims.PreferredUsername != "" {
				return claims.PreferredUsername
			}
			return claims.Subject
		}
	}
	return ""
}

// parseScopes — แตก comma/space separated scopes + ตรวจกับชุดที่ระบบรองรับ
func parseScopes(raw string) ([]string, bool) {
	seen := map[string]bool{}
	var out []string
	for _, s := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		if !apikeys.ValidScope(s) {
			return nil, false
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, false
	}
	sortStrings(out)
	return out, true
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := 0; j < len(s)-i; j++ {
			if s[j] > s[j+1] {
				s[j], s[j+1] = s[j+1], s[j]
			}
		}
	}
}

func maskKey(full string) string {
	if len(full) <= 16 {
		return full[:8] + "…"
	}
	return full[:16] + "…"
}

// ApiKeysPage — หน้าจัดการ API keys (UI — ต้อง login)
func ApiKeysPage(k auth.Keyfunc, cfg auth.Config, store apikeys.KeyStore) fiber.Handler {
	return func(c *fiber.Ctx) error {
		lang := web.LangOf(c)
		s := currentSession(k, cfg, c)
		if s == nil {
			return needLogin(c, k, cfg, lang)
		}
		keys := store.List(s.Username)
		var rows strings.Builder
		for _, key := range keys {
			status := fmt.Sprintf(`<span class="pill ok">%s</span>`, web.T(lang, "ใช้งานได้", "Active"))
			if key.Revoked {
				status = fmt.Sprintf(`<span class="pill warn">%s</span>`, web.T(lang, "ถูกยกเลิก", "Revoked"))
			}
			scopes := ""
			for _, sc := range key.Scopes {
				scopes += fmt.Sprintf(`<span class="pill">%s</span>`, web.Esc(sc))
			}
			revokeBtn := ""
			if !key.Revoked {
				revokeBtn = fmt.Sprintf(`<form method="post" action="/apikeys/revoke" style="display:inline">
<input type="hidden" name="id" value="%s"><button class="btn btn-ghost btn-sm" onclick="return confirm('%s')">%s</button></form>`,
					web.Esc(key.ID), web.T(lang, "ยืนยันการยกเลิก key นี้?", "Revoke this key?"), web.T(lang, "ยกเลิก", "Revoke"))
			}
			lastUsed := key.LastUsed.Format("2006-01-02 15:04")
			if key.LastUsed.IsZero() {
				lastUsed = "—"
			}
			rows.WriteString(fmt.Sprintf(`<tr>
<td><code>%s…</code><br><small style="color:var(--muted)">%s</small></td>
<td>%s</td><td>%s</td><td>%s</td><td class="count">%s</td><td>%s</td></tr>`,
				web.Esc(key.ID), web.Esc(maskKey(key.Key)), web.Esc(key.Name),
				status, scopes, lastUsed, revokeBtn))
		}
		if rows.Len() == 0 {
			rows.WriteString(fmt.Sprintf(`<tr><td colspan="6" style="color:var(--muted)">%s</td></tr>`,
				web.T(lang, "ยังไม่มี API key — สร้างใบแรกด้านบน", "No API keys yet — create your first key above")))
		}

		scopeBoxes := ""
		for _, sc := range apikeys.AvailableScopes {
			scopeBoxes += fmt.Sprintf(`<label style="margin-right:14px"><input type="checkbox" name="scopes" value="%s"> <code>%s</code></label>`, sc, sc)
		}

		body := fmt.Sprintf(`<div class="notice ok"><b>%s</b> — %s</div>
<div class="card"><h2>%s</h2><p class="sub">%s (<code>apikey</code> %s) · %s <code>POST /apikeys/validate</code></p>
<form method="post" action="/apikeys/create">
<label>%s</label> <input name="name" required style="padding:8px;border:1px solid #cbd5e1;border-radius:8px;width:220px">
<div style="margin:10px 0">%s</div>
<button class="btn btn-primary btn-sm" type="submit">%s</button>
</form>
<div id="newkey" style="display:none;margin-top:14px"><div class="notice ok"><b>%s</b><br><code id="keyval" style="font-size:14px;user-select:all"></code><br><span style="color:var(--muted);font-size:12.5px">%s</span></div></div>
</div>
<div class="card"><h2>%s</h2>
<table><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th></th></tr>%s</table></div>
<div class="card"><h2>%s</h2>
<table><tr><th>%s</th><td><code>apikey: &lt;key&gt;</code> %s Kong <code>/openapi/apikey/*</code></td></tr>
<tr><th>%s</th><td><code>POST /apikeys/validate</code> <code>key=&lt;key&gt;</code> → <code>{active, owner, scopes}</code> — %s</td></tr></table></div>`,
			web.T(lang, "Central API Keys", "Central API Keys"),
			web.T(lang, "key ของคุณผูกกับ scope — ใช้เรียก Open API ผ่าน Kong หรือใช้กับ MCP server ได้ (ตรวจผ่าน endpoint เดียวกัน)",
				"your key is bound to scopes — call Open APIs via Kong or use it with MCP servers (validated through the same endpoint)"),
			web.T(lang, "สร้าง API key ใหม่", "Create a new API key"),
			web.T(lang, "scope กำหนดว่า key นี้เรียกอะไรได้", "scopes decide what this key may call"),
			web.T(lang, "ส่งเป็น header", "sent as the header"),
			web.T(lang, "ตรวจโดยระบบ:", "validated by the system:"),
			web.T(lang, "ชื่อ (เช่น mcp-prod)", "Name (e.g. mcp-prod)"),
			scopeBoxes,
			web.T(lang, "สร้าง key", "Create key"),
			web.T(lang, "⚠️ คัดลอก key เดี๋ยวนี้ — ระบบจะไม่แสดงอีก", "⚠️ Copy this key now — it will not be shown again"),
			web.T(lang, "เก็บไว้ที่ไหนก็ได้ให้ปลอดภัย", "store it somewhere safe"),
			web.T(lang, "API keys ของคุณ", "Your API keys"),
			web.T(lang, "key", "key"), web.T(lang, "ชื่อ", "Name"),
			web.T(lang, "สถานะ", "Status"), web.T(lang, "scopes", "scopes"),
			web.T(lang, "ใช้ล่าสุด", "Last used"), rows.String(),
			web.T(lang, "วิธีใช้งาน", "How to use"),
			web.T(lang, "เรียก Open API ผ่าน Kong:", "Call Open APIs via Kong:"),
			web.T(lang, "header", "header"),
			web.T(lang, "สำหรับ MCP server:", "For MCP servers:"),
			web.T(lang, "MCP server ใช้ endpoint นี้ตรวจ key + บังคับ scope ต่อ tool — contract เดียวกับ Kong plugin",
				"an MCP server validates the key via this endpoint and enforces per-tool scopes — the same contract as the Kong plugin"))

		extra := `<script>
document.querySelector('form[action="/apikeys/create"]').addEventListener('submit', async function(e){
  e.preventDefault();
  const fd=new FormData(this);
  const scopes=fd.getAll('scopes').join(',');
  const res=await fetch('/apikeys/create',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams({name:fd.get('name'),scopes})});
  if(!res.ok){const j=await res.json().catch(()=>({}));alert((j.error||'error')+' '+(j.detail||''));return;}
  const j=await res.json();
  document.getElementById('newkey').style.display='block';
  document.getElementById('keyval').textContent=j.key;
  this.querySelector('button[type="submit"]').disabled=true;
});
</script>`

		return c.Type("html").SendString(web.Page(struct {
			Title      string
			Body       string
			ActiveStep int
			DoneUntil  int
			Session    *web.Session
			PageName   string
			Lang       string
		}{
			Title: web.T(lang, "ID — Central API Keys", "ID — Central API Keys"), Body: body + extra,
			ActiveStep: 0, DoneUntil: 0, Session: s, PageName: "", Lang: lang,
		}))
	}
}

// CreateAPIKey — ออก key ใหม่ (auth: session หรือ Bearer) — คืน key เต็มครั้งเดียว
func CreateAPIKey(k auth.Keyfunc, cfg auth.Config, store apikeys.KeyStore) fiber.Handler {
	return func(c *fiber.Ctx) error {
		owner := ownerFromRequest(c, k, cfg)
		if owner == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		scopes, ok := parseScopes(c.FormValue("scopes"))
		if !ok {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid_scopes", "detail": "allowed: " + strings.Join(apikeys.AvailableScopes, ", "),
			})
		}
		name := strings.TrimSpace(c.FormValue("name"))
		if name == "" {
			name = "key"
		}
		record, full := store.Create(owner, name, scopes)
		return c.JSON(fiber.Map{
			"key_id": record.ID,
			"key":    full, // แสดงครั้งเดียว
			"name":   record.Name,
			"owner":  owner,
			"scopes": scopes,
			"hint":   "คัดลอก key ตอนนี้ — ระบบจะไม่แสดงอีก",
		})
	}
}

// ListAPIKeys — รายการ keys ของผู้ใช้ (JSON — key แบบ mask)
func ListAPIKeys(k auth.Keyfunc, cfg auth.Config, store apikeys.KeyStore) fiber.Handler {
	return func(c *fiber.Ctx) error {
		owner := ownerFromRequest(c, k, cfg)
		if owner == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		out := []fiber.Map{}
		for _, key := range store.List(owner) {
			out = append(out, fiber.Map{
				"key_id": key.ID, "key_masked": maskKey(key.Key), "name": key.Name,
				"scopes": key.Scopes, "revoked": key.Revoked, "created_at": key.CreatedAt.Unix(),
			})
		}
		return c.JSON(fiber.Map{"owner": owner, "keys": out})
	}
}

// RevokeAPIKey — ยกเลิก key (เฉพาะเจ้าของ) — ตรวจ "ทั้งสอง registry":
// 1) apiKeyStore (Central API Key)  2) ssoStore (SSO Ticket)
// เพราะ endpoint เดียวกันถูกใช้ revoke ได้ทั้ง credential สองประเภท — id ที่ไม่เจอใน store
// ใด store หนึ่งอาจเป็นของอีก store (ผู้ใช้/script ไม่จำเป็นต้องรู้ว่า id นั้นเป็นชนิดไหน)
func RevokeAPIKey(k auth.Keyfunc, cfg auth.Config, store apikeys.KeyStore, ssoStore sso.TicketStore) fiber.Handler {
	return func(c *fiber.Ctx) error {
		owner := ownerFromRequest(c, k, cfg)
		if owner == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		id := c.FormValue("id")
		if store.Revoke(owner, id) {
			return c.JSON(fiber.Map{"revoked": true, "key_id": id, "type": "api_key"})
		}
		if user, ok := ssoStore.Revoke(id); ok {
			return c.JSON(fiber.Map{"revoked": true, "ticket_id": id, "type": "sso_ticket", "username": user})
		}
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "key_not_found_or_already_revoked"})
	}
}

// ValidateAPIKey — ตรวจ key สำหรับ Kong plugin / MCP server (key คือความลับ — ไม่ต้อง auth เพิ่ม)
// คืน active + owner + scopes — inactive ก็ตอบ 200 (active:false) ตามธรรมเนียม RFC 7662
func ValidateAPIKey(store apikeys.KeyStore) fiber.Handler {
	return func(c *fiber.Ctx) error {
		key := c.FormValue("key")
		if key == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "key_required"})
		}
		if rec := store.Validate(key); rec != nil {
			return c.JSON(fiber.Map{
				"active": true, "owner": rec.Owner, "name": rec.Name,
				"scopes": rec.Scopes, "token_type": "central_api_key",
			})
		}
		return c.JSON(fiber.Map{"active": false})
	}
}
