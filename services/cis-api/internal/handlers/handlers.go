// Package handlers — demo endpoints ของ CIS (projects)
package handlers

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	jwt "github.com/golang-jwt/jwt/v5"

	"central/auth-go"
	"central/cis-api/internal/oidc"
	"central/cis-api/internal/web"
)

const allowedTenant = "company_001"

func demoProject() fiber.Map {
	return fiber.Map{"projectId": "PRJ-001", "companyId": allowedTenant, "status": "active"}
}

// Home — หน้าแรกของ CIS Portal ตาม flow rootcase:
// [1] ล็อกอิน ID (Keycloak login) → [2] Buyer Portal → [3] CIS Portal (SSO) → [4] Logout กลาง
func Home(k auth.Keyfunc, cfg auth.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		lang := web.LangOf(c)
		token := c.Cookies("cis_session")

		// ยังไม่ login → ถ้า browser มีตั๋ว SSO ของ ID กลาง ให้พาไป /auth/login
		// (ตรงนั้น redeem ตั๋วเงียบ ๆ แล้วพากลับมาที่นี่ — cookie sso_try กันวน loop)
		if token == "" && c.Cookies(oidc.SSOCookieName) != "" && c.Cookies("sso_try_cis") == "" {
			return c.Redirect("/auth/login", fiber.StatusFound)
		}

		// ยังไม่ login → hero + ปุ่มเข้าสู่ระบบผ่าน ID
		if token == "" {
			body := `<section class="hero">
<h1>Central CIS Portal</h1>
<p>` + web.T(lang, "ระบบข้อมูลโครงการ (Go Fiber) — ล็อกอินผ่าน <b>ID</b> (Central Identity) ครั้งเดียว", "Project information system (Go Fiber) — sign in via <b>ID</b> (Central Identity) once") + `<br>
` + web.T(lang, "ถ้าเพิ่งล็อกอินที่ Buyer Portal ระบบจะ <b>SSO อัตโนมัติ</b> โดยไม่ถามรหัสผ่าน", "If you just signed in at Buyer Portal, it <b>SSOs automatically</b> without asking for a password") + `</p>
<a class="btn btn-primary" href="/auth/login">` + web.T(lang, "เข้าสู่ระบบด้วย ID", "Sign in with ID") + `</a>
<p style="margin-top:18px;font-size:13px;color:#bbf7d0">` + web.T(lang, "ถ้ามี SSO session อยู่ จะกลับมาที่หน้านี้ทันทีโดยไม่เจอหน้า login", "If an SSO session exists, you come right back here without seeing a login page") + `</p>
</section>
<div class="card"><h2>` + web.T(lang, "มีอะไรให้ทดลอง", "What to try") + `</h2><p class="sub">` + web.T(lang, "ล็อกอินแล้วจะเห็น: โปรไฟล์จาก claims, Projects, ปุ่มกลับไป Buyer (SSO) และ Logout กลาง", "After signing in you get: profile from claims, Projects, a button back to Buyer (SSO) and global logout") + `</p>
<ul style="font-size:14px;line-height:1.9">
<li><b>ID</b> = Keycloak realm <code>central</code> — ` + web.T(lang, "session กลางของทุกระบบ", "the central session of every system") + `</li>
<li>` + web.T(lang, "CIS ตรวจ token เองผ่าน JWKS:", "CIS verifies tokens itself via JWKS:") + ` <code>iss</code> + <code>aud=cis-api</code> + <code>exp</code> + scope</li>
<li>` + web.T(lang, "token ของ Buyer", "A Buyer token") + ` (<code>aud=buyer-api</code>) ` + web.T(lang, "ต้องถูกปฏิเสธที่นี่ — กัน cross-audience confusion", "must be rejected here — prevents cross-audience confusion") + `</li>
</ul></div>`
			return c.Type("html").SendString(web.Page(struct {
				Title      string
				Body       string
				ActiveStep int
				DoneUntil  int
				Session    *web.Session
				AppName    string
				DataPage   string
				OtherURL   string
				OtherLabel string
				Lang       string
			}{
				Title: "Central CIS Portal", Body: body, ActiveStep: 1, DoneUntil: 2,
				Session: nil, AppName: "CIS Portal", DataPage: "home",
				OtherURL: "http://localhost:3010", OtherLabel: "Buyer Portal", Lang: lang,
			}))
		}

		// มี cookie — verify ก่อนเชื่อถือ (signature/iss/aud/exp ผ่าน JWKS)
		claims, err := auth.VerifyCentral(k, cfg, token)
		if err == nil && c.Cookies("sso_bound") != "" {
			// Logout กลาง propagate — session ผูกกับตั๋ว SSO: ตั๋วถูก revoke/logout-all ที่ไหนก็ได้
			// → เคลียร์ session + cookie ตั๋ว แล้วกลับ "หน้า landing ของแอปเรา" (ไม่พาไปหน้า login ของ Keycloak เอง)
			if !oidc.TicketAlive(c.Cookies("sso_bound")) {
				clearLocal := func(name string) {
					c.Cookie(&fiber.Cookie{Name: name, Value: "", Path: "/", Expires: time.Now().Add(-time.Hour), MaxAge: -1, HTTPOnly: true, SameSite: "Lax"})
				}
				clearLocal("cis_session")
				clearLocal("cis_id_token")
				clearLocal("sso_bound")
				clearLocal("sso_try_cis")
				clearLocal("central_sso")
				return c.Redirect("/", fiber.StatusFound)
			}
		}
		if err != nil {
			// token หมดอายุ/ไม่ถูกต้อง — ถ้า browser ยังมีตั๋ว SSO ให้ลอง redeem ใหม่ให้เงียบ ๆ
			// (ตั๋วยังอยู่ = broker renew token ใหม่ → กลับเข้าระบบได้เลย; ตั๋วตาย → กลับหน้า landing)
			if c.Cookies("central_sso") != "" && c.Cookies("sso_try_cis") == "" {
				clearLocal := func(name string) {
					c.Cookie(&fiber.Cookie{Name: name, Value: "", Path: "/", Expires: time.Now().Add(-time.Hour), MaxAge: -1, HTTPOnly: true, SameSite: "Lax"})
				}
				clearLocal("cis_session")
				clearLocal("cis_id_token")
				clearLocal("sso_bound")
				clearLocal("sso_try_cis")
				return c.Redirect("/auth/login", fiber.StatusFound)
			}
			body := `<div class="notice warn"><b>` + web.T(lang, "Session หมดอายุหรือไม่ถูกต้อง", "Session expired or invalid") + `</b> — ` + web.T(lang, "token ในเครื่องไม่ผ่านการตรวจจาก JWKS ของ ID (อาจถูก logout กลางหรือ exp หมด)", "the local token did not pass ID's JWKS verification (globally logged out or exp passed)") + `</div>
<div class="card"><h2>` + web.T(lang, "เริ่มใหม่", "Start over") + `</h2><div class="actions"><a class="btn btn-primary" href="/auth/login">` + web.T(lang, "ล็อกอินอีกครั้งด้วย ID", "Sign in again with ID") + `</a></div></div>`
			return c.Type("html").SendString(web.Page(struct {
				Title      string
				Body       string
				ActiveStep int
				DoneUntil  int
				Session    *web.Session
				AppName    string
				DataPage   string
				OtherURL   string
				OtherLabel string
				Lang       string
			}{
				Title: "Central CIS Portal — " + web.T(lang, "Session หมดอายุ", "Session expired"), Body: body, ActiveStep: 1, DoneUntil: 2,
				Session: sessionFromUnverified(token), AppName: "CIS Portal", DataPage: "home",
				OtherURL: "http://localhost:3010", OtherLabel: "Buyer Portal", Lang: lang,
			}))
		}

		s := sessionFromClaims(claims)
		body := `<div class="notice ok"><b>` + web.T(lang, "ล็อกอินผ่าน ID อยู่", "Signed in via ID") + `</b> — ` + web.T(lang, "session กลางนี้ใช้ได้ทั้ง Buyer และ CIS", "this central session works on both Buyer and CIS") + `</div>
` + web.SessionCards(s, lang) + `
<div class="card"><h2>` + web.T(lang, "ไปต่อใน flow", "Continue the flow") + `</h2><p class="sub">` + web.T(lang, "เส้นทางทดสอบตาม rootcase — ล็อกอินครั้งเดียว ใช้ได้ทุกระบบ จนกว่าจะ logout กลาง", "Test path per rootcase — sign in once, use everywhere, until global logout") + `</p>
<div class="actions">
<a class="btn btn-primary btn-sm" href="/projects/page">` + web.T(lang, "จัดการ Projects", "Manage Projects") + `</a>
<a class="btn btn-ghost btn-sm" href="http://localhost:3000">` + web.T(lang, "ID — บัญชีกลาง", "ID — central account") + `</a>
<a class="btn btn-ghost btn-sm" href="http://localhost:3010">` + web.T(lang, "กลับ Buyer Portal (SSO)", "Back to Buyer Portal (SSO)") + `</a>
<a class="btn btn-ghost btn-sm" href="/auth/logout">` + web.T(lang, "Logout กลาง (ทุกระบบ)", "Global logout (all systems)") + `</a>
</div></div>
<script>` + web.ToastScript + `</script>`
		return c.Type("html").SendString(web.Page(struct {
			Title      string
			Body       string
			ActiveStep int
			DoneUntil  int
			Session    *web.Session
			AppName    string
			DataPage   string
			OtherURL   string
			OtherLabel string
			Lang       string
		}{
			Title: "Central CIS Portal", Body: body, ActiveStep: 3, DoneUntil: 2,
			Session: s, AppName: "CIS Portal", DataPage: "home",
			OtherURL: "http://localhost:3010", OtherLabel: "Buyer Portal", Lang: lang,
		}))
	}
}

// ProjectsList — GET /projects (ต้องผ่าน central auth + projects.read)
func ProjectsList() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, _ := c.Locals("auth").(*auth.Claims)
		return c.JSON(fiber.Map{"ok": true, "auth": claimsView(claims), "projects": []fiber.Map{demoProject()}})
	}
}

// ProjectsCreate — POST /projects (ต้องมี projects.write — ใช้ทดสอบ 403)
func ProjectsCreate() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, _ := c.Locals("auth").(*auth.Claims)
		return c.JSON(fiber.Map{"ok": true, "created": true, "by": claims.Subject})
	}
}

// OpenApiProjects — เส้นทาง Open API (Kong forward มา หรือเรียกตรง)
// ตรวจ tenant binding ของ service principal ที่ CIS เอง
func OpenApiProjects() fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, _ := c.Locals("auth").(*auth.Claims)
		if claims.PrincipalType == "service" && claims.TenantID != allowedTenant {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "tenant_not_authorized"})
		}
		return c.JSON(fiber.Map{
			"ok":            true,
			"principalType": claims.PrincipalType,
			"tenantId":      claims.TenantID,
			"projects":      []fiber.Map{demoProject()},
		})
	}
}

// ProjectsPage — หน้าจอ Projects ของ CIS Portal — data มาจาก fetch('/projects') โดยใช้ cookie session
// (cookie → Authorization header ผ่าน middleware ใน main.go — จำลอง BFF, POC only)
func ProjectsPage(k auth.Keyfunc, cfg auth.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		lang := web.LangOf(c)
		var s *web.Session
		if token := c.Cookies("cis_session"); token != "" {
			// Logout กลาง propagate — session ผูกกับตั๋ว SSO: ตั๋วตาย → เคลียร์ session
			// (เพิ่มความสม่ำเสมอกับหน้า Home — ตรวจ liveness ทุกหน้า page ที่ render)
			if c.Cookies("sso_bound") != "" && !oidc.TicketAlive(c.Cookies("sso_bound")) {
				clearLocal := func(name string) {
					c.Cookie(&fiber.Cookie{Name: name, Value: "", Path: "/", Expires: time.Now().Add(-time.Hour), MaxAge: -1, HTTPOnly: true, SameSite: "Lax"})
				}
				clearLocal("cis_session")
				clearLocal("cis_id_token")
				clearLocal("sso_bound")
				clearLocal("sso_try_cis")
				clearLocal("central_sso")
				return c.Redirect("/auth/login", fiber.StatusFound)
			}
			if claims, err := auth.VerifyCentral(k, cfg, token); err == nil {
				s = sessionFromClaims(claims)
			}
		}
		body := `<div class="card">
<h2>Projects <span class="sub" id="who"></span></h2>
<p class="sub">` + web.T(lang, "ข้อมูลจาก", "Data from") + ` <code>GET /projects</code> — ` + web.T(lang, "Middleware ตรวจ central token (JWKS) + scope", "middleware verifies the central token (JWKS) + scope") + ` <code>projects.read</code> ` + web.T(lang, "ทุกครั้ง", "every time") + `</p>
<div id="state"><p class="sub">` + web.T(lang, "กำลังโหลด…", "Loading…") + `</p></div>
<table id="tbl" style="display:none">
<thead><tr><th>Project ID</th><th>Company</th><th>` + web.T(lang, "สถานะ", "Status") + `</th></tr></thead>
<tbody></tbody>
</table>
<div class="actions" style="margin-top:14px">
<button class="btn btn-primary btn-sm" onclick="createProject()">+ ` + web.T(lang, "สร้าง Project", "Create Project") + `</button>
<span class="sub" style="align-self:center">` + web.T(lang, "ต้องมี scope", "Requires scope") + ` <code>projects.write</code></span>
</div></div>
<script>
` + web.ToastScript + `
async function load() {
  const st = document.getElementById('state');
  const r = await fetch('/projects');
  if (r.status === 401 || r.status === 403) {
    st.outerHTML = '<div class="notice err"><b>` + web.T(lang, "ไม่ได้รับอนุญาต", "Not authorized") + ` (' + r.status + ')</b> — ` + web.T(lang, "session หมดอายุหรือ scope ไม่พอ", "session expired or insufficient scope") + ` <a href="/auth/login">` + web.T(lang, "ล็อกอินใหม่", "Sign in again") + `</a></div>';
    return;
  }
  const j = await r.json();
  st.textContent = '';
  const a = j.auth || {};
  document.getElementById('who').textContent = '— ` + web.T(lang, "ผู้ใช้:", "User:") + ` ' + String(a.subject || '?').slice(0,8) + '… (scope: ' + (a.scopes || []).join(', ') + ')';
  const tb = document.querySelector('#tbl tbody');
  tb.innerHTML = j.projects.map(p =>
    '<tr><td><b>' + p.projectId + '</b></td><td><code>' + p.companyId + '</code></td><td><span class="pill ok">' + p.status + '</span></td></tr>').join('');
  document.getElementById('tbl').style.display = 'table';
}
async function createProject() {
  const r = await fetch('/projects', { method: 'POST' });
  if (r.status === 201 || r.status === 200) { toast('` + web.T(lang, "สร้าง Project สำเร็จ — ผ่าน scope projects.write", "Project created — via scope projects.write") + `'); load(); }
  else if (r.status === 403) { toast('403 — ` + web.T(lang, "scope ไม่พอ (ต้องมี projects.write)", "insufficient scope (needs projects.write)") + `'); }
  else { toast('` + web.T(lang, "ล้มเหลว HTTP", "Failed HTTP") + ` ' + r.status); }
}
load();
</script>`
		return c.Type("html").SendString(web.Page(struct {
			Title      string
			Body       string
			ActiveStep int
			DoneUntil  int
			Session    *web.Session
			AppName    string
			DataPage   string
			OtherURL   string
			OtherLabel string
			Lang       string
		}{
			Title: "CIS Portal — Projects", Body: body, ActiveStep: 3, DoneUntil: 3,
			Session: s, AppName: "CIS Portal", DataPage: "projects",
			OtherURL: "http://localhost:3010", OtherLabel: "Buyer Portal", Lang: lang,
		}))
	}
}

// MintLegacyToken — DEV ONLY: mint legacy token จำลอง (HS256) ให้ test script
func MintLegacyToken(cfg auth.Config, devMode bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !devMode {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "dev_mode_disabled"})
		}
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": cfg.LegacyIssuer,
			"sub": "legacy-cis-user",
			"jti": randomHex(8),
			"iat": now.Unix(),
			"exp": now.Add(5 * time.Minute).Unix(),
		})
		signed, err := tok.SignedString([]byte(cfg.LegacySecret))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"token": signed, "note": "DEV ONLY — legacy HS256 token จำลอง"})
	}
}

func claimsView(claims *auth.Claims) fiber.Map {
	if claims == nil {
		return fiber.Map{}
	}
	return fiber.Map{
		"subject":       claims.Subject,
		"clientId":      claims.ClientID,
		"principalType": claims.PrincipalType,
		"scopes":        claims.Scopes(),
		"tokenId":       claims.ID,
		"tenantId":      claims.TenantID,
		"issuer":        claims.Issuer,
	}
}

// sessionFromClaims — แปลง claims ที่ verify แล้วเป็นข้อมูลแสดงผล UI
func sessionFromClaims(claims *auth.Claims) *web.Session {
	if claims == nil {
		return nil
	}
	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = claims.Subject
	}
	var exp int64
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Unix()
	}
	return &web.Session{
		Username:      username,
		Email:         claims.Email,
		Sub:           claims.Subject,
		ClientID:      claims.ClientID,
		PrincipalType: claims.PrincipalType,
		TenantID:      claims.TenantID,
		Scopes:        claims.Scopes(),
		Exp:           exp,
		Issuer:        claims.Issuer,
	}
}

// sessionFromUnverified — decode เพื่อแสดงชื่อผู้ใช้บนหน้า "session หมดอายุ" เท่านั้น (ไม่ใช้ตัดสินสิทธิ์)
func sessionFromUnverified(token string) *web.Session {
	claims, err := decodeUnverified(token)
	if err != nil {
		return nil
	}
	return sessionFromClaims(claims)
}

func decodeUnverified(token string) (*auth.Claims, error) {
	claims := new(auth.Claims)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	if _, _, err := parser.ParseUnverified(token, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand — ถูกต้องแม้ err เพราะใช้เฉพาะ jti จำลอง
	return fmt.Sprintf("%x", b)
}
