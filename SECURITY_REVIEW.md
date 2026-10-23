# Security Review: Bob's Used Books Classic

**Date:** 2026-10-23
**Reviewer:** Security Architect (manual source-code audit)
**Scope:** `app/` (Bookstore.Web, Bookstore.Data, Bookstore.Domain, Bookstore.Common, Bookstore.Cdk) plus `Dockerfile` and `web.config` files
**Target:** ASP.NET MVC 5 web application on .NET Framework 4.8 (C#)
**Standards referenced:** OWASP Top 10 (2021), OWASP ASVS, CWE, NIST SP 800-53 Rev. 5

> **Method and limitation:** This is a static source-code review. The .NET Framework 4.8 toolchain is not available in the review environment, so the application was not built or executed and no dynamic (DAST) or dependency-scanner confirmation was performed. Severities are assessed from code reading and should be validated with runtime testing before and after remediation. Line numbers are approximate and refer to the files as they exist at review time.

---

## Executive summary

Bob's Used Books Classic is a sample e-commerce application. It demonstrates good practice in some areas (parameterized LINQ-to-Entities queries, Razor auto-encoding, randomized stored file names, image moderation hook for the AWS path). However, the review identified a number of material security weaknesses, several of which are directly exploitable in the default configuration.

The most serious issues are:

1. **Missing anti-CSRF protection on every state-changing action** (no `[ValidateAntiForgeryToken]` anywhere in the codebase).
2. **Insecure Direct Object Reference (IDOR) on order details** allowing any authenticated user to read any customer's order (PII) by guessing an integer ID.
3. **Default "local" authentication grants full `Administrators` access to every anonymous visitor** and is the shipped default in `web.config`.
4. **Open redirects** in the authentication and address flows.
5. **Hardcoded Cognito bootstrap admin credentials** documented in the README (`Admin` / `P@ssword1`).

### Findings overview

| # | Severity | Title | OWASP | CWE |
|---|----------|-------|-------|-----|
| 1 | High | No CSRF protection on state-changing POST actions | A01 | CWE-352 |
| 2 | High | IDOR / broken object-level authorization on order details | A01 | CWE-639 / CWE-284 |
| 3 | High | Default local auth auto-authenticates everyone as Administrator | A07 / A05 | CWE-1188 / CWE-287 |
| 4 | Medium | Open redirect in `AuthenticationController.Login` and `AddressController` | A01 | CWE-601 |
| 5 | Medium | Hardcoded default admin credentials in documentation/first-run | A07 | CWE-798 |
| 6 | Medium | Insecure cookies (no HttpOnly / Secure / SameSite) | A05 / A07 | CWE-614 / CWE-1004 |
| 7 | Medium | File upload type check relies on extension only; local validator is a no-op | A04 / A05 | CWE-434 |
| 8 | Medium | `debug="true"` and `Environment=Development`; no `customErrors`/security headers | A05 | CWE-11 / CWE-16 |
| 9 | Medium | Cognito OIDC token validation weakened (`UseTokenLifetime=false`, custom claim mapping, no explicit validation) | A07 / A02 | CWE-287 / CWE-347 |
| 10 | Low/Med | Potential DoS via image decompression (ImageMagick, no size/pixel limits) | A05 | CWE-400 / CWE-409 |
| 11 | Low | Environment variables silently override every app setting | A05 | CWE-15 |
| 12 | Low | Null-reference / unvalidated OIDC claims can crash sign-in | A07 | CWE-476 / CWE-20 |
| 13 | Low | Verbose stored error data and TempData error exposure | A09 / A05 | CWE-209 |
| 14 | Info | Dependency hygiene / SCA needed; LogMonitor fetched over network in build | A06 | CWE-1104 |

---

## Detailed findings

### Finding 1 — No CSRF protection on any state-changing action (High)

- **OWASP:** A01:2021 Broken Access Control (CSRF) · **CWE-352** · **NIST:** SC-23, SI-10
- **Locations:** All `[HttpPost]` actions across the app. Confirmed by a repository-wide search: `ValidateAntiForgeryToken`, `@Html.AntiForgeryToken`, and `AllowHtml` produce **zero** matches. Examples:
  - `app/Bookstore.Web/Controllers/AddressController.cs` — `Create`, `Update`, `Delete`
  - `app/Bookstore.Web/Controllers/CheckoutController.cs` — `Index` (places order)
  - `app/Bookstore.Web/Controllers/OrdersController.cs` — `Delete` (cancels order)
  - `app/Bookstore.Web/Controllers/ShoppingCartController.cs` / `WishlistController.cs` — `Delete`, `MoveToShoppingCart`, `MoveAllItemsToShoppingCart`
  - `app/Bookstore.Web/Areas/Admin/Controllers/InventoryController.cs` — `Create`, `Update`
  - `app/Bookstore.Web/Areas/Admin/Controllers/OrdersController.cs` — `Details` (POST updates order status)
  - `app/Bookstore.Web/Areas/Admin/Controllers/OffersController.cs`, `ReferenceDataController.cs`

**Description:** ASP.NET MVC does not add anti-forgery tokens automatically. Because authentication is cookie-based (both the Cognito cookie `.AspNet.Cookies` and the local `LocalAuthentication` cookie), any external site can auto-submit a form to these endpoints and the browser will attach the user's cookie. An attacker can cancel orders, add/alter inventory, change order status, create addresses, or clear carts on behalf of a logged-in victim (including an administrator) with a single crafted page.

**Vulnerable code (representative):**
```csharp
// Areas/Admin/Controllers/OrdersController.cs
[HttpPost]
public async Task<ActionResult> Details(OrderDetailsViewModel model)
{
    var dto = new UpdateOrderStatusDto(model.OrderId, model.SelectedOrderStatus);
    await orderService.UpdateOrderStatusAsync(dto);   // no antiforgery token
    ...
}
```

**Remediation:**
- Add `@Html.AntiForgeryToken()` to every form and apply `[ValidateAntiForgeryToken]` (or a global `AutoValidateAntiforgeryTokenAttribute`-style filter) to all non-idempotent POST actions.
- Register it globally in `App_Start/FilterConfig.cs` so new actions are protected by default.
- Set cookie `SameSite=Lax` (or `Strict`) as defense in depth (see Finding 6).

---

### Finding 2 — IDOR / broken object-level authorization on order details (High)

- **OWASP:** A01:2021 Broken Access Control · **CWE-639 / CWE-284** · **NIST:** AC-3, AC-4
- **Locations:**
  - `app/Bookstore.Web/Controllers/OrdersController.cs` — `Details(int id)`
  - `app/Bookstore.Web/Controllers/CheckoutController.cs` — `Finished(int orderId)`
  - Backed by `app/Bookstore.Data/Repositories/OrderRepository.cs` — `GetAsync(int id)` (no owner filter)

**Description:** The repository exposes two overloads:
```csharp
async Task<Order> IOrderRepository.GetAsync(int id)                 // NO ownership filter
    => await dbContext.Order.Include(...).SingleOrDefaultAsync(x => x.Id == id);

async Task<Order> IOrderRepository.GetAsync(int id, string sub)     // ownership-scoped
    => await dbContext.Order.SingleOrDefaultAsync(x => x.Id == id && x.Customer.Sub == sub);
```
The customer-facing `OrdersController.Details` and `CheckoutController.Finished` call the **unscoped** `GetOrderAsync(id)`:
```csharp
// OrdersController.cs
public async Task<ActionResult> Details(int id)
{
    var order = await orderService.GetOrderAsync(id);   // any id, any customer
    return View(new OrderDetailsViewModel(order));
}
```
Any authenticated user can enumerate sequential integer order IDs and read other customers' orders, which include customer name, shipping address, and purchased items (PII). The correct, owner-scoped overload already exists and is used by `CancelOrderAsync`, which proves the gap is accidental. The orders list (`Index`) is correctly scoped by `User.GetSub()`, making the detail endpoint the weak link.

**Remediation:**
- Change `OrdersController.Details` and `CheckoutController.Finished` to pass the current user's `sub` and use the owner-scoped repository overload; return 404/403 when no match.
- Remove or restrict the unscoped `GetAsync(int id)` so it can only be reached from the Admin area (which is `[Authorize(Roles="Administrators")]`).
- Add an integration test asserting user A cannot fetch user B's order.

---

### Finding 3 — Default "local" authentication authenticates every visitor as Administrator (High)

- **OWASP:** A07:2021 Identification and Authentication Failures / A05 Security Misconfiguration · **CWE-1188 (insecure default) / CWE-287** · **NIST:** AC-2, AC-6, CM-6
- **Locations:**
  - `app/Bookstore.Web/Web.config` — `<add key="Services/Authentication" value="local" />` (shipped default)
  - `app/Bookstore.Web/Helpers/LocalAuthenticationMiddleware.cs`
  - `app/Bookstore.Web/App_Start/AuthenticationSetup.cs`

**Description:** With the default `local` setting, `LocalAuthenticationMiddleware` fabricates a fully privileged identity for anyone who hits `/Authentication/Login` or presents the unauthenticated `LocalAuthentication` marker cookie:
```csharp
identity.AddClaim(new Claim(ClaimTypes.Name, "bookstoreuser"));
identity.AddClaim(new Claim("nameidentifier", UserId));          // fixed GUID for all users
identity.AddClaim(new Claim(ClaimTypes.Role, "Administrators"));  // full admin to everyone
```
The cookie carries no signature or server-side session; merely setting `LocalAuthentication` to any value authenticates the request. Every "user" shares the same hardcoded `nameidentifier` (`FB6135C7-...`), so all local users collapse into one identity and all gain the `Administrators` role that gates the entire Admin area (`AdminAreaControllerBase`).

This is intended as a developer convenience, but it is the default in source control. If the app is deployed without switching `Services/Authentication` to `aws`, the entire admin surface is open to the public. README also notes ECS/Fargate deployments are forced onto this local path because Cognito requires HTTPS redirects.

**Remediation:**
- Do not ship `local` as the default for any deployable configuration; gate the local middleware behind an explicit `Environment == "Development"` check and fail closed otherwise.
- Never grant `Administrators` by default; local dev identity should be an ordinary customer, with admin opt-in.
- Make the local cookie unforgeable (signed) or, better, restrict local auth to non-production builds only.
- Document the deployment hardening requirement prominently.

---

### Finding 4 — Open redirect in Login and Address flows (Medium)

- **OWASP:** A01:2021 Broken Access Control · **CWE-601 (URL Redirection to Untrusted Site)** · **NIST:** SI-10
- **Locations:**
  - `app/Bookstore.Web/Controllers/AuthenticationController.cs` — `Login(string redirectUri)`
  - `app/Bookstore.Web/Controllers/AddressController.cs` — `Create`/`Update` return `Redirect(model.ReturnUrl)`

**Description:**
```csharp
public ActionResult Login(string redirectUri = null)
{
    if (string.IsNullOrWhiteSpace(redirectUri)) return RedirectToAction("Index", "Home");
    return Redirect(redirectUri);   // attacker-controlled, unvalidated absolute URL
}
```
`redirectUri` and `ReturnUrl` are taken directly from the request and passed to `Redirect()` with no allow-list or `Url.IsLocalUrl()` check. An attacker can craft `/Authentication/Login?redirectUri=https://evil.example/phish` to bounce victims to a phishing site under the trust of the legitimate domain, aiding credential theft.

**Remediation:**
- Validate every redirect target with `Url.IsLocalUrl(target)` (or an explicit allow-list) and fall back to `Home/Index` otherwise. Apply to both the login and address return-URL paths.

---

### Finding 5 — Hardcoded default admin credentials (Medium)

- **OWASP:** A07:2021 Identification and Authentication Failures · **CWE-798 / CWE-521** · **NIST:** IA-5
- **Location:** `README.md` ("Amazon Cognito first run": Username `Admin`, Password `P@ssword1`), provisioned by the Cognito/CDK bootstrap.

**Description:** A well-known default administrator credential is published in the repository and used to seed the Cognito user pool on first run. If the credential is not rotated immediately after deployment, anyone who reads the public sample repo can log in as administrator. Weak, guessable, and shared defaults are a classic initial-access vector.

**Remediation:**
- Force a password change on first login; generate a random bootstrap password stored in Secrets Manager rather than a static documented value.
- Remove the literal password from the README or clearly mark it as a throwaway that must be rotated before any non-local use.

---

### Finding 6 — Insecure cookies: no HttpOnly, Secure, or SameSite (Medium)

- **OWASP:** A05 Security Misconfiguration / A07 · **CWE-614 (Secure flag) / CWE-1004 (HttpOnly) / CWE-1275 (SameSite)** · **NIST:** SC-8, SC-23
- **Locations:**
  - `app/Bookstore.Web/Helpers/LocalAuthenticationMiddleware.cs` — `new HttpCookie("LocalAuthentication") { Expires = ... }`
  - `app/Bookstore.Web/Helpers/HttpContextExtensions.cs` — `GetShoppingCartCorrelationId` builds `ShoppingCartId` cookie
  - `app/Bookstore.Web/App_Start/AuthenticationSetup.cs` — `new CookieAuthenticationOptions()` (defaults only; `CookieSecure`/`SameSite` not set)
  - No `<httpCookies httpOnlyCookies="true" requireSSL="true" />` and no `requireSSL`/HSTS in any `web.config`.

**Description:** None of the cookies set `HttpOnly`, `Secure`, or `SameSite`. The `ShoppingCartId` cookie doubles as a bearer of the cart correlation ID (and equals the user's `sub` when authenticated), so an XSS or network attacker reading it can hijack or correlate carts. The `LocalAuthentication` cookie is an auth marker with none of these flags. Absent `SameSite`, the CSRF exposure in Finding 1 is wider.

**Remediation:**
- Set `HttpOnly`, `Secure`, and `SameSite=Lax/Strict` on all cookies; enforce `requireSSL="true"` and `httpOnlyCookies="true"` in `web.config`; set `CookieSecure = CookieSecureOption.Always` and a `SameSite` mode in `CookieAuthenticationOptions`.
- Do not derive the cart correlation ID from the user's `sub`; use an opaque random value.
- Enforce HTTPS and HSTS at the edge/app.

---

### Finding 7 — File upload: extension-only type check and no-op local validator (Medium)

- **OWASP:** A04 Insecure Design / A05 · **CWE-434 (Unrestricted Upload) / CWE-20** · **NIST:** SI-10, SI-3
- **Locations:**
  - `app/Bookstore.Web/Helpers/ImageTypesAttribute.cs` (extension allow-list only)
  - `app/Bookstore.Web/Helpers/MaxFileSizeAttribute.cs` (size)
  - `app/Bookstore.Data/ImageValidationServices/LocalImageValidationService.cs` (`return true` always)
  - `app/Bookstore.Domain/Books/BookService.cs` — `SaveAsync` validation ordering
  - `app/Bookstore.Data/FileServices/LocalFileService.cs`, `S3FileService.cs`

**Description:** Admin cover-image upload validates the file **type by extension only** (`Path.GetExtension(file.FileName)`), never by magic bytes or content type. The default `LocalImageValidationService.IsSafeAsync` unconditionally returns `true`, so in the default configuration there is effectively no content safety check; only the AWS Rekognition path performs moderation (and that only checks for objectionable imagery, not file-type spoofing). A malicious user can upload a non-image payload with a `.png`/`.jpg` extension.

Mitigating factors that reduce (but do not eliminate) impact: stored files get a random name via `Path.GetRandomFileName()` keeping the original extension, and `LocalFileService` writes into `images/coverimages` rather than an executable path. However, `Path.GetExtension(filename)` is taken from the attacker-supplied filename, so a crafted extension is preserved on disk/S3. Also note the validation-order bug in `BookService.SaveAsync`: the image is **resized before the safety check**, and the safety check runs against the original `coverImage` stream while the resized stream is what gets stored, so the moderation result does not necessarily correspond to the bytes persisted.

**Remediation:**
- Validate real content type by decoding the image (reject anything that is not a valid raster image) and verify magic bytes; do not trust the client extension or `Content-Type`.
- Make `LocalImageValidationService` perform a real check or fail closed in non-dev.
- Run validation on the exact bytes that will be stored, before persisting; serve user images from a separate, no-execute domain/bucket with `Content-Disposition` and a restrictive `Content-Type`.
- Normalize the stored extension from the validated content type, not the user-supplied name.

---

### Finding 8 — Debug build, Development environment, missing error handling and security headers (Medium)

- **OWASP:** A05:2021 Security Misconfiguration · **CWE-11 / CWE-16 / CWE-756** · **NIST:** CM-6, SC-18
- **Locations:**
  - `app/Bookstore.Web/Web.config` — `<compilation debug="true" targetFramework="4.8" />`, `<add key="Environment" value="Development" />`
  - No `<customErrors mode="On/RemoteOnly">` in any `web.config`; `Web.Release.config` only removes the debug attribute and leaves `customErrors` commented out.
  - No security response headers (CSP, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy, HSTS) configured anywhere.

**Description:** Shipping `debug="true"` disables request timeouts, bloats responses, and (with no `customErrors`) tends to surface detailed ASP.NET error pages including stack traces to clients. `Environment=Development` combined with the local auth default (Finding 3) means the insecure developer posture is the out-of-the-box state. The absence of a Content-Security-Policy and anti-clickjacking headers increases the blast radius of any reflected/stored script and allows framing.

**Remediation:**
- Set `debug="false"` and `Environment=Production` for deployed builds (enforce via the release transform).
- Add `<customErrors mode="RemoteOnly" defaultRedirect="~/Error" />` and a generic error view; never leak stack traces.
- Add security headers (CSP with a strict default, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` / CSP `frame-ancestors 'none'`, `Referrer-Policy`, HSTS) via middleware or `web.config`.

---

### Finding 9 — Weakened OIDC/Cognito token validation (Medium)

- **OWASP:** A07 Identification and Authentication Failures / A02 Cryptographic Failures · **CWE-287 / CWE-347 (improper verification of signature/claims)** · **NIST:** IA-2, SC-23
- **Location:** `app/Bookstore.Web/App_Start/AuthenticationSetup.cs`

**Description:** The OpenID Connect setup sets `UseTokenLifetime = false` and supplies a `TokenValidationParameters` that only remaps `NameClaimType`/`RoleClaimType`, without explicitly asserting issuer/audience/lifetime validation. Disabling token-lifetime use means the session cookie lifetime is decoupled from token expiry (tokens can effectively outlive their validity window via the cookie). The role claim is driven entirely by `cognito:groups`, so authorization to the Admin area depends on correct group hygiene in the identity provider. The `SecurityTokenValidated` notification also trusts claim contents without validation (see Finding 12).

**Remediation:**
- Explicitly configure `TokenValidationParameters` with `ValidateIssuer`, `ValidateAudience`, `ValidateLifetime = true`, and the expected issuer/audience; align cookie expiration with token lifetime or implement refresh.
- Treat `cognito:groups` as sensitive; ensure group membership is tightly controlled and audited for the `Administrators` mapping.

---

### Finding 10 — Potential denial of service via image processing (Low/Medium)

- **OWASP:** A05 Security Misconfiguration (resource limits) · **CWE-400 / CWE-409 (decompression bomb)** · **NIST:** SC-5
- **Location:** `app/Bookstore.Data/ImageResizeService/ImageResizeService.cs`

**Description:** Uploaded images are decoded with ImageMagick (`new MagickImage(image)`) with no pixel/dimension/memory limits before resizing. A small crafted file (decompression bomb or extreme dimensions) can consume large amounts of CPU/RAM on the server. The `MaxFileSizeAttribute` bounds the upload byte size but not the decompressed pixel count.

**Remediation:**
- Set ImageMagick resource limits (`ResourceLimits.Width/Height/Memory/Area`) and reject images exceeding sane bounds before processing; process uploads with timeouts and in a constrained worker if possible.

---

### Finding 11 — Environment variables silently override all app settings (Low)

- **OWASP:** A05 Security Misconfiguration · **CWE-15 (External Control of System Setting)** · **NIST:** CM-6
- **Location:** `app/Bookstore.Data/BookstoreConfiguration.cs`

**Description:**
```csharp
foreach (string key in ConfigurationManager.AppSettings) {
    _appSettings[key] = ConfigurationManager.AppSettings[key];
    if (Environment.GetEnvironmentVariable(key) != null)
        _appSettings[key] = Environment.GetEnvironmentVariable(key);  // env always wins
}
```
Any environment variable whose name matches a setting key (for example `Services/Authentication`, `Services/Database`, `Files/BucketName`) silently overrides configuration. In a shared or container host, an injected environment variable could, for example, flip authentication to the insecure `local` mode or redirect the file/S3 target. This is a legitimate 12-factor pattern, but combined with the insecure `local` default it widens the misconfiguration risk and deserves explicit, documented control.

**Remediation:**
- Restrict env-var overrides to an explicit allow-list of expected keys, log overrides, and never allow security-critical toggles (auth mode) to be changed by ambient environment without validation.

---

### Finding 12 — Unvalidated OIDC claims cause null-reference during sign-in (Low)

- **OWASP:** A07 / input validation · **CWE-476 / CWE-20** · **NIST:** SI-10
- **Location:** `app/Bookstore.Web/App_Start/AuthenticationSetup.cs` — `SecurityTokenValidated`

**Description:**
```csharp
identity.FindFirst(y => y.Type.Contains("givenname")).Value,   // NRE if claim absent
identity.FindFirst(y => y.Type.Contains("surname")).Value);
```
If the IdP does not return `givenname`/`surname`, `FindFirst(...)` returns `null` and `.Value` throws, breaking authentication (availability) and potentially surfacing an error. `ClaimsPrincipalExtensions.GetSub` and the local middleware similarly assume specific claims exist.

**Remediation:**
- Null-check claims and use safe defaults; validate required claims and reject/handle gracefully when absent.

---

### Finding 13 — Error/notification data exposure and inconsistent error pages (Low/Medium)

- **OWASP:** A09 Security Logging/Monitoring Failures / A05 · **CWE-209 (information exposure through error message)** · **NIST:** SI-11, AU-9
- **Locations:** `app/Bookstore.Web/Areas/Admin/Controllers/ErrorController.cs`, `Views/Shared/Error.cshtml`, `TempData["Message"]` usage; `App_Start/FilterConfig.cs` (`HandleErrorAttribute` only).

**Description:** With no `customErrors` configured (Finding 8) and `debug="true"`, unhandled exceptions can expose stack traces and internal details. Logging is configured (`LoggingSetup`) but there is no evidence of security event logging (failed authz, IDOR attempts, admin actions) or alerting, which hampers detection of the access-control abuse described above.

**Remediation:**
- Return generic error views to clients; log full details server-side only.
- Add security-relevant audit logging (authentication outcomes, authorization denials, admin mutations, file uploads) and ship to a monitored sink (the AWS CloudWatch target already exists for the `aws` logging mode).

---

### Finding 14 — Dependency hygiene and supply chain (Informational)

- **OWASP:** A06:2021 Vulnerable and Outdated Components · **CWE-1104 / CWE-1357** · **NIST:** SA-10, SI-2, RA-5
- **Locations:** `app/Bookstore.Web/packages.config`, `Dockerfile`

**Description:** The project pins many packages (EntityFramework 6.5.1, Newtonsoft.Json 13.0.3, jQuery 3.7.1, Microsoft.IdentityModel 8.7.0, AWS SDK v3, NLog 5.4.0, ImageMagick via Magick.NET). Most pinned versions are reasonably current, but .NET Framework 4.8 and the full ASP.NET MVC 5 stack carry long-term maintenance risk, and the client-side libraries (jQuery, jQuery.Validation, Modernizr 2.8.3) should be tracked for advisories. The `Dockerfile` downloads `LogMonitor.exe` from a GitHub release over the network at build time **without checksum/signature verification**, a supply-chain integrity gap:
```dockerfile
RUN Invoke-WebRequest -Uri "https://github.com/.../LogMonitor.exe" -OutFile "LogMonitor.exe"
```

**Remediation:**
- Run a Software Composition Analysis tool (for example `dotnet list package --vulnerable` on a migrated build, OWASP Dependency-Check, GitHub Dependabot) and remediate on a schedule.
- Pin `LogMonitor.exe` to a specific release and verify its hash/signature in the Dockerfile; prefer a trusted internal mirror.
- Keep Magick.NET/ImageMagick current (image parsers are a frequent CVE source).

---

## Positive observations

- **SQL injection:** Data access uses Entity Framework 6 with LINQ (`Where(x => x.Name.Contains(...))`); no raw SQL string concatenation or `SqlCommand` was found. The search path (`SearchController` → `BookRepository.ListAsync`) is parameterized by EF. (A01/A03 — no injection identified.)
- **XSS:** Razor views output model values with `@Model.*` (auto HTML-encoded) and the search did **not** find any `Html.Raw` usage, so stored values such as book summaries are encoded by default. Keep it that way and avoid introducing `Html.Raw`/`MvcHtmlString` on user data.
- **Stored file naming:** Uploaded files are stored under a server-generated random name (`Path.GetRandomFileName()`), reducing path/overwrite attacks.
- **Owner-scoped queries exist** for addresses and order cancellation, showing the correct pattern is understood (it simply is not applied to order details — Finding 2).

---

## Prioritized remediation roadmap

**Immediate (High):**
1. Add anti-CSRF tokens globally and validate on all POSTs (Finding 1).
2. Fix the order-details IDOR to use owner-scoped lookups (Finding 2).
3. Remove `local` admin-by-default; gate local auth to dev only and never auto-grant `Administrators` (Finding 3).

**Short term (Medium):**
4. Validate all redirects with `Url.IsLocalUrl` (Finding 4).
5. Rotate/randomize the Cognito bootstrap credential; force first-login change (Finding 5).
6. Harden cookies (HttpOnly/Secure/SameSite) and enforce HTTPS/HSTS (Finding 6).
7. Real content-based upload validation; fail-closed local validator; validate the bytes actually stored (Finding 7).
8. Disable debug, set Production, add `customErrors` and security headers (Finding 8).
9. Strengthen OIDC token validation (Finding 9).

**Medium/Low:**
10. Image-processing resource limits (Finding 10); 11. restrict env-var overrides (Finding 11); 12. null-safe claim handling (Finding 12); 13. generic errors + security audit logging (Finding 13); 14. SCA and Dockerfile integrity pinning (Finding 14).

---

*This report was produced by manual static analysis only; validate each finding with runtime testing and a dependency scanner, and re-test after remediation.*
