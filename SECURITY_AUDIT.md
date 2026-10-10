# Security Audit Report — Bob's Used Books Classic

**Target:** `bobs-used-bookstore-classic` (ASP.NET MVC 5, .NET Framework 4.8, C#)
**Assessment type:** Manual static source-code security review (white-box)
**Standards referenced:** OWASP Top 10 (2021), OWASP ASVS, NIST SP 800-53 Rev. 5, NIST SP 800-63B
**Scope:** `app/Bookstore.Web`, `app/Bookstore.Data`, `app/Bookstore.Domain`, `app/Bookstore.Common`, `app/Bookstore.Cdk`, root configuration and scripts

> Note: This is a source-only audit. The application was not built or run (Windows/.NET Framework app, Linux sandbox, no network). Findings were verified by reading the actual source. Line numbers refer to the state of the repository at audit time.

---

## Executive summary

Bob's Used Books Classic is a sample used-book store with a public storefront and an authenticated administrative area. It supports a fully local ("disconnected") mode for development and an AWS-integrated mode (Cognito, RDS SQL Server, S3, Rekognition, CloudWatch).

The review found a number of security weaknesses that, while partly explained by the application's role as a sample, are the kind of defects that are routinely copied into production forks. The most serious issues are:

- **A development authentication bypass (`LocalAuthenticationMiddleware`) that grants every visitor full `Administrators` access** without any credential check whenever the application runs in the default "local" authentication mode — which is the shipped default and the only supported mode on ECS/Fargate per the README.
- **No CSRF (anti-forgery) protection on any state-changing POST action** across the storefront and admin area.
- **Broken object-level authorization (IDOR)** on order viewing: `OrdersController.Details`, `CheckoutController.Finished`, allowing any authenticated user to read any customer's order (PII, shipping address, items) by guessing a numeric id.
- **An open redirect** in `AuthenticationController.Login`.
- **Insecure cookie configuration** (no `HttpOnly`, `Secure`, or `SameSite`) for the local-auth and shopping-cart cookies, combined with no HTTPS/HSTS enforcement.
- **Insecure configuration defaults**: `debug="true"`, no `customErrors`, no security headers, and the EF database initializer that drops and recreates the schema.

The good news: the data layer uses Entity Framework LINQ throughout, so there is **no SQL injection** exposure, and views use Razor's default HTML-encoding with **no `Html.Raw` usage**, so stored/reflected XSS exposure is low. File uploads are validated by extension and (in AWS mode) scanned by Rekognition, and uploaded files are stored under server-generated random names, which mitigates path traversal and overwrite attacks.

### Findings by severity

| # | Severity | Title | OWASP 2021 |
|---|----------|-------|------------|
| C-1 | Critical | Local authentication middleware grants everyone Administrator access | A07 / A01 |
| H-1 | High | No CSRF protection on any state-changing request | A01 |
| H-2 | High | IDOR: any user can read any order (and address/offer) by id | A01 |
| H-3 | High | Open redirect in `AuthenticationController.Login` | A01 |
| H-4 | High | Insecure cookies (no HttpOnly/Secure/SameSite) and no TLS/HSTS enforcement | A05 / A02 |
| M-1 | Medium | `debug="true"` and missing `customErrors` leak internals | A05 |
| M-2 | Medium | Shopping-cart correlation id derived from user `sub`, trusted from client cookie | A01 / A04 |
| M-3 | Medium | Missing security response headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS) | A05 |
| M-4 | Medium | File upload validated by extension only; no magic-byte/content-type check; local mode unscanned | A04 / A08 |
| M-5 | Medium | EF `DropCreateDatabaseIfModelChanges` initializer risks data loss / tampering | A05 |
| L-1 | Low | Hardcoded default admin credentials in source and README | A07 |
| L-2 | Low | Connection string with `Password=` persisted to SSM as plaintext parameter | A02 |
| L-3 | Low | Cognito client uses `USER_PASSWORD` auth flow | A07 |
| L-4 | Low | Error controller is `AllowAnonymous` on an admin base; broad `AllowAnonymous` surface | A01 |
| I-1 | Info | Outdated/`net45` dependencies and no SCA process | A06 |
| I-2 | Info | Logging configuration and potential sensitive-data logging | A09 |

---

## Critical findings

### C-1. Local authentication middleware grants every visitor full Administrator access
**Severity:** Critical
**OWASP:** A07:2021 Identification and Authentication Failures; A01:2021 Broken Access Control
**NIST:** IA-2, AC-6 (least privilege), AC-3
**Files:**
- `app/Bookstore.Web/Helpers/LocalAuthenticationMiddleware.cs` (whole file; roles at lines ~50-57)
- `app/Bookstore.Web/App_Start/AuthenticationSetup.cs:30-33` (selects local vs. Cognito)
- `app/Bookstore.Web/Web.config` (`Services/Authentication` = `local`, line ~20)

**Description.** When `Services/Authentication` is `local` (the shipped default, and the only mode usable on ECS/Fargate per the README), `LocalAuthenticationMiddleware` fabricates a fully authenticated identity for anyone who requests `/Authentication/Login` or presents a `LocalAuthentication` cookie. No username or password is ever checked. The fabricated identity is unconditionally given the `Administrators` role:

```csharp
identity.AddClaim(new Claim(ClaimTypes.Name, "bookstoreuser"));
identity.AddClaim(new Claim(ClaimTypes.Role, "Administrators"));   // every visitor is an admin
```

Because the admin area authorizes on exactly that role (`[Authorize(Roles = "Administrators")]` in `AdminAreaControllerBase.cs`), any anonymous visitor can obtain admin by simply hitting `/Authentication/Login` and then browsing to `/Admin/...`. The `LocalAuthentication` cookie that marks the "session" carries no secret, no signature, and no expiry validation beyond a client-controlled date — it is a static marker, so it can be set by the client directly.

**Exploitation.**
1. Browse to `https://host/Authentication/Login`. The middleware creates the admin principal, drops a `LocalAuthentication` cookie, and redirects to `/`.
2. Navigate to `/Admin/Inventory`, `/Admin/Orders`, `/Admin/Offers`, etc. All are accessible with full read/write (add/update inventory, change order status, approve/pay offers).

**Remediation.**
- Treat local authentication as a build-time-only convenience. Guard it so it can never run outside an explicit development build, for example compile the middleware under `#if DEBUG` and additionally require `Environment == "Development"` from config, and fail closed (throw at startup) if `Services/Authentication == "local"` in any non-development environment.
- Never assign the `Administrators` role in the dev identity by default; make the dev role explicit and minimal.
- For production, require the Cognito (or equivalent real IdP) path and document that local mode is not a deployment option. The README's note that Fargate "has to use the local authentication service" should be revisited — HTTP-only Cognito limitations should be solved with TLS, not by shipping an auth bypass.

---

## High findings

### H-1. No CSRF / anti-forgery protection on state-changing requests
**Severity:** High
**OWASP:** A01:2021 Broken Access Control (CSRF)
**NIST:** SC-23, SI-10
**Files (representative POST actions with no `[ValidateAntiForgeryToken]`):**
- `app/Bookstore.Web/Controllers/AddressController.cs` — `Create`, `Update`, `Delete`
- `app/Bookstore.Web/Controllers/CheckoutController.cs` — `Index` (places order)
- `app/Bookstore.Web/Controllers/ShoppingCartController.cs` — `Delete`
- `app/Bookstore.Web/Controllers/ResaleController.cs` — `Create`
- `app/Bookstore.Web/Controllers/OrdersController.cs` — `Delete` (cancel order)
- `app/Bookstore.Web/Areas/Admin/Controllers/OffersController.cs` — `ApproveAsync`, `RejectAsync`, `ReceivedAsync`, `PaidAsync`
- `app/Bookstore.Web/Areas/Admin/Controllers/InventoryController.cs` — `Create`, `Update`
- `app/Bookstore.Web/Areas/Admin/Controllers/OrdersController.cs` — `Details` (POST updates order status)

A repository-wide search for `ValidateAntiForgeryToken` returned **zero** matches. The global filter set (`FilterConfig.cs`) adds only `HandleErrorAttribute` and a bare `AuthorizeAttribute`; there is no global anti-forgery filter.

**Description / exploitation.** None of the POST endpoints validate an anti-forgery token, and the auth cookies have no `SameSite` restriction (see H-4). An attacker can host a page that auto-submits a form to, say, `/Admin/Offers/PaidAsync` or `/Checkout` while a logged-in admin/customer visits it, causing state changes (marking offers paid, cancelling orders, placing orders, adding/removing inventory, deleting addresses) without the victim's intent.

**Remediation.**
- Add `@Html.AntiForgeryToken()` to every form and decorate every state-changing action with `[ValidateAntiForgeryToken]`. Prefer a global solution: register `AutoValidateAntiforgeryTokenAttribute`-equivalent behavior (in MVC5, apply `[ValidateAntiForgeryToken]` via a base controller or a custom global filter that enforces it on all non-GET verbs).
- Combine with `SameSite=Lax` (or `Strict`) cookies (H-4) for defense in depth.

### H-2. Insecure Direct Object Reference (IDOR) — any user can read any order
**Severity:** High
**OWASP:** A01:2021 Broken Access Control
**NIST:** AC-3, AC-4
**Files:**
- `app/Bookstore.Web/Controllers/OrdersController.cs:27-31` (`Details(int id)`)
- `app/Bookstore.Web/Controllers/CheckoutController.cs:46-51` (`Finished(int orderId)`)
- `app/Bookstore.Domain/Orders/OrderService.cs:54-57` (`GetOrderAsync(int id)`)
- `app/Bookstore.Data/Repositories/OrderRepository.cs:28-40` (`GetAsync(int id)` — no owner filter)

**Description.** The repository exposes two getters: an **unscoped** `GetAsync(int id)` and an **owner-scoped** `GetAsync(int id, string sub)`. The customer-facing `OrdersController.Details` and `CheckoutController.Finished` call the unscoped path via `OrderService.GetOrderAsync(id)`, so authorization is based solely on a sequential integer id. There is no check that the order belongs to the current user (`User.GetSub()`), unlike `OrdersController.Delete`, which correctly uses the scoped `CancelOrderAsync` path.

```csharp
// OrdersController (storefront)
public async Task<ActionResult> Details(int id)
{
    var order = await orderService.GetOrderAsync(id);   // no User.GetSub() scoping
    return View(new OrderDetailsViewModel(order));
}
```

The returned `Order` includes customer identity, shipping `Address`, and line items (see the `Include(...)` graph in `OrderRepository.GetAsync(int id)`).

**Exploitation.** An authenticated customer requests `/Orders/Details/1`, `/2`, `/3`, … and reads other customers' orders, names, and shipping addresses — a direct PII breach via enumeration.

**Remediation.**
- Change `OrdersController.Details` and `CheckoutController.Finished` to use an owner-scoped lookup (pass `User.GetSub()` and resolve via `OrderRepository.GetAsync(int id, string sub)`), returning `404`/`403` when the order is not owned by the caller.
- Consider deprecating/removing the unscoped `GetOrderAsync(int id)` from the storefront surface entirely, keeping it only behind admin authorization.
- Audit the analogous address and offer getters: `AddressService.GetAddressAsync` is called with `User.GetSub()` (good), and offers list by `sub`; keep that pattern consistently and avoid introducing unscoped getters in customer controllers.

### H-3. Open redirect in `AuthenticationController.Login`
**Severity:** High
**OWASP:** A01:2021 Broken Access Control (unvalidated redirect)
**NIST:** SI-10
**File:** `app/Bookstore.Web/Controllers/AuthenticationController.cs:10-15`

```csharp
public ActionResult Login(string redirectUri = null)
{
    if (string.IsNullOrWhiteSpace(redirectUri)) return RedirectToAction("Index", "Home");
    return Redirect(redirectUri);   // attacker-controlled absolute URL
}
```

**Description / exploitation.** `redirectUri` comes straight from the query string and is passed to `Redirect()` with no validation that it is a local/allow-listed URL. An attacker crafts `https://host/Authentication/Login?redirectUri=https://evil.example/phish`. Because the link originates from the trusted application domain, it is effective for phishing and for bouncing OAuth/login flows to attacker-controlled pages.

**Remediation.**
- Only redirect to local URLs: `if (Url.IsLocalUrl(redirectUri)) return Redirect(redirectUri); return RedirectToAction("Index","Home");`
- Or validate against an explicit allow-list of hosts. Apply the same discipline to the Cognito logout `logout_uri` construction in `CognitoSignOut` and URL-encode query parameters.

### H-4. Insecure cookies and no TLS/HSTS enforcement
**Severity:** High
**OWASP:** A05:2021 Security Misconfiguration; A02:2021 Cryptographic Failures (data in transit)
**NIST:** SC-8, SC-23, AC-12
**Files:**
- `app/Bookstore.Web/Helpers/LocalAuthenticationMiddleware.cs:34-36` (`LocalAuthentication` cookie)
- `app/Bookstore.Web/Helpers/HttpContextExtensions.cs:12-37` (`ShoppingCartId` cookie)
- `app/Bookstore.Web/App_Start/AuthenticationSetup.cs:39` (`new CookieAuthenticationOptions()` with defaults)
- `app/Bookstore.Web/Web.config` (no `<httpCookies>`, no `requireSSL`, no `<rewrite>`/HSTS)

**Description.** Cookies are created without `HttpOnly`, `Secure`, or `SameSite`:

```csharp
var userCookie = new HttpCookie("LocalAuthentication") { Expires = DateTime.Now.AddDays(1) };
// ...
context.Response.Cookies.Add(new HttpCookie(CookieKey, shoppingCartClientId)); // no flags
```

The Cognito cookie middleware is initialized with a default `CookieAuthenticationOptions()` and no `CookieSecure = CookieSecureOption.Always`. There is no global `<httpCookies httpOnlyCookies="true" requireSSL="true" />`, no `customErrors`, and no HTTPS redirect/HSTS. The README explicitly notes Fargate runs over HTTP.

**Exploitation.** Over HTTP, cookies travel in clear text and can be captured on the network. Without `HttpOnly`, any reflected/stored script (or a future XSS regression) can read the auth/cart cookie. Without `SameSite`, cross-site requests carry the cookie, enabling the CSRF in H-1.

**Remediation.**
- Set `HttpOnly = true` and `Secure = true` on all cookies; add `SameSite = SameSiteMode.Lax` (or `Strict` for auth). In Web.config add `<system.web><httpCookies httpOnlyCookies="true" requireSSL="true" /></system.web>`.
- For OWIN cookie auth set `CookieHttpOnly = true` and `CookieSecure = CookieSecureOption.Always`.
- Terminate TLS and enforce HTTPS (redirect HTTP→HTTPS) with HSTS (`Strict-Transport-Security`). Put the Fargate service behind an ALB/CloudFront with an ACM certificate instead of serving plain HTTP.

---

## Medium findings

### M-1. `debug="true"` and missing `customErrors` leak internal details
**Severity:** Medium
**OWASP:** A05:2021 Security Misconfiguration
**NIST:** SI-11, CM-6
**Files:**
- `app/Bookstore.Web/Web.config` — `<compilation debug="true" targetFramework="4.8" />`, `Environment=Development`
- `app/Bookstore.Web/Web.Release.config` — the release transform only `RemoveAttributes(debug)`; the `<customErrors>` block is left commented out
- `app/Bookstore.Data/Bookstore.Data.csproj` — Debug is the default configuration

**Description.** With `debug="true"` and no `<customErrors mode="On"/>`, unhandled exceptions render the ASP.NET yellow-screen-of-death with stack traces, file paths, and framework versions. The release transform removes the debug flag but never establishes `customErrors` or a safe default error page, so a misbuilt/mis-deployed instance leaks internals. `HandleErrorAttribute` only takes effect when custom errors are enabled.

**Remediation.** Set `customErrors mode="RemoteOnly"` (or `On`) with a generic `defaultRedirect`; ensure the Release transform enforces `debug="false"` and custom errors; build/deploy in Release. Verify no stack traces are returned to clients.

### M-2. Shopping-cart correlation id trusts a client cookie and reuses the user `sub`
**Severity:** Medium
**OWASP:** A01:2021 Broken Access Control; A04:2021 Insecure Design
**NIST:** AC-3, SC-8
**File:** `app/Bookstore.Web/Helpers/HttpContextExtensions.cs:12-37`

**Description.** `GetShoppingCartCorrelationId` returns the raw value of the client-supplied `ShoppingCartId` cookie if present; otherwise, for authenticated users, it uses `User.GetSub()` (the Cognito/user identifier) as the cart id and writes it into a non-HttpOnly cookie. The cart is then looked up solely by this client-controlled value (`shoppingCartService.GetShoppingCartAsync(correlationId)`), with no server-side binding of cart to the authenticated user.

**Exploitation.** An attacker who learns or guesses another user's `sub` (it is placed in a readable cookie, and `sub`-shaped values appear in flows) can set their `ShoppingCartId` cookie to that value and read/modify the victim's cart. Even without targeting a specific victim, the cart ownership is entirely client-asserted.

**Remediation.** Do not derive the cart id from the user `sub`, and do not trust the cart cookie for authenticated users. For logged-in users, resolve the cart from the server-side identity. For anonymous users, use an unguessable random GUID (already done) stored in an `HttpOnly`/`Secure`/`SameSite` cookie, and on login migrate/merge the anonymous cart to the user. Validate that the resolved cart belongs to the caller.

### M-3. Missing security response headers
**Severity:** Medium
**OWASP:** A05:2021 Security Misconfiguration
**NIST:** SC-18, SC-7
**Files:** `app/Bookstore.Web/Web.config` (no `<system.webServer><httpProtocol><customHeaders>`), `Startup.cs` (no header middleware)

**Description.** No `Content-Security-Policy`, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, or `Strict-Transport-Security` is set. This increases the impact of any future XSS, allows clickjacking, and permits MIME sniffing.

**Remediation.** Add the headers via `web.config` `customHeaders` or OWIN middleware: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (or a CSP `frame-ancestors 'none'`), a restrictive `Content-Security-Policy`, `Referrer-Policy: no-referrer`, and HSTS once HTTPS is enforced.

### M-4. File upload validated by extension only; no content-type/magic-byte check; local mode is unscanned
**Severity:** Medium
**OWASP:** A04:2021 Insecure Design; A08:2021 Software and Data Integrity Failures
**NIST:** SI-10, SI-3
**Files:**
- `app/Bookstore.Web/Helpers/ImageTypesAttribute.cs` (extension-only check)
- `app/Bookstore.Web/Helpers/MaxFileSizeAttribute.cs` (size check — good, keep)
- `app/Bookstore.Data/FileServices/LocalFileService.cs` (random filename — good; preserves client extension)
- `app/Bookstore.Data/ImageValidationServices/LocalImageValidationService.cs` (local mode)
- `app/Bookstore.Data/ImageValidationServices/RekognitionImageValidationService.cs` (AWS mode)

**Description.** Image type validation relies on `Path.GetExtension(file.FileName)` matching an allow-list — it inspects the client-supplied filename, not the file content. There is no verification that the bytes are actually a PNG/JPG, and the stored object keeps the (attacker-controlled) extension. In AWS mode content is scanned by Rekognition for objectionable categories, but Rekognition does not validate file type and local mode performs no content moderation at all. Positives: files are stored under server-generated random names (no path traversal / overwrite), and S3 keys use only the random name.

**Exploitation.** An attacker can upload a non-image payload with an image extension (e.g., a polyglot or an HTML/SVG file renamed `.png`). If such content is ever served with a sniffable content type or from the same origin, it can lead to stored XSS or content-type confusion; at minimum it defeats the intended "images only" control. Local mode accepts any image content with no moderation.

**Remediation.** Validate the actual content (magic bytes / decode with the imaging library already present, Magick.NET) and reject anything that does not decode to the expected image format; normalize/re-encode images server-side; set a correct, non-sniffable `Content-Type` and `Content-Disposition` on served objects; serve user content from a separate origin/CDN (CloudFront is already used in AWS mode); keep the size limit; and ensure content moderation runs (or uploads are otherwise constrained) in all modes.

### M-5. EF `DropCreateDatabaseIfModelChanges` initializer
**Severity:** Medium
**OWASP:** A05:2021 Security Misconfiguration (and availability/integrity risk)
**NIST:** CM-6, CP-10
**Files:** `app/Bookstore.Data/BookstoreDbInitializer.cs:9`, `app/Bookstore.Data/ApplicationDbContext.cs:58` (`Database.SetInitializer(new BookstoreDbInitializer())`)

**Description.** The context is wired to `DropCreateDatabaseIfModelChanges`, which drops and recreates the database (losing all data) whenever the model hash changes. In a shared/production database this is a data-loss and integrity hazard, and the automatic seed also recreates fixed-id reference data.

**Remediation.** Use EF Migrations with an explicit, reviewed upgrade path; do not register a drop-create initializer for non-local environments (the Web.config `<contexts>` initializer block is commented out, but the code-based `SetInitializer` still runs). Gate seeding to development only.

---

## Low findings

### L-1. Hardcoded default admin credentials in source and documentation
**Severity:** Low
**OWASP:** A07:2021 Identification and Authentication Failures
**NIST:** IA-5
**Files:** `app/Bookstore.Cdk/CoreStack.cs:161` (`TemporaryPassword = "P@ssword1"`, username `admin`); `README.md` (Username `Admin` / Password `P@ssword1`)

**Description.** A well-known default admin credential is baked into the CDK and the README. If the forced-reset / `MessageAction: SUPPRESS` flow is misconfigured or the temporary password is not rotated, this is a trivially guessable admin account.

**Remediation.** Generate a random temporary password (e.g., from Secrets Manager) at deploy time, force a reset on first sign-in, and remove the literal password from source and docs. Document retrieval from Secrets Manager instead of printing a static password.

### L-2. Database connection string (with password) stored as plaintext SSM parameter
**Severity:** Low
**OWASP:** A02:2021 Cryptographic Failures
**NIST:** SC-28, IA-5
**Files:** `app/Bookstore.Cdk/DatabaseStack.cs:71-82`, `config-scripts/Update-ConnectionString.ps1:4-12`

**Description.** The RDS password is read from a secret and then composed into a full connection string stored in an SSM `StringParameter` (`StringValue = "...;Password=...;"`). A standard `String` parameter is not encrypted at rest with a customer-managed key and is readable by anyone with `ssm:GetParameter` on the path. The password is duplicated out of Secrets Manager into a less-protected store.

**Remediation.** Store the connection string as a `SecureString` SSM parameter (KMS-encrypted) or, better, keep the password only in Secrets Manager and have the app assemble the connection string at runtime from the secret. Scope IAM read access to the parameter/secret tightly.

### L-3. Cognito app client enables the `USER_PASSWORD` auth flow
**Severity:** Low
**OWASP:** A07:2021 Identification and Authentication Failures
**NIST:** IA-2
**Files:** `app/Bookstore.Cdk/CoreStack.cs:207-210`, `app/Bookstore.Cdk/EcsStack.cs:95-98`

**Description.** `AuthFlows { UserPassword = true }` enables `USER_PASSWORD_AUTH`, which sends the password directly to Cognito rather than using SRP, enlarging the surface for credential handling/brute force when combined with no visible rate limiting or MFA.

**Remediation.** Prefer `USER_SRP_AUTH` / the hosted UI authorization-code flow (the app already uses the code flow); disable `USER_PASSWORD_AUTH` unless explicitly required; enable MFA and Cognito advanced security / throttling.

### L-4. Overly broad `AllowAnonymous` surface and anonymous admin error controller
**Severity:** Low
**OWASP:** A01:2021 Broken Access Control
**NIST:** AC-3
**Files:** `app/Bookstore.Web/Areas/Admin/Controllers/ErrorController.cs:6` (`[AllowAnonymous]` on a controller deriving from the admin base), plus `HomeController`, `SearchController`, `ShoppingCartController`, `WishlistController` are entirely `[AllowAnonymous]`.

**Description.** The global `AuthorizeAttribute` filter is good (default-deny), but several controllers opt the entire class out. `ShoppingCartController`/`WishlistController` being anonymous combines with M-2 (client-asserted cart id) to make cart operations fully unauthenticated. The admin `ErrorController` being `AllowAnonymous` is likely intentional for error display, but inheriting the admin base makes the intent easy to misread.

**Remediation.** Keep `AllowAnonymous` strictly to genuinely public read endpoints; ensure anonymous cart/wishlist operations cannot touch another principal's data (fix M-2); keep the admin error page minimal and confirm it never renders privileged data.

---

## Informational

### I-1. Dependency currency and lack of SCA
**OWASP:** A06:2021 Vulnerable and Outdated Components. **NIST:** RA-5, SA-10.
The solution targets .NET Framework 4.8 and references several packages via `net45` binaries (e.g., AWS SDK `net45` assemblies in `Bookstore.Data.csproj`). There is no evidence of a software-composition-analysis step (e.g., `dotnet list package --vulnerable`, Dependabot, or OWASP Dependency-Check). Even though EF 6.5.1 and current AWS SDKs are reasonably recent, the project should run SCA in CI and track advisories for the identity/token packages (`System.IdentityModel.Tokens.Jwt`, `Microsoft.IdentityModel.*`) referenced in `Web.config` binding redirects. **Action:** add automated dependency scanning and a patch cadence.

### I-2. Logging configuration and sensitive data
**OWASP:** A09:2021 Security Logging and Monitoring Failures. **NIST:** AU-2, AU-9, AU-12.
`LoggingSetup.cs` logs at `Info` to a `DebuggerTarget` locally or CloudWatch (`AWSTarget`) in AWS mode. There is no explicit security-event logging (auth success/failure, access-control denials) and no scrubbing policy. Confirm that DTOs/exception payloads containing PII, tokens (`SaveTokens = true` in the OIDC options keeps tokens in the auth ticket), or connection strings are never written to logs. **Action:** add structured security event logging, ensure log integrity/retention, and verify no secrets/PII are logged.

---

## Positive observations (what is done well)

- **No SQL injection:** all data access uses EF LINQ with parameterization; a search for `SqlQuery`/`ExecuteSqlCommand`/`FromSql` returned no raw SQL (`BookRepository`, `OrderRepository`, etc.).
- **No `Html.Raw`:** Razor views rely on default output encoding, so reflected/stored XSS exposure is low.
- **Default-deny authorization:** a global `AuthorizeAttribute` is registered in `FilterConfig`, and the admin area adds role-based authorization.
- **Safe file storage naming:** uploaded files are written under `Path.GetRandomFileName()`-derived names (local and S3), preventing path traversal and overwrites.
- **Image moderation in AWS mode:** Rekognition screens uploads against objectionable categories.
- **Scoped owner lookups exist** for cancel-order, addresses, and offers-by-user; the pattern just needs to be applied consistently (see H-2).

---

## Prioritized remediation roadmap

1. **Immediate (Critical/High):** Remove/guard the local auth admin bypass (C-1); add anti-forgery across all POSTs (H-1); scope order reads to the owner (H-2); fix the open redirect (H-3); enforce HTTPS/HSTS and set `HttpOnly`/`Secure`/`SameSite` on all cookies (H-4).
2. **Near term (Medium):** Harden configuration — `debug=false`, `customErrors`, security headers (M-1, M-3); bind carts to the server-side identity (M-2); validate uploaded file content and serve user content safely (M-4); replace the drop-create EF initializer with migrations (M-5).
3. **Hygiene (Low/Info):** Remove hardcoded admin credentials and rotate at deploy (L-1); store secrets as SecureString/Secrets Manager only (L-2); disable `USER_PASSWORD_AUTH` and enable MFA (L-3); tighten `AllowAnonymous` scope (L-4); add dependency scanning (I-1) and security logging with PII/secret scrubbing (I-2).

---

*Report produced by manual static source review. Line numbers are approximate and should be re-confirmed against the current tree before remediation.*
