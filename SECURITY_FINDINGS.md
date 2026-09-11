# Security Assessment Report: Bob's Used Books Classic

**Assessment type:** Manual static application security review (SAST-style source analysis)
**Target:** `bobs-used-bookstore-classic` (ASP.NET MVC, .NET Framework 4.8, C#) + AWS CDK IaC
**Scope:** Web application (`Bookstore.Web`), domain/data layers (`Bookstore.Domain`, `Bookstore.Data`), infrastructure-as-code (`Bookstore.Cdk`), `Dockerfile`, and configuration.
**Standards referenced:** OWASP Top 10 (2021), NIST SP 800-53 Rev.5, NIST SP 800-63B.
**Method:** Full manual review of 136 C# files, 42 Razor views, and 11 configuration files. Dynamic testing was not performed (the app targets .NET Framework 4.8 / Windows containers and cannot be built or run in this Linux sandbox). Findings are based on source evidence.

> **Important context on the "local" mode.** This application ships two operating modes selected by `web.config` `Services/*` keys: a fully local mode (default, disconnected from AWS) and an AWS-connected mode. Several of the most severe findings live in the "local" implementations. These are intended for development/demo, but because they are the **shipped defaults** and are trivially reachable if deployed as-is (the ECS deployment actually forces `Services/Authentication = "local"`), they are treated as real findings, not hypotheticals.

---

## Executive summary

Bob's Used Books Classic is a sample e-commerce bookstore. The review found systemic gaps in **authentication**, **access control**, and **CSRF protection**, plus multiple **security-misconfiguration** and **infrastructure hardening** issues. The single most serious issue is that the default ("local") authentication path grants **unauthenticated administrator access to anyone** who requests the login URL. The application also has **no CSRF protection on any state-changing endpoint**, **no ownership checks** on several object-by-id lookups (IDOR), and ships with **`debug="true"`**, **no `customErrors`**, and **no security-header or secure-cookie configuration**.

Because this is a sample/reference application, many issues are "by design for simplicity," but they are documented here as they would materially compromise a real deployment.

### Findings by severity

| # | Severity | Title | OWASP 2021 |
|---|----------|-------|------------|
| F-01 | Critical | Local auth middleware grants admin to any anonymous request | A07 Identification & Auth Failures |
| F-02 | Critical | Hardcoded default admin credentials (`admin` / `P@ssword1`) in source, CDK, and README | A07 / A02 |
| F-03 | High | No CSRF protection on any state-changing POST action | A01 Broken Access Control |
| F-04 | High | IDOR: order details/receipt accessible by id without ownership check | A01 Broken Access Control |
| F-05 | High | Shopping cart / wishlist keyed on a non-HttpOnly, client-controlled cookie (cart hijack) | A01 / A05 |
| F-06 | High | RDS connection string (with DB password) stored as plaintext SSM `String`, not `SecureString` | A02 Cryptographic Failures |
| F-07 | High | `compilation debug="true"` and no `customErrors` (verbose errors / stack traces) | A05 Security Misconfiguration |
| F-08 | High | ECS/ALB serves the app over HTTP only; no TLS listener | A02 / A05 |
| F-09 | Medium | Missing HTTP security headers and secure/HttpOnly cookie policy | A05 Security Misconfiguration |
| F-10 | Medium | Open redirect in login and address return-URL handling | A01 (Unvalidated Redirects) |
| F-11 | Medium | Overly permissive IAM policy (`rekognition:* on Resource "*"`) | A05 / least-privilege |
| F-12 | Medium | S3 image bucket lacks explicit encryption + block-public-access; auto-delete/DESTROY | A05 Security Misconfiguration |
| F-13 | Medium | RDS instance not encrypted at rest; backups disabled | A02 / A05 |
| F-14 | Medium | Cognito self-sign-up enabled with a privileged "Administrators" group present | A07 / A05 |
| F-15 | Medium | Unrestricted image upload processed by ImageMagick (decompression-bomb / parser DoS) | A05 / A06 |
| F-16 | Low | Local image validation is a no-op (always returns "safe") | A04 Insecure Design |
| F-17 | Low | Insufficient logging & monitoring (single global error handler, no audit trail) | A09 Logging & Monitoring Failures |
| F-18 | Low | OpenID Connect: `SaveTokens=true`, `COGNITO_ADMIN` scope requested; broad token storage | A05 / A02 |
| F-19 | Low | Cookieless correlation id uses `Guid.NewGuid()` (not a security finding by itself; see F-05) | Informational |

**Areas assessed and found clean / not applicable:** SQL injection (all data access uses Entity Framework LINQ with parameterization; no raw SQL, `FromSql`, `ExecuteSqlCommand`, or string-concatenated queries found), XSS via `Html.Raw` (no `@Html.Raw` usage in any view; Razor auto-encodes output), XXE / insecure deserialization (no `XmlDocument`/`BinaryFormatter`/`XmlSerializer` on untrusted input found), command injection (no process execution on user input found).

---

## Detailed findings

### F-01 — Local authentication middleware grants administrator access to any anonymous visitor
- **Severity:** Critical
- **OWASP:** A07:2021 Identification and Authentication Failures
- **NIST:** IA-2 (Identification and Authentication), AC-6 (Least Privilege), IA-5
- **Files:**
  - `app/Bookstore.Web/Helpers/LocalAuthenticationMiddleware.cs` (lines ~24–61)
  - `app/Bookstore.Web/Controllers/AuthenticationController.cs` (lines ~10–15)
  - `app/Bookstore.Web/App_Start/AuthenticationSetup.cs` (lines ~29–33)

**Description.** In the default "local" authentication mode, the OWIN middleware intercepts any request whose path starts with `/Authentication/Login`, unconditionally builds a `ClaimsPrincipal`, and assigns it the **`Administrators`** role. There is no username, password, or any credential check. A `LocalAuthentication` cookie is then set (with no value, no HttpOnly, no Secure, no signature), and on every subsequent request the mere presence of that cookie re-establishes the same admin identity.

**Evidence.**
```csharp
// LocalAuthenticationMiddleware.cs
if (context.Request.Path.Value.StartsWith("/Authentication/Login"))
{
    CreateClaimsPrincipal(context);              // no credentials checked
    await SaveCustomerDetailsAsync();
    var userCookie = new HttpCookie("LocalAuthentication") { Expires = DateTime.Now.AddDays(1) };
    HttpContext.Current.Response.Cookies.Add(userCookie);
    context.Response.Redirect("/");
}
...
private void CreateClaimsPrincipal(IOwinContext context)
{
    var identity = new ClaimsIdentity("Application");
    identity.AddClaim(new Claim(ClaimTypes.Name, "bookstoreuser"));
    ...
    identity.AddClaim(new Claim(ClaimTypes.Role, "Administrators"));   // <-- admin for everyone
    context.Request.User = new ClaimsPrincipal(identity);
}
```

**Impact.** Anyone who can reach the site can become an administrator simply by visiting `/Authentication/Login` (or by forging the `LocalAuthentication` cookie). This grants full access to the Admin area (inventory create/update, order management, offers, reference data). The README's deployment section states the ECS/Fargate deployment **forces `Services/Authentication = "local"`** because the Cognito hosted UI needs HTTPS — so this path is the one used in the provided cloud deployment, not just local dev. See also `EcsStack.cs` (`{ "Services/Authentication", "local" }`).

**Remediation.**
- Do not ship a "local" auth provider that self-elevates to admin. If a dev bypass is required, gate it behind a compile-time `#if DEBUG` and an explicit non-production environment check, and never assign the `Administrators` role by default.
- For any internet-reachable deployment, require a real IdP (Cognito) with enforced HTTPS. Do not degrade to the local bypass to work around the HTTPS redirect requirement; put the ALB behind TLS (see F-08) so Cognito can be used.
- Sign/encrypt any auth cookie and set `HttpOnly` + `Secure` + `SameSite`.

---

### F-02 — Hardcoded default administrator credentials in source, IaC, and documentation
- **Severity:** Critical
- **OWASP:** A07:2021 Identification and Authentication Failures / A02:2021 Cryptographic Failures
- **NIST:** IA-5 (Authenticator Management), SP 800-63B
- **Files:**
  - `app/Bookstore.Cdk/CoreStack.cs` (`CreateDefaultAdminUser`, lines ~140–175)
  - `README.md` ("Amazon Cognito first run": `Username: Admin`, `Password: P@ssword1`)

**Description.** The CDK stack provisions a Cognito user `admin` with a hardcoded temporary password `P@ssword1`, adds it to the `Administrators` group, and the README publishes these credentials.

**Evidence.**
```csharp
// CoreStack.cs
const string UserName = "admin";
Parameters = new Dictionary<string, string>
{
    { "UserPoolId", WebAppUserPool.UserPoolId },
    { "Username", UserName },
    { "TemporaryPassword", "P@ssword1" },       // hardcoded, published in README
    { "MessageAction", "SUPPRESS" }
},
```

**Impact.** A publicly known admin credential seeded into every deployment. Combined with F-14 (self-sign-up) and the `COGNITO_ADMIN` OAuth scope, this is a direct path to administrative compromise.

**Remediation.**
- Generate a random temporary password at deploy time (e.g., AWS Secrets Manager generated secret) and require change-on-first-login; never commit a password to source or docs.
- Remove the credentials from `README.md` or replace with instructions to set them out-of-band.
- Do not add the seeded user to a privileged group automatically.

---

### F-03 — No CSRF protection on any state-changing endpoint
- **Severity:** High
- **OWASP:** A01:2021 Broken Access Control (CSRF)
- **NIST:** SC-8, SI-10
- **Files (all `[HttpPost]` actions lack `[ValidateAntiForgeryToken]`):**
  - `app/Bookstore.Web/Controllers/CheckoutController.cs` (Index POST)
  - `app/Bookstore.Web/Controllers/OrdersController.cs` (Delete)
  - `app/Bookstore.Web/Controllers/ResaleController.cs` (Create)
  - `app/Bookstore.Web/Controllers/AddressController.cs` (Create/Update/Delete)
  - `app/Bookstore.Web/Controllers/ShoppingCartController.cs` (Delete)
  - `app/Bookstore.Web/Controllers/WishlistController.cs` (MoveToShoppingCart / MoveAllItemsToShoppingCart / Delete)
  - `app/Bookstore.Web/Areas/Admin/Controllers/InventoryController.cs` (Create/Update)
  - `app/Bookstore.Web/Areas/Admin/Controllers/OffersController.cs` (4 POSTs)
  - `app/Bookstore.Web/Areas/Admin/Controllers/OrdersController.cs` (Details POST)
  - `app/Bookstore.Web/Areas/Admin/Controllers/ReferenceDataController.cs` (2 POSTs)

**Description.** A repository-wide search confirms **zero** occurrences of `AntiForgeryToken`, `[ValidateAntiForgeryToken]`, or `@Html.AntiForgeryToken()` anywhere in the codebase. Every state-changing POST is therefore vulnerable to Cross-Site Request Forgery.

**Impact.** An attacker can host a page that auto-submits forms to these endpoints. Against an authenticated admin this allows forging inventory changes, order-status updates, and reference-data edits; against a customer it allows cart/address/order manipulation. This is especially severe combined with F-01 (admin identity persisted in a cookie).

**Remediation.**
- Add `@Html.AntiForgeryToken()` to every form and decorate every state-changing action (or a global filter) with `[ValidateAntiForgeryToken]`.
- Set `SameSite=Lax`/`Strict` on auth/session cookies as defense in depth.

---

### F-04 — IDOR: order details and checkout receipt retrievable by id without ownership check
- **Severity:** High
- **OWASP:** A01:2021 Broken Access Control (Insecure Direct Object Reference)
- **NIST:** AC-3 (Access Enforcement), AC-4
- **Files:**
  - `app/Bookstore.Web/Controllers/OrdersController.cs` — `Details(int id)` (lines ~26–30)
  - `app/Bookstore.Web/Controllers/CheckoutController.cs` — `Finished(int orderId)` (lines ~45–49)
  - `app/Bookstore.Data/Repositories/OrderRepository.cs` — `GetAsync(int id)` vs `GetAsync(int id, string sub)`

**Description.** The customer-facing `OrdersController.Details` and `CheckoutController.Finished` call `orderService.GetOrderAsync(id)` / `GetOrderAsync(orderId)`, which resolves to the repository overload `GetAsync(int id)` that looks up by primary key **only**. A second overload `GetAsync(int id, string sub)` that scopes by the authenticated customer's `sub` exists but is **not** used by these read paths. Order ids are sequential integers.

**Evidence.**
```csharp
// OrdersController.cs (customer)
public async Task<ActionResult> Details(int id)
{
    var order = await orderService.GetOrderAsync(id);   // no ownership scoping
    return View(new OrderDetailsViewModel(order));
}
```
```csharp
// OrderRepository.cs
async Task<Order> IOrderRepository.GetAsync(int id) { ... SingleOrDefaultAsync(x => x.Id == id); }
async Task<Order> IOrderRepository.GetAsync(int id, string sub) {
    return await dbContext.Order.SingleOrDefaultAsync(x => x.Id == id && x.Customer.Sub == sub);
}
```

**Impact.** Any authenticated user can enumerate `?id=1,2,3...` and read other customers' orders, including linked customer, address, and order-item PII (a confidentiality breach / privacy violation).

**Remediation.** Always scope customer reads to the current principal: use `GetAsync(id, User.GetSub())` (as `OrderRepository.GetAsync(int id, string sub)` already supports) and return 404 when no owned record matches. Keep the unscoped overload for the Admin area only.

---

### F-05 — Cart/wishlist keyed on a non-HttpOnly, client-controlled correlation cookie
- **Severity:** High
- **OWASP:** A01:2021 Broken Access Control / A05:2021 Security Misconfiguration
- **NIST:** AC-3, SC-23 (Session Authenticity)
- **Files:**
  - `app/Bookstore.Web/Helpers/HttpContextExtensions.cs` (`GetShoppingCartCorrelationId`)
  - `app/Bookstore.Web/Controllers/ShoppingCartController.cs` (`[AllowAnonymous]`)
  - `app/Bookstore.Web/Controllers/WishlistController.cs` (`[AllowAnonymous]`)

**Description.** The shopping cart and wishlist are retrieved via a `ShoppingCartId` correlation identifier read directly from a client cookie. The cookie is written with **no `HttpOnly`, no `Secure`, and no `SameSite`** flags. For authenticated users the correlation id is set to the user's `sub` (a stable, guessable identifier); for anonymous users it is a random GUID. Both `ShoppingCartController` and `WishlistController` are marked `[AllowAnonymous]`.

**Evidence.**
```csharp
// HttpContextExtensions.cs
var cookieOptions = new CookieOptions { Expires = DateTime.Now.AddYears(1), Path = "/" };  // options never applied
...
shoppingCartClientId = context.User.Identity.IsAuthenticated ? context.User.GetSub() : Guid.NewGuid().ToString();
context.Response.Cookies.Add(new HttpCookie(CookieKey, shoppingCartClientId));   // no HttpOnly/Secure/SameSite
```

**Impact.**
- Because the correlation id equals the user `sub` when authenticated and the cart is fetched by that value, an attacker who learns/guesses a `sub` (which is also used as the order/address key) can set the `ShoppingCartId` cookie to that value and view/modify another user's cart or wishlist.
- The cookie is readable by client script (no `HttpOnly`) and sent over plaintext HTTP (no `Secure`; see F-08), enabling theft/tampering.
- The prepared `cookieOptions` object is never passed to the emitted cookie, so even the intended `Path`/`Expires` hardening is a no-op.

**Remediation.** Use a signed/opaque, server-issued cart token that is unrelated to the user `sub`; set `HttpOnly`, `Secure`, `SameSite` on the cookie; for authenticated users resolve the cart server-side from the authenticated identity rather than a client-supplied cookie value.

---

### F-06 — Database connection string (with password) stored as plaintext SSM `String`
- **Severity:** High
- **OWASP:** A02:2021 Cryptographic Failures
- **NIST:** SC-28 (Protection of Information at Rest), IA-5, SC-12
- **File:** `app/Bookstore.Cdk/DatabaseStack.cs` (`CreateConnectionString`, lines ~70–83)

**Description.** The RDS master password is pulled from the RDS-managed secret and then **re-serialized into a full connection string stored in an SSM Parameter Store `StringParameter` (plaintext `String` type, not `SecureString`)**.

**Evidence.**
```csharp
var password = Database.Secret.SecretValueFromJson("password");
...
_ = new StringParameter(this, "DatabaseConnectionStringSSMParameter", new StringParameterProps
{
    ParameterName = $"/{Constants.AppName}/Database/ConnectionStrings/BookstoreDatabaseConnection",
    StringValue = $"Server={server};Database={database};User Id={userId};Password={password};"  // plaintext, incl. password
});
```

**Impact.** The database password is exposed in cleartext to anyone with `ssm:GetParameter` on that path (the ECS task role has exactly this, see `EcsStack.cs`), and in CloudFormation template/change-set output. It defeats the purpose of the RDS-managed secret.

**Remediation.** Keep the credential only in Secrets Manager and have the app read it at runtime, or use an SSM `SecureString` (KMS-encrypted) parameter. Never concatenate the password into a plaintext parameter. Restrict read access to the specific secret ARN.

---

### F-07 — `debug="true"` compilation and no `customErrors` (verbose errors / information disclosure)
- **Severity:** High
- **OWASP:** A05:2021 Security Misconfiguration
- **NIST:** SI-11 (Error Handling), CM-6, CM-7
- **Files:**
  - `app/Bookstore.Web/Web.config` (`<compilation debug="true" targetFramework="4.8" />`)
  - `app/Bookstore.Web/Web.Release.config` (only removes `debug`; does **not** add `<customErrors>`)

**Description.** The base `Web.config` enables `debug="true"` and defines **no** `<customErrors>` element (defaults to `mode="RemoteOnly"` only if left default — but here there is no `<system.web>/<customErrors>` at all, and the Release transform does not add one). With debug on and no custom error page, unhandled exceptions render full ASP.NET yellow-screen stack traces.

**Evidence.**
```xml
<!-- Web.config -->
<system.web>
  <compilation debug="true" targetFramework="4.8" />
  <httpRuntime targetFramework="4.8" />
</system.web>
```
```xml
<!-- Web.Release.config: removes debug but adds NO customErrors section -->
<compilation xdt:Transform="RemoveAttributes(debug)" />
```

**Impact.** `debug="true"` disables request timeouts, bloats memory, leaks PDB/source paths, and is explicitly warned against for production by Microsoft. Absent `customErrors`, stack traces, framework versions, and internal paths are disclosed to clients, aiding attackers.

**Remediation.** Set `debug="false"` for all non-dev builds (the Release transform should also explicitly set it false, not just remove it) and add `<customErrors mode="On" defaultRedirect="~/Home/Error" />` with `<httpErrors>` for IIS. Log full details server-side only.

---

### F-08 — Application served over HTTP only in the ECS/ALB deployment (no TLS)
- **Severity:** High
- **OWASP:** A02:2021 Cryptographic Failures / A05:2021 Security Misconfiguration
- **NIST:** SC-8 (Transmission Confidentiality/Integrity), SC-13
- **File:** `app/Bookstore.Cdk/EcsStack.cs` (`ApplicationLoadBalancedFargateService`, health check `Path = "/Home/Privacy"`)

**Description.** The `ApplicationLoadBalancedFargateService` is created without a `Certificate`/`Protocol = HTTPS` listener, so the ALB listens on HTTP:80. The README confirms "ECS on Fargate is configured to use HTTP." Consequently auth cookies (F-01/F-05) and all form data (checkout, addresses) traverse the network in cleartext, and Cognito cannot be used (driving the F-01 admin-bypass fallback).

**Impact.** Session/cookie theft and data interception via network MITM; no transport integrity. Combined with non-Secure cookies (F-05, F-09) this is directly exploitable on shared networks.

**Remediation.** Provision an ACM certificate and configure an HTTPS (443) listener with HTTP→HTTPS redirect on the ALB; then enable Cognito OIDC (removing the need for the local admin bypass). Set `requireSSL` on cookies once TLS is in place.

---

### F-09 — Missing HTTP security headers and secure cookie policy
- **Severity:** Medium
- **OWASP:** A05:2021 Security Misconfiguration
- **NIST:** SC-8, SC-18, CM-6
- **Files:** `app/Bookstore.Web/Web.config`, `app/Bookstore.Web/Views/Web.config`

**Description.** No `<httpCookies httpOnlyCookies="true" requireSSL="true" />`, no `<httpProtocol><customHeaders>` for `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`/frame-ancestors, `Strict-Transport-Security`, or `Referrer-Policy`. ASP.NET also emits `Server` and `X-Powered-By`/`X-AspNet-Version` banners by default, which are not suppressed.

**Impact.** Increased exposure to XSS impact (no CSP), clickjacking (no frame protections), MIME sniffing, and technology fingerprinting. Cookies default to non-Secure/non-HttpOnly (compounds F-05).

**Remediation.** Add `<httpCookies httpOnlyCookies="true" requireSSL="true" sameSite="Lax" />`, define the security headers in `<system.webServer><httpProtocol><customHeaders>`, remove `X-Powered-By` (`<remove name="X-Powered-By"/>`), and set `<httpRuntime enableVersionHeader="false" />`.

---

### F-10 — Open redirect via login `redirectUri` and address `ReturnUrl`
- **Severity:** Medium
- **OWASP:** A01:2021 Broken Access Control (Unvalidated Redirects and Forwards)
- **NIST:** SI-10
- **Files:**
  - `app/Bookstore.Web/Controllers/AuthenticationController.cs` — `Login(string redirectUri)` → `return Redirect(redirectUri);`
  - `app/Bookstore.Web/Controllers/AddressController.cs` — `Create`/`Update` → `return Redirect(model.ReturnUrl);`

**Description.** User-controlled URLs are passed straight to `Redirect(...)` with no validation that the target is a local/allow-listed URL.

**Evidence.**
```csharp
// AuthenticationController.cs
public ActionResult Login(string redirectUri = null)
{
    if (string.IsNullOrWhiteSpace(redirectUri)) return RedirectToAction("Index", "Home");
    return Redirect(redirectUri);   // arbitrary external URL
}
```

**Impact.** Phishing and OAuth-flow abuse: a crafted `?redirectUri=https://evil.example` link on the trusted domain redirects victims off-site, lending credibility to credential-harvesting pages.

**Remediation.** Use `Url.IsLocalUrl(redirectUri)` and reject/normalize non-local targets; or maintain an allow-list of return destinations.

---

### F-11 — Overly permissive IAM policy (Rekognition on all resources)
- **Severity:** Medium
- **OWASP:** A05:2021 Security Misconfiguration (Least Privilege)
- **NIST:** AC-6 (Least Privilege)
- **File:** `app/Bookstore.Cdk/EcsStack.cs` (`CreateEcsPermissions`)

**Description.** The ECS task role is granted `rekognition:DetectModerationLabels` on `Resources = "*"`, plus broad CloudWatch Logs actions on `arn:aws:logs:*:*:log-group:*:log-stream:*`. While Rekognition's `DetectModerationLabels` is resourceless by nature, the logs grant and the wildcard SSM path are broader than necessary.

**Impact.** A compromised task (e.g., via F-15) has more AWS reach than required, increasing blast radius.

**Remediation.** Scope logs actions to the specific log group ARN (`log-group:BobsUsedBooksClassic:*`), scope SSM to the exact parameter ARNs the app reads, and prefer condition keys where possible.

---

### F-12 — S3 image bucket lacks explicit encryption / block-public-access; destructive removal policy
- **Severity:** Medium
- **OWASP:** A05:2021 Security Misconfiguration
- **NIST:** SC-28, SI-12, CP-9
- **File:** `app/Bookstore.Cdk/CoreStack.cs` (`CreateImageS3Bucket`)

**Description.** The `Bucket` is created without explicit `Encryption`, `BlockPublicAccess = BLOCK_ALL`, `EnforceSSL = true`, or versioning. It sets `AutoDeleteObjects = true` and `RemovalPolicy.DESTROY`. Access is fronted by CloudFront OAI (good), but the bucket-level protections are not asserted in code and rely on account defaults.

**Impact.** Risk of accidental data loss (DESTROY + auto-delete) and, if account-level S3 Block Public Access is ever disabled, exposure. No enforced TLS-only bucket policy.

**Remediation.** Set `BlockPublicAccess = BlockPublicAccess.BLOCK_ALL`, `Encryption = BucketEncryption.S3_MANAGED` (or KMS), `EnforceSSL = true`, and use a non-destructive `RemovalPolicy` for any environment holding real data.

---

### F-13 — RDS instance not encrypted at rest; automated backups disabled
- **Severity:** Medium
- **OWASP:** A02:2021 Cryptographic Failures / A05 Security Misconfiguration
- **NIST:** SC-28, CP-9 (System Backup)
- **File:** `app/Bookstore.Cdk/DatabaseStack.cs` (`CreateDatabase`)

**Description.** `DatabaseInstance` is created without `StorageEncrypted = true` (no KMS key) and with `BackupRetention = Duration.Seconds(0)` (backups disabled). The security group is created but no ingress is defined in this file (ingress is added later via `Connections.AllowTo` from ECS, which is appropriate).

**Impact.** Customer/order PII stored unencrypted at rest; no point-in-time recovery. Note this is called out in comments as a cost-saving sample choice, but it is a real risk in any non-throwaway deployment.

**Remediation.** Set `StorageEncrypted = true` with a managed/customer KMS key and enable a reasonable `BackupRetention` for production.

---

### F-14 — Cognito self-sign-up enabled alongside a privileged Administrators group
- **Severity:** Medium
- **OWASP:** A07:2021 Identification and Authentication Failures / A05
- **NIST:** AC-2 (Account Management), IA-2
- **File:** `app/Bookstore.Cdk/CoreStack.cs` (`CreateCognitoUserPool`, `CreateUserPoolClient`)

**Description.** The user pool sets `SelfSignUpEnabled = true` with `AutoVerify email`, and the app clients request the `COGNITO_ADMIN` OAuth scope. There is no restriction preventing self-registered users from being placed into or requesting the `Administrators` group beyond manual controls.

**Impact.** Open registration on an app that also defines an admin group and ships a known admin credential (F-02) broadens the attack surface for privilege escalation and abuse (spam accounts).

**Remediation.** Disable self-sign-up (or add admin approval / domain restrictions) for any deployment that has privileged roles; remove the `COGNITO_ADMIN` scope from app clients unless explicitly required; enforce strong password policy and MFA (NIST SP 800-63B).

---

### F-15 — Unrestricted image upload processed by ImageMagick (decompression bomb / parser DoS)
- **Severity:** Medium
- **OWASP:** A05:2021 Security Misconfiguration / A06 Vulnerable and Outdated Components
- **NIST:** SI-10 (Input Validation), SC-5 (Denial of Service Protection)
- **Files:**
  - `app/Bookstore.Web/Areas/Admin/Models/Inventory/InventoryCreateUpdateViewModel.cs` (`CoverImage` validators)
  - `app/Bookstore.Web/Helpers/ImageTypesAttribute.cs`, `MaxFileSizeAttribute.cs`
  - `app/Bookstore.Data/ImageResizeService/ImageResizeService.cs` (`new MagickImage(image)`)

**Description.** Uploaded cover images are validated only by **file extension** (`.png/.jpg/.jpeg`) and a 2 MB size cap — not by actual content type / magic bytes. The stream is then handed to Magick.NET (`new MagickImage(image)`) for resizing. Extension-only validation is trivially bypassed, and ImageMagick has a long history of parser vulnerabilities and is susceptible to decompression bombs (a small file can expand to consume large memory/CPU).

**Impact.** A crafted image can cause CPU/memory exhaustion (DoS) on the server, or exploit an ImageMagick parser bug. Because uploads reach `InventoryController` (admin), and admin is reachable per F-01, this is realistically triggerable.

**Remediation.** Validate real content type (inspect magic bytes / use `MagickFormatInfo`), set explicit ImageMagick resource limits (`ResourceLimits.Width/Height/Memory`), disable unneeded coders, keep Magick.NET patched, and process uploads out-of-band where possible.

---

### F-16 — Local image validation is a no-op (always "safe")
- **Severity:** Low
- **OWASP:** A04:2021 Insecure Design
- **NIST:** SI-10
- **File:** `app/Bookstore.Data/ImageValidationServices/LocalImageValidationService.cs`

**Description.** In local mode the content-moderation check unconditionally returns `true`.
```csharp
public async Task<bool> IsSafeAsync(Stream image) => await Task.Run(() => true);
```
**Impact.** No moderation of uploaded imagery in the default configuration (acceptable for dev, but silently ships as the default). **Remediation.** Make the default fail-safe/explicit, and document that moderation only occurs in AWS mode.

---

### F-17 — Insufficient logging and monitoring
- **Severity:** Low
- **OWASP:** A09:2021 Security Logging and Monitoring Failures
- **NIST:** AU-2 (Event Logging), AU-6, AU-12
- **Files:** `app/Bookstore.Web/Global.asax.cs` (`Application_Error`), `app/Bookstore.Web/App_Start/LoggingSetup.cs`

**Description.** The only error handling is a single global `Application_Error` that logs the exception. There is no security-relevant audit logging (authentication events, admin actions, authorization failures, order access), and the local logging target is only the debugger. There is no alerting/monitoring wired for suspicious activity.

**Impact.** IDOR access (F-04), CSRF-driven changes (F-03), and the auth bypass (F-01) would leave little forensic trail. **Remediation.** Add structured audit logging for auth and admin/privileged actions and authorization denials, ship to CloudWatch in all modes, and add alerting.

---

### F-18 — OpenID Connect token handling: broad scope and token persistence
- **Severity:** Low
- **OWASP:** A05:2021 Security Misconfiguration / A02
- **NIST:** IA-5, SC-28
- **Files:** `app/Bookstore.Web/App_Start/AuthenticationSetup.cs`, `app/Bookstore.Cdk/CoreStack.cs` / `EcsStack.cs`

**Description.** The OIDC middleware sets `SaveTokens = true` (persisting access/refresh/ID tokens in the auth cookie) and the app clients request the `COGNITO_ADMIN` scope. The default `CookieAuthenticationOptions()` are used with no explicit `CookieSecure`/`SameSite` hardening. Combined with HTTP-only transport (F-08), persisted tokens are at elevated risk.

**Remediation.** Request only the minimum scopes (`openid profile email`), avoid `SaveTokens` unless needed, and configure cookie auth with `CookieSecure = Always`, `SameSite`, and short lifetimes.

---

### F-19 — (Informational) Anonymous cart correlation id generation
- **Severity:** Informational
- **File:** `app/Bookstore.Web/Helpers/HttpContextExtensions.cs`

`Guid.NewGuid()` for anonymous carts is acceptable in isolation; the real risk is the authenticated-user branch reusing `sub` and the missing cookie flags — tracked under **F-05**. Listed here only to note it was reviewed.

---

## Areas explicitly reviewed and not flagged

| Area | Result | Evidence |
|------|--------|----------|
| SQL Injection | Not found | All data access uses EF6 LINQ (`dbContext.Order.Where(...)`, `SingleOrDefaultAsync`); no `FromSql`/`ExecuteSqlCommand`/`SqlQuery`/raw `CommandText`/string-concatenated SQL anywhere in `app/`. |
| Cross-Site Scripting (stored/reflected) | No `Html.Raw` sinks | No `@Html.Raw`/`Html.Raw` in any of the 42 `.cshtml` views; Razor HTML-encodes by default. (Note: F-09 CSP absence still increases residual XSS impact.) |
| Command Injection | Not found | No `Process.Start`, shell invocation, or OS command execution on user input. |
| XXE / Insecure Deserialization | Not found | No `BinaryFormatter`, `XmlSerializer`/`XmlDocument`/`DataContractSerializer` over untrusted input; JSON handled by Newtonsoft/System.Text.Json without type-name handling. |
| Path traversal on stored files | Low risk | `LocalFileService`/`S3FileService` generate server-side random filenames (`Path.GetRandomFileName()`), preserving only the extension; user filename is not used for the storage key. |

*Assessment limitation:* dynamic/runtime testing (authenticated fuzzing, live IDOR exploitation, dependency CVE confirmation against running binaries) was **not** performed because the .NET Framework 4.8 / Windows-container app cannot be built or executed in this Linux environment. Dependency versions in `packages.config` appear current (e.g., Newtonsoft.Json 13.0.3, EntityFramework 6.5.1) but were not scanned against a live CVE feed; a follow-up SCA scan (e.g., `dotnet list package --vulnerable` on a Windows build, or OWASP Dependency-Check) is recommended.

---

## Prioritized remediation roadmap

1. **Immediately (Critical):** Remove/gate the local admin auth bypass (F-01); rotate and stop publishing default admin credentials (F-02).
2. **High:** Add anti-forgery tokens globally (F-03); enforce ownership scoping on order reads (F-04); fix cart cookie/correlation model (F-05); move DB secret out of plaintext SSM (F-06); disable debug + add customErrors (F-07); terminate TLS at the ALB (F-08).
3. **Medium:** Add security headers + secure cookies (F-09); validate redirects (F-10); tighten IAM (F-11); harden S3 (F-12) and RDS (F-13); restrict Cognito sign-up/scopes (F-14); harden image upload/processing (F-15).
4. **Low / hygiene:** Make local image validation explicit (F-16); add security audit logging + alerting (F-17); minimize OIDC scope/token persistence (F-18).

> No application source was modified as part of this assessment; this report is a findings-only deliverable. Remediation can be undertaken as a follow-up on request.
