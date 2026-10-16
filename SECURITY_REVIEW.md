# Security Review: Bob's Used Books Classic

**Target:** `bobs-used-bookstore-classic` — ASP.NET MVC 5 application on .NET Framework 4.8
**Review type:** Manual static source code review (SAST-style, no dynamic testing, no build)
**Standards referenced:** OWASP Top 10 (2021), OWASP ASVS, NIST SP 800-53 Rev. 5, NIST SP 800-63B
**Scope:** `app/Bookstore.Web`, `app/Bookstore.Data`, `app/Bookstore.Domain`, `app/Bookstore.Common`, `app/Bookstore.Cdk`, configuration files, `Dockerfile`

> This is a documentation-only deliverable. No application behavior was changed.

---

## Executive summary

Bob's Used Books Classic is an AWS sample application. As is common with samples, it prioritizes ease of first-run over production hardening, and several of those trade-offs are security relevant. The review found issues spanning authentication, access control, CSRF, security misconfiguration, cryptographic handling of secrets, file upload handling, and cloud infrastructure (CDK) configuration.

The two most serious issues are:

1. **The "local" authentication mode grants every anonymous visitor full Administrator rights** with no credential check at all (`LocalAuthenticationMiddleware`). This mode is the default in `Web.config` and is also what the ECS/Fargate deployment runs in production, per `EcsStack.cs`.
2. **Broken object-level authorization (IDOR)** lets any authenticated customer read any other customer's order by guessing a numeric id (`OrdersController.Details`, `CheckoutController.Finished`).

In addition, **no controller action uses an anti-forgery token**, so the entire authenticated surface is open to CSRF; **`debug="true"` with no `<customErrors>`** leaks stack traces; secrets are embedded in connection strings and logged paths without protection; and the CDK stacks use **permissive IAM (`Resource = "*"`)**, a **hardcoded default admin password (`P@ssword1`)**, **self-sign-up enabled on the Cognito pool**, and **`RemovalPolicy.DESTROY` with auto-delete** on the data bucket.

### Findings by severity

| # | Severity | Title | OWASP 2021 |
|---|----------|-------|------------|
| F-01 | Critical | Local auth mode grants Administrator to all anonymous users | A07 |
| F-02 | Critical | Broken object-level authorization (IDOR) on orders | A01 |
| F-03 | High | No CSRF / anti-forgery protection on any state-changing action | A01 |
| F-04 | High | Hardcoded default admin credentials in CDK and docs | A07 |
| F-05 | High | Authentication/session cookies lack Secure, HttpOnly, SameSite | A05 / A07 |
| F-06 | High | `debug="true"` and missing `customErrors` leak internals | A05 |
| F-07 | High | Overly permissive IAM policies in CDK (`Resource = "*"`) | A01 / A05 |
| F-08 | Medium | Secrets handled in plaintext (connection strings, SSM, logging) | A02 |
| F-09 | Medium | Unrestricted file upload: validation is bypassable and client-trusted | A04 / A05 |
| F-10 | Medium | Cognito user pool allows self sign-up; weak password policy | A07 |
| F-11 | Medium | Missing security response headers (HSTS, CSP, X-Content-Type-Options) | A05 |
| F-12 | Medium | S3 data bucket uses RemovalPolicy.DESTROY + AutoDeleteObjects | A05 |
| F-13 | Medium | Open redirect in authentication login flow | A01 |
| F-14 | Low | RDS: backups disabled, storage/transit encryption not enforced | A05 / A04 |
| F-15 | Low | Verbose error logging may capture sensitive data | A09 |
| F-16 | Low | Dependency/patch management: pinned libraries, no SCA gate | A06 |

---

## Critical findings

### F-01 — Local authentication mode grants Administrator to every anonymous visitor
- **Severity:** Critical
- **OWASP:** A07:2021 Identification and Authentication Failures (also A01 Broken Access Control)
- **NIST:** SP 800-53 AC-3, IA-2; SP 800-63B
- **Files:**
  - `app/Bookstore.Web/Helpers/LocalAuthenticationMiddleware.cs` (lines 24-61)
  - `app/Bookstore.Web/App_Start/AuthenticationSetup.cs` (lines 19-33)
  - `app/Bookstore.Web/Web.config` (`Services/Authentication` = `local`, line ~19)
  - `app/Bookstore.Cdk/EcsStack.cs` (lines ~60-66, forces `local` in Fargate)

**Description.** When `Services/Authentication` is `local` (the default, and the mode used by the ECS/Fargate deployment because the Cognito Hosted UI requires HTTPS), `LocalAuthenticationMiddleware.Invoke` builds a `ClaimsPrincipal` for anyone who requests `/Authentication/Login` and unconditionally adds `new Claim(ClaimTypes.Role, "Administrators")`. No username or password is ever checked. It then drops a non-expiring-marker cookie named `LocalAuthentication`; on every subsequent request the mere presence of that cookie re-establishes the same Administrator principal.

```csharp
identity.AddClaim(new Claim(ClaimTypes.Role, "Administrators"));
context.Request.User = new ClaimsPrincipal(identity);
```

**Impact.** Any unauthenticated user who browses to `/Authentication/Login` (or forges the `LocalAuthentication` cookie) becomes an administrator and can reach the entire `Admin` area (`[Authorize(Roles = "Administrators")]` in `AdminAreaControllerBase`), including inventory create/update/delete, offer approval and payout, order management, and reference data editing. Because `EcsStack.cs` sets `Services/Authentication = local` for the Fargate task, this applies to the documented production deployment path, not just local development.

**Remediation.**
- Treat local mode strictly as a developer-only convenience: compile it out of release builds or gate it behind a build configuration / environment guard so it can never run in a deployed environment.
- For any deployed environment, require a real identity provider (Cognito) over HTTPS. If Fargate must stay on HTTP behind the ALB, terminate TLS at the ALB and configure the OIDC redirect to use the HTTPS ALB URL rather than falling back to local auth.
- Never assign the `Administrators` role implicitly. Roles must come from an authenticated identity provider.

---

### F-02 — Broken object-level authorization (IDOR) on order details
- **Severity:** Critical
- **OWASP:** A01:2021 Broken Access Control
- **NIST:** SP 800-53 AC-3, AC-4
- **Files:**
  - `app/Bookstore.Web/Controllers/OrdersController.cs` (lines 24-29)
  - `app/Bookstore.Web/Controllers/CheckoutController.cs` (`Finished`, lines ~46-50)
  - `app/Bookstore.Domain/Orders/OrderService.cs` (`GetOrderAsync(int id)`, lines ~53-55)

**Description.** `OrdersController.Details(int id)` calls `orderService.GetOrderAsync(id)` using only the route id, with no check that the order belongs to the current user. Compare with `OrdersController.Delete`, which correctly scopes the operation to the owner via `new CancelOrderDto(User.GetSub(), id)`, and with `AddressService.GetAddressAsync(string sub, int id)`, which takes the owner `sub` as a parameter. The order read path is missing that ownership binding. `CheckoutController.Finished(int orderId)` has the same defect.

```csharp
public async Task<ActionResult> Details(int id)
{
    var order = await orderService.GetOrderAsync(id);   // no ownership check
    return View(new OrderDetailsViewModel(order));
}
```

**Impact.** Any authenticated customer can enumerate `/Orders/Details/{id}` (and `/Checkout/Finished?orderId={id}`) and read other customers' orders: items purchased, quantities, prices, and any shipping/address data exposed by the view model. This is a confidentiality breach and a classic IDOR.

**Remediation.**
- Add an owner parameter to the read path, mirroring `GetAddressAsync`: `GetOrderAsync(string sub, int id)` and filter in the repository `WHERE Order.CustomerSub == sub`.
- Return 404 (not 403) when the record exists but is not owned by the caller, to avoid confirming existence.
- Audit every controller action that accepts an `id` from the route/query and loads a user-owned entity for the same gap (orders, offers, cart items, wishlist items).

---

## High findings

### F-03 — No CSRF / anti-forgery protection on state-changing actions
- **Severity:** High
- **OWASP:** A01:2021 Broken Access Control (CSRF)
- **NIST:** SP 800-53 SC-23
- **Files (all `[HttpPost]` actions lack `[ValidateAntiForgeryToken]`):**
  - `app/Bookstore.Web/Controllers/AddressController.cs` (Create/Update/Delete)
  - `app/Bookstore.Web/Controllers/OrdersController.cs` (Delete)
  - `app/Bookstore.Web/Controllers/ShoppingCartController.cs` (Delete)
  - `app/Bookstore.Web/Controllers/WishlistController.cs` (MoveToShoppingCart/MoveAllItemsToShoppingCart/Delete)
  - `app/Bookstore.Web/Controllers/CheckoutController.cs` (Index)
  - `app/Bookstore.Web/Controllers/ResaleController.cs` (Create)
  - `app/Bookstore.Web/Areas/Admin/Controllers/InventoryController.cs` (Create/Update)
  - `app/Bookstore.Web/Areas/Admin/Controllers/OffersController.cs` (Approve/Reject/Received/Paid)
  - `app/Bookstore.Web/Areas/Admin/Controllers/ReferenceDataController.cs` (Create/Update)
  - `app/Bookstore.Web/Areas/Admin/Controllers/OrdersController.cs` (Details POST)

**Description.** A repository-wide search for `ValidateAntiForgeryToken` / `AntiForgery` returns no matches. No `@Html.AntiForgeryToken()` is present in the forms, and there is no global `AutoValidateAntiforgeryTokenAttribute` registered in `FilterConfig` (which only registers `HandleErrorAttribute` and `AuthorizeAttribute`). ASP.NET MVC does not provide CSRF protection unless it is explicitly added.

**Impact.** An attacker-controlled page can forge authenticated requests against any POST endpoint using the victim's cookies. Combined with F-05 (no SameSite on cookies), this is fully exploitable: an admin visiting a malicious page could be made to approve offers, trigger payouts (`OffersController.PaidAsync`), create/update/delete inventory, or edit reference data; a customer could have orders cancelled or cart/wishlist modified.

**Remediation.**
- Add `@Html.AntiForgeryToken()` to every form and `[ValidateAntiForgeryToken]` to every state-changing action, or register a global `AutoValidateAntiforgeryTokenAttribute` in `FilterConfig.RegisterGlobalFilters`.
- Set `SameSite=Lax` (or `Strict`) on auth cookies as defense in depth (see F-05).

---

### F-04 — Hardcoded default administrator credentials
- **Severity:** High
- **OWASP:** A07:2021 Identification and Authentication Failures
- **NIST:** SP 800-53 IA-5; SP 800-63B
- **Files:**
  - `app/Bookstore.Cdk/CoreStack.cs` (`CreateDefaultAdminUser`, `TemporaryPassword = "P@ssword1"`, lines ~140-160)
  - `README.md` ("Amazon Cognito first run" section)

**Description.** The CDK provisions a Cognito admin user `admin` with a fixed temporary password `P@ssword1`, and the README publishes `Admin` / `P@ssword1`. The password is weak, well known (documented publicly in the upstream sample), and committed to source control.

**Impact.** If the deployed stack does not force an immediate password rotation before exposure, the admin account is trivially compromised. Even as a "temporary" password, Cognito's `MessageAction = SUPPRESS` means no notification is sent, increasing the chance the default persists.

**Remediation.**
- Generate a random temporary password at deploy time (e.g., Secrets Manager generated secret) and never commit it. Require a forced change on first sign-in.
- Remove the literal password from `README.md`, or clearly scope it to throwaway sandbox use with a loud warning.
- Enforce MFA for administrator accounts.

---

### F-05 — Authentication/session cookies lack Secure, HttpOnly, and SameSite
- **Severity:** High
- **OWASP:** A05:2021 Security Misconfiguration (also A07)
- **NIST:** SP 800-53 SC-8, SC-23
- **Files:**
  - `app/Bookstore.Web/Helpers/LocalAuthenticationMiddleware.cs` (lines ~30-34)
  - `app/Bookstore.Web/Controllers/AuthenticationController.cs` (lines ~24-45)
  - `app/Bookstore.Web/App_Start/AuthenticationSetup.cs` (`new CookieAuthenticationOptions()`, line ~39)
  - `app/Bookstore.Web/Web.config` (no `<httpCookies>` element)

**Description.** The `LocalAuthentication` cookie is created with no flags:

```csharp
var userCookie = new HttpCookie("LocalAuthentication") { Expires = DateTime.Now.AddDays(1) };
```

`HttpOnly`, `Secure`, and `SameSite` are all unset. The Cognito path uses `new CookieAuthenticationOptions()` with defaults and does not set `CookieSecure` / `CookieSameSite`. `Web.config` has no `<system.web><httpCookies requireSSL="true" httpOnlyCookies="true" .../>`.

**Impact.** Cookies may be transmitted over HTTP (interceptable), are readable by client script (XSS token theft), and are sent on cross-site requests (enables F-03 CSRF). The `LocalAuthentication` cookie is also a pure presence marker with no integrity protection, so it can be forged to obtain the admin principal (compounds F-01).

**Remediation.**
- Set `HttpOnly = true`, `Secure = true`, and `SameSite = Lax/Strict` on all auth cookies.
- Add `<httpCookies httpOnlyCookies="true" requireSSL="true" sameSite="Lax" />` to `Web.config`.
- For Cognito, configure `CookieSecure = CookieSecureOption.Always` and set `CookieSameSite` on `CookieAuthenticationOptions`.
- Replace the presence-only local cookie with a signed/encrypted token if local mode is retained for dev.

---

### F-06 — `debug="true"` and missing `customErrors` leak internal details
- **Severity:** High
- **OWASP:** A05:2021 Security Misconfiguration
- **NIST:** SP 800-53 SI-11, CM-6
- **Files:**
  - `app/Bookstore.Web/Web.config` (`<compilation debug="true" targetFramework="4.8" />`, line ~44; no `<customErrors>` element)
  - `app/Bookstore.Web/Web.Release.config` (only removes the `debug` attribute; does not add `<customErrors>`)

**Description.** `Web.config` compiles with `debug="true"` and defines no `<customErrors>` section, so ASP.NET defaults to `RemoteOnly`/`Off` behavior that renders the full Yellow Screen of Death with stack traces, source snippets, and framework versions on unhandled errors. The release transform removes `debug` but still never sets `<customErrors mode="On">`. `Global.asax.cs` logs the exception but does not render a safe error page.

**Impact.** Running with `debug="true"` disables request timeouts and batch optimizations and exposes detailed diagnostics; without `customErrors`, exception detail (stack traces, SQL, file paths, connection fragments) is returned to clients, aiding reconnaissance and exploitation (A05 / information disclosure).

**Remediation.**
- Set `debug="false"` for all non-developer builds (the project ships `debug="true"` as the committed default).
- Add `<customErrors mode="On" defaultRedirect="~/Error" />` (or `RemoteOnly` with a generic page) and a safe error controller/view.
- Verify the release transform actually produces a hardened config in CI.

---

### F-07 — Overly permissive IAM policies in CDK
- **Severity:** High
- **OWASP:** A01:2021 Broken Access Control (least privilege) / A05 Security Misconfiguration
- **NIST:** SP 800-53 AC-6 (Least Privilege)
- **Files:** `app/Bookstore.Cdk/EcsStack.cs` (`CreateEcsPermissions`, lines ~132-175)

**Description.** The ECS task role is granted wildcard resources:

```csharp
Actions = new[] { "rekognition:DetectModerationLabels" },
Resources = new[] { "*" }
...
Actions = new[] { "logs:...": }, Resources = new[] { "arn:aws:logs:*:*:log-group:*:log-stream:*" }
```

Rekognition is scoped to all resources, and CloudWatch Logs permissions span all log groups across the account. Additionally, the README instructs deployers to use an IAM user with `AdministratorAccess`.

**Impact.** A compromise of the Fargate task (for example via F-01/F-09) yields broader AWS access than the workload needs: writing to arbitrary log groups and calling Rekognition account-wide. The `AdministratorAccess` deployment guidance violates least privilege for the human/CI principal too.

**Remediation.**
- Scope `logs:*` to the application's own log group ARN (`Constants.AppName`), and prefer letting CDK create and grant the specific log group.
- Scope Rekognition to the minimum required (Rekognition's `DetectModerationLabels` has limited resource-level support; constrain via conditions where possible and isolate the task role).
- Replace `AdministratorAccess` deploy guidance with a scoped deployment policy.

---

## Medium findings

### F-08 — Secrets handled and stored in plaintext
- **Severity:** Medium
- **OWASP:** A02:2021 Cryptographic Failures
- **NIST:** SP 800-53 SC-28, SC-12, IA-5
- **Files:**
  - `app/Bookstore.Cdk/DatabaseStack.cs` (`CreateConnectionString`, builds `...Password={password};` into an SSM `StringParameter`, lines ~70-85)
  - `app/Bookstore.Web/Web.config` (`<connectionStrings>` in cleartext, line ~11)
  - `app/Bookstore.Web/App_Start/ConfigurationSetup.cs` (reads parameters, no decryption/SecureString handling)

**Description.** The database connection string, including the RDS master password, is written into a standard SSM `StringParameter` (not a `SecureString`), rendering the password readable in plaintext to anyone with `ssm:GetParameter` on that path (which the task role has). The local `Web.config` connection string is also plaintext (acceptable for LocalDB with integrated security, but the pattern of plaintext secrets carries into AWS mode). `ConfigurationSetup` fetches these as plain strings.

**Impact.** Database credentials are exposed to any principal with read access to the parameter path, and are present in CloudFormation/SSM history. Plaintext at rest violates cryptographic-storage expectations for secrets.

**Remediation.**
- Keep the RDS secret in Secrets Manager (CDK already has `Database.Secret`) and have the app read it directly at runtime instead of materializing the password into an SSM `StringParameter`.
- If SSM must be used, use `SecureString` with a CMK and grant decrypt narrowly.
- Encrypt `Web.config` sections (`aspnet_regiis -pe`) where applicable, and never commit real secrets.

### F-09 — Unrestricted file upload: validation is client-trusted and bypassable
- **Severity:** Medium
- **OWASP:** A04:2021 Insecure Design / A05 Security Misconfiguration
- **NIST:** SP 800-53 SI-10
- **Files:**
  - `app/Bookstore.Web/Helpers/ImageTypesAttribute.cs` (extension-only check on `file.FileName`)
  - `app/Bookstore.Web/Helpers/MaxFileSizeAttribute.cs`
  - `app/Bookstore.Web/Areas/Admin/Controllers/InventoryController.cs` (Create/Update accept `CoverImage`)
  - `app/Bookstore.Data/FileServices/LocalFileService.cs` and `S3FileService.cs`

**Description.** `ImageTypesAttribute` validates only the file extension (`Path.GetExtension(file.FileName)`), which is attacker-controlled and does not reflect real content. There is no server-side content-type/magic-byte verification. `LocalFileService` writes the uploaded bytes under the web root (`/Content/images/coverimages/`) using the original extension. The Rekognition "safety" check (`RekognitionImageValidationService`) is a moderation filter, not a file-type or malware check, and is skipped entirely in local mode.

**Impact.** An attacker can upload a file with an image extension but arbitrary content. Because files land under the web root with the original extension, mislabeled or oversized content, polyglot files, or content that later gets served with an unexpected type can lead to stored content issues (and, in misconfigured servers, script execution). Weak validation also enables denial-of-service via large/odd files. The admin upload path is reachable by anyone under F-01.

**Remediation.**
- Validate real content (magic bytes / decode as image via `System.Drawing`/`ImageSharp`) server-side, not just the extension.
- Store uploads outside the web root or in S3 only, serve via CloudFront with a fixed `Content-Type` and `Content-Disposition`, and never execute the directory.
- Generate server-side filenames (already done) and enforce an allowlist of real image types plus a strict size cap.
- Run content moderation/AV regardless of local vs aws mode, or clearly mark local mode as non-production.

### F-10 — Cognito user pool allows self sign-up and uses a weak password policy
- **Severity:** Medium
- **OWASP:** A07:2021 Identification and Authentication Failures
- **NIST:** SP 800-63B
- **Files:** `app/Bookstore.Cdk/CoreStack.cs` (`CreateCognitoUserPool`, `SelfSignUpEnabled = true`; `CreateUserPoolClient` enables `UserPassword` auth flow and `COGNITO_ADMIN` scope)

**Description.** The user pool sets `SelfSignUpEnabled = true`, no explicit password policy or MFA is configured, and the app clients enable the `UserPassword` auth flow (`ADMIN_USER_PASSWORD`-style direct auth) and request the broad `aws.cognito.signin.user.admin` (`COGNITO_ADMIN`) scope.

**Impact.** Anyone can register accounts. The absent explicit password policy relies on Cognito defaults with no MFA, and the `COGNITO_ADMIN` scope grants the token holder self-service identity operations that are broader than a storefront needs.

**Remediation.**
- Disable self sign-up for admin-capable pools, or separate customer and admin pools.
- Define an explicit strong password policy and require MFA for the Administrators group.
- Drop the `COGNITO_ADMIN` scope unless specifically required; prefer the authorization-code flow without `UserPassword` for a web app.

### F-11 — Missing security response headers
- **Severity:** Medium
- **OWASP:** A05:2021 Security Misconfiguration
- **NIST:** SP 800-53 SC-8, SC-18
- **Files:** `app/Bookstore.Web/Web.config` (no `<system.webServer><httpProtocol><customHeaders>`), no header middleware in `Startup.cs`

**Description.** The application sets none of `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`/frame-ancestors, or `Referrer-Policy`. There is no HTTPS redirect/HSTS enforcement in the app.

**Impact.** Missing HSTS permits SSL-strip/downgrade; missing CSP and `X-Content-Type-Options` increase XSS and MIME-sniffing risk; missing frame protections allow clickjacking.

**Remediation.**
- Add response headers via `<customHeaders>` or OWIN middleware: `Strict-Transport-Security`, a restrictive `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- Enforce HTTPS and `RequireHttps` on controllers/globally.

### F-12 — S3 data bucket configured for destruction
- **Severity:** Medium
- **OWASP:** A05:2021 Security Misconfiguration
- **NIST:** SP 800-53 CP-9, SC-28
- **Files:** `app/Bookstore.Cdk/CoreStack.cs` (`CreateImageS3Bucket`: `AutoDeleteObjects = true`, `RemovalPolicy = RemovalPolicy.DESTROY`)

**Description.** The cover-image bucket is set to auto-delete all objects and be destroyed when the stack is torn down. The code also does not set `BlockPublicAccess`, server-side encryption, or SSL-only bucket policy explicitly (access is fronted by CloudFront OAI, which is good, but the bucket's own hardening is implicit).

**Impact.** Accidental or malicious stack deletion causes irreversible data loss. Lack of explicit `BlockPublicAccess`/encryption/`aws:SecureTransport` policy leaves hardening to defaults.

**Remediation.**
- For non-sandbox use, set `RemovalPolicy.RETAIN` and disable `AutoDeleteObjects`.
- Set `BlockPublicAccess = BLOCK_ALL`, enable SSE (S3-managed or KMS), and add an `aws:SecureTransport=false` deny policy.

### F-13 — Open redirect in authentication login flow
- **Severity:** Medium
- **OWASP:** A01:2021 Broken Access Control (Unvalidated Redirect)
- **NIST:** SP 800-53 SI-10
- **Files:** `app/Bookstore.Web/Controllers/AuthenticationController.cs` (`Login(string redirectUri)` → `return Redirect(redirectUri);`)

**Description.** `Login` redirects to a caller-supplied `redirectUri` without validating that it is a local/allowlisted URL.

```csharp
public ActionResult Login(string redirectUri = null)
{
    if (string.IsNullOrWhiteSpace(redirectUri)) return RedirectToAction("Index", "Home");
    return Redirect(redirectUri);   // unvalidated
}
```

**Impact.** `/Authentication/Login?redirectUri=https://evil.example` sends users to an attacker site, enabling phishing that abuses the application's trusted domain. In local mode (F-01), this is combined with the login that establishes an authenticated session.

**Remediation.** Use `Url.IsLocalUrl(redirectUri)` and reject or default to home for non-local targets; prefer `RedirectToLocal` helper patterns.

---

## Low findings

### F-14 — RDS hardening gaps (backups disabled, encryption not enforced)
- **Severity:** Low
- **OWASP:** A05 Security Misconfiguration / A04 Insecure Design
- **NIST:** SP 800-53 CP-9, SC-28, SC-8
- **Files:** `app/Bookstore.Cdk/DatabaseStack.cs`

**Description.** `BackupRetention = Duration.Seconds(0)` disables automated backups. `StorageEncrypted` is not set, and TLS to the database is not explicitly enforced. The DB is correctly placed in a private subnet with a dedicated security group (good), and connectivity is restricted to the app via `AllowTo(..., Port.Tcp(1433))` in `EcsStack`.

**Impact.** No point-in-time recovery; storage-at-rest and in-transit encryption left to defaults.

**Remediation.** Enable `StorageEncrypted = true` with a CMK, set a non-zero `BackupRetention`, and enforce TLS (`rds.force_ssl`) for non-sandbox deployments.

### F-15 — Verbose error logging may capture sensitive data
- **Severity:** Low
- **OWASP:** A09:2021 Security Logging and Monitoring Failures
- **NIST:** SP 800-53 AU-9, SI-11
- **Files:** `app/Bookstore.Web/Global.asax.cs` (`logger.Error(ex)`), `app/Bookstore.Web/App_Start/LoggingSetup.cs`

**Description.** Full exceptions are logged at the global handler. Exceptions can carry sensitive values (query parameters, connection details). Logs are shipped to CloudWatch; ensure they are access-controlled and scrubbed. There is otherwise little evidence of audit logging for sensitive admin actions (offer approval, payouts).

**Impact.** Potential sensitive-data leakage into logs; limited audit trail for privileged actions.

**Remediation.** Scrub/avoid logging sensitive fields, add structured audit logging for admin/privileged operations, and restrict log access.

### F-16 — Dependency and patch management
- **Severity:** Low
- **OWASP:** A06:2021 Vulnerable and Outdated Components
- **NIST:** SP 800-53 SA-22, RA-5
- **Files:** `app/Bookstore.Web/packages.config`

**Description.** Dependencies are pinned (good) and most are recent (Newtonsoft.Json 13.0.3, jQuery 3.7.1, EntityFramework 6.5.1, AWS SDK current). No critical known-vulnerable package was identified by inspection. However, the whole stack is on .NET Framework 4.8 (maintenance mode), and there is no evidence of an automated software-composition-analysis (SCA) gate to catch future CVEs.

**Impact.** Without an SCA/patch process, newly disclosed vulnerabilities in these libraries would go undetected.

**Remediation.** Add SCA (e.g., `dotnet list package --vulnerable` equivalent / Dependabot / OWASP Dependency-Check) to CI, and plan migration off .NET Framework where feasible.

---

## Positive observations

- **No SQL injection found.** Data access uses Entity Framework 6 with LINQ (`BookRepository`, etc.); user input flows through parameterized `.Where(...)` expressions, not string concatenation. No `Html.Raw`, `Request[...]`, or raw SQL was found.
- **No obvious XSS sinks in views.** No `@Html.Raw` usages were found; Razor's default output encoding applies.
- **Admin area is attribute-protected** via `[Authorize(Roles = "Administrators")]` on `AdminAreaControllerBase`, and a global `AuthorizeAttribute` is registered in `FilterConfig` (authentication is required by default). The weakness is in how the role is assigned (F-01), not the attribute usage.
- **S3 is fronted by CloudFront with Origin Access Identity**, and the DB sits in a private subnet with a scoped security group.
- **Server-side generated filenames** for uploads (`Path.GetRandomFileName()`) mitigate path traversal in the storage layer.

---

## Prioritized remediation roadmap

1. **F-01, F-02** (Critical): Remove implicit admin grant / gate local auth out of deployments; add ownership checks to all object reads.
2. **F-03, F-05** (High): Add anti-forgery tokens globally and harden cookie flags (Secure/HttpOnly/SameSite).
3. **F-06, F-07** (High): Ship `debug="false"` + `customErrors`; scope IAM to least privilege.
4. **F-04** (High): Remove hardcoded default admin password; force rotation + MFA.
5. **F-08 – F-13** (Medium): Secrets to Secrets Manager, real file-content validation, Cognito policy hardening, security headers, bucket retention/encryption, open-redirect fix.
6. **F-14 – F-16** (Low): RDS backups/encryption, log scrubbing + audit logging, SCA in CI.

---

*Prepared as a static source review mapped to OWASP Top 10 (2021) and NIST SP 800-53 / 800-63B. Dynamic testing (DAST), live AWS posture checks, and a dependency CVE scan are recommended as follow-ups to confirm exploitability and catch runtime-only issues.*
