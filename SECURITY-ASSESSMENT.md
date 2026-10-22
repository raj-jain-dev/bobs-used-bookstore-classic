# Security Assessment — Bob's Used Books Classic

**Target:** `bobs-used-bookstore-classic` (ASP.NET MVC 5, .NET Framework 4.8, C#)
**Assessment type:** Manual / static source-code security review
**Standards:** OWASP Top 10 (2021), NIST SP 800-53 Rev. 5, NIST SSDF (SP 800-218)
**Branch reviewed:** `main`

---

## 1. Executive Summary

Bob's Used Books Classic is a backport of an AWS sample bookstore built on ASP.NET MVC 5 / .NET Framework 4.8. The application supports a pluggable service model (`local` vs `aws`) for authentication, database, file storage, image validation, and logging. **All toggles default to `local` in `Web.config`.**

The most serious issues stem from the `local` defaults and from web-layer hardening that was never applied. In particular, the default local authentication provider grants **full administrator access to any anonymous visitor**, there is **no CSRF protection anywhere** in the application, and multiple data-access paths key off a **client-controlled cookie or an unverified object id** (IDOR). The AWS deployment path also ships **hardcoded default credentials** and an over-broad IAM policy.

Because the sample is explicitly designed to run disconnected from AWS by default, the `local` findings are not theoretical — they describe the behavior of the application as shipped and as a developer would first run it.

### Findings by severity

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High     | 5 |
| Medium   | 6 |
| Low      | 3 |
| Info     | 2 |
| **Total** | **18** |

### Finding index

| ID | Title | Severity |
|----|-------|----------|
| F-01 | Local auth provider grants unauthenticated administrator access | Critical |
| F-02 | Hardcoded / documented default credentials (`P@ssword1`) + Cognito self-sign-up | Critical |
| F-03 | No CSRF protection on any state-changing action | High |
| F-04 | Shopping-cart correlation-id IDOR (client-controlled cookie) | High |
| F-05 | Missing ownership checks on order lookups (IDOR) | High |
| F-06 | Open redirect in `AuthenticationController.Login` | High |
| F-07 | Over-broad IAM (`ANY_RESOURCE`) and destructive removal policies in CDK | High |
| F-08 | Security misconfiguration: `debug="true"`, no `customErrors`, no secure cookie flags | Medium |
| F-09 | Missing security response headers (CSP, X-Frame-Options, HSTS, etc.) | Medium |
| F-10 | Weak file-upload validation (extension-only, no content/magic-byte check) | Medium |
| F-11 | Plaintext DB connection string stored in SSM `StringParameter` | Medium |
| F-12 | State-changing operations exposed over HTTP GET | Medium |
| F-13 | Insufficient security logging, monitoring, and audit trail | Medium |
| F-14 | Unpinned / unverified supply-chain artifact download in Dockerfile | Low |
| F-15 | Host-header influence on Cognito logout/return URLs | Low |
| F-16 | Outdated / legacy client-side components (jQuery, Modernizr, Bootstrap) | Low |
| F-17 | Injection (SQL / XSS) surface review — low residual risk | Info |
| F-18 | SSRF and insecure-deserialization surface review — no sink found | Info |

---

## 2. Scope, Methodology, and Limitations

### Scope
The entire repository was reviewed, with emphasis on:
- Web layer: `app/Bookstore.Web` (controllers, `App_Start`, helpers, views, `Web.config`).
- Data/services layer: `app/Bookstore.Data` (EF6 repositories, file services, image validation/resize).
- Infrastructure-as-code: `app/Bookstore.Cdk` (`CoreStack`, `DatabaseStack`, `EcsStack`, `NetworkStack`).
- Build / ops: `Dockerfile`, `LogMonitorConfig.json`, `README.md`, dependency manifests.

### Methodology
A manual static review was performed by reading the source directly and corroborating cross-cutting claims with repository-wide pattern searches. Specific searches run and their results:

- **Raw SQL:** search for `SqlQuery|ExecuteSqlCommand|ExecuteSqlRaw|FromSql` across `app/**/*.cs` → **no matches** (data access is EF6 LINQ).
- **CSRF:** search for `AntiForgery|ValidateAntiForgeryToken` across `app/**` → **no matches**; `HttpPost` enumeration found **19 POST actions** plus several state-changing GET actions.
- **XSS sinks:** search for `Html.Raw|@Html.Raw|MvcHtmlString|HtmlString` across all `.cshtml` views → **no matches** (Razor auto-encoding in effect).
- **Insecure deserialization:** search for `BinaryFormatter|JavaScriptSerializer|XmlSerializer|TypeNameHandling|LosFormatter|NetDataContractSerializer` across `app/**/*.cs` → **no matches**.
- **Security headers:** inspection of `Web.config` and `Views/Web.config` → no `<httpCookies>`, `<customErrors>`, or `<customHeaders>` hardening present.

### Limitations
- **No build or runtime testing.** The sandbox is Linux with no .NET Framework 4.8 toolchain, so the application was neither compiled nor executed. Findings are source-based; dynamic exploitation was not attempted.
- **AWS automated scanner unavailable.** The automated AWS security scanner requires AWS credentials / IAM role and could not be run; cloud posture findings are derived from reading the CDK source only.
- **No dependency lockfile resolution.** Package versions were read from `packages.config` and `.csproj` manifests. Where a specific version could not be confirmed vulnerable against a published advisory, the report describes the risk class rather than asserting a CVE.
- Line numbers reflect the source at review time on branch `main`.

---

## 3. Findings

Each finding uses the template: **Severity · OWASP 2021 · NIST mapping · Location · Impact · Evidence · Remediation**.

---

### F-01 — Local authentication provider grants unauthenticated administrator access

- **Severity:** Critical
- **OWASP 2021:** A07 Identification and Authentication Failures (also A01 Broken Access Control)
- **NIST:** SP 800-53 Rev5 **IA-2** (Identification and Authentication), **AC-3** (Access Enforcement), **AC-6** (Least Privilege); SSDF **PW.1 / PW.2** (secure design & review)
- **Location:** `app/Bookstore.Web/Helpers/LocalAuthenticationMiddleware.cs:23`, `:29`, `:35`, `:57`; enabled by default via `app/Bookstore.Web/Web.config:20` (`Services/Authentication` = `local`) and `app/Bookstore.Web/App_Start/FilterConfig.cs:10`.

**Impact.** When `Services/Authentication` is `local` (the shipped default), the OWIN middleware authenticates **every** request that either targets `/Authentication/Login` or merely carries a `LocalAuthentication` cookie — with **no username/password check whatsoever** — and assigns the role `Administrators`. Combined with the global `AuthorizeAttribute` and the admin area's `[Authorize(Roles = "Administrators")]`, any anonymous visitor obtains full administrative access (inventory management, reference data, offers, orders). The cookie is created with no value, no signature, no `HttpOnly`, and no `Secure` flag, so its mere presence is sufficient to authenticate.

**Evidence.**
```csharp
// LocalAuthenticationMiddleware.cs
if (context.Request.Path.Value.StartsWith("/Authentication/Login"))      // :23
{
    CreateClaimsPrincipal(context);
    ...
    var userCookie = new HttpCookie("LocalAuthentication") { Expires = DateTime.Now.AddDays(1) }; // :29
    HttpContext.Current.Response.Cookies.Add(userCookie);
}
else if (HttpContext.Current.Request.Cookies["LocalAuthentication"] != null)  // :35
{
    CreateClaimsPrincipal(context);
    ...
}
...
identity.AddClaim(new Claim(ClaimTypes.Role, "Administrators"));           // :57
```

**Remediation.**
- Treat the `local` provider strictly as a developer convenience and never allow it in any deployed environment. Fail fast at startup if `Services/Authentication == "local"` while `Environment != "Development"`.
- Require real credential validation even locally (validate a username/password against a local user store before issuing a principal).
- Do **not** assign the `Administrators` role unconditionally; grant only a minimal non-admin role by default.
- Issue the auth cookie through a signed, encrypted mechanism (e.g. `UseCookieAuthentication` with a data protector) and set `HttpOnly = true`, `Secure = true`, `SameSite = Lax/Strict`.

```csharp
// Example startup guard (Global.asax.cs Application_Start)
var authMode = BookstoreConfiguration.GetSetting("Services/Authentication");
var env = BookstoreConfiguration.GetSetting("Environment");
if (authMode == "local" && !string.Equals(env, "Development", StringComparison.OrdinalIgnoreCase))
{
    throw new ConfigurationErrorsException(
        "Local authentication must not be enabled outside Development.");
}
```

---

### F-02 — Hardcoded / documented default credentials and Cognito self-sign-up

- **Severity:** Critical
- **OWASP 2021:** A07 Identification and Authentication Failures (also A02 Cryptographic Failures for secret exposure)
- **NIST:** SP 800-53 Rev5 **IA-5** (Authenticator Management), **AC-6** (Least Privilege), **CM-6** (Configuration Settings); SSDF **PW.1**, **PO.5**
- **Location:** `app/Bookstore.Cdk/CoreStack.cs:161` (`TemporaryPassword "P@ssword1"`), `:124` (`SelfSignUpEnabled = true`), `:209` (`UserPassword = true`); `README.md:43-44` (documents `Admin` / `P@ssword1`).

**Impact.** The AWS deployment seeds a default admin user with the static password `P@ssword1`, and the same credentials are published in the README. The Cognito user pool enables self-sign-up (`SelfSignUpEnabled = true`) and contains an `Administrators` group, with no explicit password policy or MFA configured (Cognito defaults apply). `UserPassword` auth flow is enabled, which permits direct username/password authentication (brute-force exposure) rather than SRP. Together these create a predictable, publicly-documented path to privileged access and open the door to credential-stuffing and self-registration abuse.

**Evidence.**
```csharp
// CoreStack.cs
SelfSignUpEnabled = true,                                   // :124
...
{ "TemporaryPassword", "P@ssword1" },                        // :161
...
AuthFlows = new AuthFlow { UserPassword = true }             // :209
```
```markdown
<!-- README.md:43-44 -->
* Username: **Admin**
* Password: **P@ssword1**
```

**Remediation.**
- Remove the hardcoded password. Generate a random temporary password (e.g. via AWS Secrets Manager) and force a change on first sign-in.
- Configure an explicit Cognito `PasswordPolicy` (length ≥ 12, complexity) and require MFA for the `Administrators` group.
- Reconsider `SelfSignUpEnabled`; if self-sign-up is required, ensure newly registered users cannot escalate to `Administrators` and verify email ownership before activation.
- Prefer SRP (`UserSrp`) over `UserPassword` auth flow.
- Replace the plaintext credentials in `README.md` with instructions to retrieve a generated secret.

---

### F-03 — No CSRF protection on any state-changing action

- **Severity:** High
- **OWASP 2021:** A01 Broken Access Control (CSRF; CWE-352)
- **NIST:** SP 800-53 Rev5 **SC-23** (Session Authenticity), **SI-10** (Information Input Validation); SSDF **PW.5**
- **Location:** repository-wide. All `[HttpPost]` actions lack `[ValidateAntiForgeryToken]` and no view emits `@Html.AntiForgeryToken()` (0 matches). Affected POST actions include:
  - `app/Bookstore.Web/Controllers/CheckoutController.cs:34` (`Index`)
  - `app/Bookstore.Web/Controllers/ResaleController.cs:35` (`Create`)
  - `app/Bookstore.Web/Controllers/AddressController.cs:35,54,66` (`Create`/`Update`/`Delete`)
  - `app/Bookstore.Web/Controllers/ShoppingCartController.cs:29` (`Delete`)
  - `app/Bookstore.Web/Controllers/WishlistController.cs:29,41,53`
  - `app/Bookstore.Web/Controllers/OrdersController.cs:32` (`Delete`)
  - `app/Bookstore.Web/Areas/Admin/Controllers/InventoryController.cs:42,75`
  - `app/Bookstore.Web/Areas/Admin/Controllers/OffersController.cs:28,34,40,46`
  - `app/Bookstore.Web/Areas/Admin/Controllers/ReferenceDataController.cs:33,50`
  - `app/Bookstore.Web/Areas/Admin/Controllers/OrdersController.cs:31`

**Impact.** With cookie-based authentication and no anti-forgery token, an attacker can craft a page that, when visited by an authenticated user (including an admin), silently submits requests to change inventory, approve/reject offers, cancel orders, mutate addresses, or empty carts. The admin POST actions make this a privilege-sensitive issue.

**Evidence.**
```csharp
[HttpPost]                                                   // InventoryController.cs:42
public async Task<ActionResult> Create(InventoryCreateUpdateViewModel model)
```
(No `[ValidateAntiForgeryToken]` present on any POST action; search for `AntiForgery` returned no matches.)

**Remediation.**
- Add `@Html.AntiForgeryToken()` inside every form that performs a state change.
- Decorate each state-changing POST action with `[ValidateAntiForgeryToken]`, or register a global anti-forgery filter.

```csharp
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<ActionResult> Create(InventoryCreateUpdateViewModel model) { ... }
```
```cshtml
@using (Html.BeginForm())
{
    @Html.AntiForgeryToken()
    ...
}
```

---

### F-04 — Shopping-cart correlation-id IDOR via client-controlled cookie

- **Severity:** High
- **OWASP 2021:** A01 Broken Access Control (IDOR) / A04 Insecure Design
- **NIST:** SP 800-53 Rev5 **AC-3** (Access Enforcement), **AC-4** (Information Flow), **SC-8** (Transmission Confidentiality for the cookie); SSDF **PW.1**
- **Location:** `app/Bookstore.Web/Helpers/HttpContextExtensions.cs:13,21,31`; consumed by `ShoppingCartController.cs:24,33`, `WishlistController.cs:24,33,46,58`, `SearchController.cs:38,47`, `CheckoutController.cs:27,39`.

**Impact.** The cart/wishlist key is read from a client-supplied `ShoppingCartId` cookie that is written back with no `HttpOnly` and no `Secure` flag. Any client can set or substitute an arbitrary id (and for authenticated users the id is the user's `sub`, which may appear elsewhere), allowing an attacker to read or modify another session's cart/wishlist, or — at checkout — place an order against a victim's cart contents. The repository layer trusts this id as the sole authorization key.

**Evidence.**
```csharp
// HttpContextExtensions.cs
var CookieKey = "ShoppingCartId";                            // :13
HttpCookie cookie = context.Request.Cookies[CookieKey];      // :21
...
context.Response.Cookies.Add(new HttpCookie(CookieKey, shoppingCartClientId)); // :31  (no HttpOnly/Secure)
```

**Remediation.**
- For authenticated users, derive the cart key server-side from the authenticated identity; never accept it from a client cookie.
- For anonymous carts, store the correlation id in a signed/encrypted, `HttpOnly`, `Secure`, `SameSite` cookie so it cannot be forged or swapped, and bind the cart to the session.
- Enforce an ownership check in the service/repository layer before returning or mutating a cart.

```csharp
context.Response.Cookies.Add(new HttpCookie(CookieKey, shoppingCartClientId)
{
    HttpOnly = true,
    Secure = true,
    SameSite = SameSiteMode.Lax
});
// Prefer a signed value, e.g. via MachineKey.Protect / a data protector.
```

---

### F-05 — Missing ownership checks on order lookups (IDOR)

- **Severity:** High
- **OWASP 2021:** A01 Broken Access Control (IDOR)
- **NIST:** SP 800-53 Rev5 **AC-3** (Access Enforcement), **AC-6** (Least Privilege); SSDF **PW.1**
- **Location:** `app/Bookstore.Web/Controllers/CheckoutController.cs:46-50` (`Finished(int orderId)`), `app/Bookstore.Web/Controllers/OrdersController.cs:25-29` (`Details(int id)`).

**Impact.** `Checkout.Finished` and `Orders.Details` fetch an order by its id directly (`GetOrderAsync(orderId)`) and render it without verifying that the order belongs to the current user (`User.GetSub()`). Order ids are sequential integers, so a user can enumerate `?orderId=N` / `/Orders/Details/N` and read other customers' orders (PII, address, items). Note that `Orders.Delete` and `Orders.Index` *do* scope by `User.GetSub()`, which highlights the inconsistency.

**Evidence.**
```csharp
// CheckoutController.cs
public async Task<ActionResult> Finished(int orderId)        // :46
{
    var order = await orderService.GetOrderAsync(orderId);   // :48  no owner check
    return View(new CheckoutFinishedViewModel(order));
}
```
```csharp
// OrdersController.cs
public async Task<ActionResult> Details(int id)              // :25
{
    var order = await orderService.GetOrderAsync(id);        // :27  no owner check
    ...
}
```

**Remediation.**
- Pass the authenticated user's id into the lookup and filter server-side, returning 404/403 when the order is not owned by the caller.

```csharp
var order = await orderService.GetOrderAsync(id);
if (order == null || order.CustomerId != User.GetSub())
{
    return new HttpStatusCodeResult(HttpStatusCode.NotFound);
}
```

---

### F-06 — Open redirect in `AuthenticationController.Login`

- **Severity:** High
- **OWASP 2021:** A01 Broken Access Control (Unvalidated Redirect, CWE-601)
- **NIST:** SP 800-53 Rev5 **SI-10** (Information Input Validation), **AC-4** (Information Flow); SSDF **PW.5**
- **Location:** `app/Bookstore.Web/Controllers/AuthenticationController.cs:10-15`.

**Impact.** `Login` redirects to any attacker-supplied absolute URL via `Redirect(redirectUri)` with no allow-list or same-origin check. This enables phishing (crafting `/Authentication/Login?redirectUri=https://evil.example`) and can be chained with the local-auth behavior to lend legitimacy to a malicious destination.

**Evidence.**
```csharp
public ActionResult Login(string redirectUri = null)         // :10
{
    if(string.IsNullOrWhiteSpace(redirectUri)) return RedirectToAction("Index", "Home");
    return Redirect(redirectUri);                            // :14
}
```

**Remediation.**
- Only redirect to local URLs, or validate against an explicit allow-list of hosts.

```csharp
if (string.IsNullOrWhiteSpace(redirectUri) || !Url.IsLocalUrl(redirectUri))
{
    return RedirectToAction("Index", "Home");
}
return Redirect(redirectUri);
```

---

### F-07 — Over-broad IAM and destructive removal policies in CDK

- **Severity:** High
- **OWASP 2021:** A05 Security Misconfiguration (also A04 Insecure Design)
- **NIST:** SP 800-53 Rev5 **AC-6** (Least Privilege), **CM-6** (Configuration Settings), **CP-9/SC-28** (data durability/protection); SSDF **PO.5**, **PW.9**
- **Location:** `app/Bookstore.Cdk/CoreStack.cs:176` (`AwsCustomResourcePolicy.ANY_RESOURCE`), `:49` and `:132` (`RemovalPolicy.DESTROY`); `app/Bookstore.Cdk/EcsStack.cs` (`rekognition:DetectModerationLabels` on `Resources = "*"`, logs on broad ARNs).

**Impact.** The custom resource that creates the default admin user is granted IAM permissions over `ANY_RESOURCE`, far beyond the single Cognito call it needs — a least-privilege violation that broadens blast radius if the resource is abused. `RemovalPolicy.DESTROY` with `AutoDeleteObjects = true` on the image bucket and the user pool means stack deletion destroys data irrecoverably. ECS task-role statements use `"*"` resources for Rekognition and broad log ARNs.

**Evidence.**
```csharp
// CoreStack.cs
Policy = AwsCustomResourcePolicy.FromSdkCalls(
    new SdkCallsPolicyOptions { Resources = AwsCustomResourcePolicy.ANY_RESOURCE })  // :176
...
RemovalPolicy = RemovalPolicy.DESTROY                        // :49, :132
```

**Impact note / remediation.**
- Scope the custom-resource policy to the specific Cognito user-pool ARN and action instead of `ANY_RESOURCE`.
- For anything holding real data, use `RemovalPolicy.RETAIN` (or snapshot) in non-sample deployments and disable `AutoDeleteObjects`.
- Constrain Rekognition/logs statements to specific resources where the service supports resource-level permissions.

---

### F-08 — Security misconfiguration: debug build, no custom errors, insecure cookie defaults

- **Severity:** Medium
- **OWASP 2021:** A05 Security Misconfiguration (stack-trace leakage also A09)
- **NIST:** SP 800-53 Rev5 **CM-6** (Configuration Settings), **SC-8** (Transmission Confidentiality), **SI-11** (Error Handling); SSDF **PW.9**
- **Location:** `app/Bookstore.Web/Web.config:33` (`<compilation debug="true" ...>`), absence of `<customErrors>` and `<httpCookies>` in both `Web.config` and `Views/Web.config`; `app/Bookstore.Web/Web.Release.config` only removes the `debug` attribute.

**Impact.** `debug="true"` disables request timeouts/optimizations and can leak detailed diagnostics. With no `<customErrors mode="On|RemoteOnly">`, unhandled exceptions surface the ASP.NET "yellow screen of death" with stack traces and source paths to end users (information disclosure, A05/A09). The absence of `<httpCookies httpOnlyCookies="true" requireSSL="true">` means application cookies are not forced to `HttpOnly`/`Secure`. The Release transform fixes only `debug` and leaves custom errors and cookie flags unaddressed.

**Evidence.**
```xml
<!-- Web.config -->
<compilation debug="true" targetFramework="4.8" />           <!-- :33 -->
<!-- no <customErrors>, no <httpCookies> anywhere -->
```

**Remediation.**
```xml
<system.web>
  <compilation targetFramework="4.8" />           <!-- debug removed in production -->
  <customErrors mode="RemoteOnly" defaultRedirect="~/Error" />
  <httpCookies httpOnlyCookies="true" requireSSL="true" sameSite="Lax" />
  <httpRuntime targetFramework="4.8" enableVersionHeader="false" />
</system.web>
```
Ensure the Release transform also sets `customErrors` and cookie hardening, and redirect `Application_Error` to a safe error view (see F-13).

---

### F-09 — Missing security response headers

- **Severity:** Medium
- **OWASP 2021:** A05 Security Misconfiguration
- **NIST:** SP 800-53 Rev5 **SC-8** (Transmission Confidentiality/Integrity), **SC-18** (Mobile Code / content restrictions), **CM-6**; SSDF **PW.9**
- **Location:** `app/Bookstore.Web/Web.config` (no `<system.webServer><httpProtocol><customHeaders>`), `Views/Web.config` (none).

**Impact.** No `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, or HSTS (`Strict-Transport-Security`) are emitted. This leaves the app exposed to clickjacking, MIME sniffing, weaker XSS defense-in-depth, and transport downgrade.

**Evidence.** Inspection of `Web.config` and `Views/Web.config` shows no `customHeaders` block and no `requireSSL`/HSTS configuration.

**Remediation.**
```xml
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="X-Frame-Options" value="DENY" />
      <add name="X-Content-Type-Options" value="nosniff" />
      <add name="Referrer-Policy" value="no-referrer" />
      <add name="Content-Security-Policy" value="default-src 'self'; object-src 'none'; frame-ancestors 'none'" />
      <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
```
Tune the CSP to the bundles and CDN domains actually used, then enforce.

---

### F-10 — Weak file-upload validation (extension-only, no content/magic-byte check)

- **Severity:** Medium
- **OWASP 2021:** A04 Insecure Design (also A05)
- **NIST:** SP 800-53 Rev5 **SI-10** (Information Input Validation), **SC-18**; SSDF **PW.5**
- **Location:** `app/Bookstore.Web/Helpers/ImageTypesAttribute.cs:24-26` (extension check only), `app/Bookstore.Web/Helpers/MaxFileSizeAttribute.cs` (size check), `app/Bookstore.Web/Areas/Admin/Models/Inventory/InventoryCreateUpdateViewModel.cs:82-85`; storage in `app/Bookstore.Data/FileServices/LocalFileService.cs:28-41` and `S3FileService.cs:34-52`; local validation no-op in `app/Bookstore.Data/ImageValidationServices/LocalImageValidationService.cs:10-13`.

**Impact.** Cover-image validation checks only the file **extension** and a 2 MB size cap; there is no verification of the actual content type or magic bytes, so a non-image or polyglot file renamed to `.jpg` passes validation. When `Services/ImageValidationService` is `local`, `IsSafeAsync` always returns `true`. When `aws`, Rekognition moderates *content categories* (nudity, violence, etc.) but does not validate file type or guard against decompression/decoder abuse. `ImageResizeService` loads untrusted input into ImageMagick, which has a history of decoder vulnerabilities and decompression-bomb DoS. The saved object preserves the attacker-controlled extension (`Path.GetExtension(filename)`).

**Evidence.**
```csharp
// ImageTypesAttribute.cs
var extension = Path.GetExtension(file.FileName);            // :24
return imageTypes.Contains(extension, StringComparer.OrdinalIgnoreCase);  // :26
```
```csharp
// LocalImageValidationService.cs
public async Task<bool> IsSafeAsync(Stream image)
{
    return await Task.Run(() => true);                        // :11  always "safe"
}
```

**Remediation.**
- Validate content by inspecting magic bytes / decoding the image, not just the extension; reject on mismatch.
- Re-derive and normalize the stored extension/content-type from the validated image format rather than trusting `file.FileName`.
- Constrain ImageMagick with resource limits (`MagickResourceLimits`) to mitigate decompression bombs, and keep `Magick.NET` current.
- Ensure the local image-validation service performs real checks (or make it explicit that `local` is dev-only and unsafe for production).

---

### F-11 — Plaintext DB connection string stored in SSM `StringParameter`

- **Severity:** Medium
- **OWASP 2021:** A02 Cryptographic Failures (Sensitive Data Exposure)
- **NIST:** SP 800-53 Rev5 **SC-28** (Protection of Information at Rest), **IA-5**, **SC-12/SC-13** (key/crypto); SSDF **PW.9**
- **Location:** `app/Bookstore.Cdk/DatabaseStack.cs:78-81`; related `config-scripts/Update-ConnectionString.ps1`.

**Impact.** The RDS connection string — including the database password pulled from the generated secret — is written into an SSM **`StringParameter`** (plaintext) rather than a `SecureString`. Anyone with `ssm:GetParameter` on that path (and the ECS task role has `ssm:GetParametersByPath`/`GetParameter` over `AppName/*`) can read the DB password in clear text.

**Evidence.**
```csharp
// DatabaseStack.cs
StringValue = $"Server={server};Database={database};User Id={userId};Password={password};"  // :81
// stored via StringParameter (plaintext), not a SecureString
```

**Remediation.**
- Keep the connection secret in AWS Secrets Manager (already the source) and have the app read it at runtime; avoid copying the password into SSM at all.
- If SSM must be used, store it as a `SecureString` (KMS-encrypted) and grant decrypt narrowly.
- Scope read permissions to the specific parameter ARN rather than a wildcard path.

---

### F-12 — State-changing operations exposed over HTTP GET

- **Severity:** Medium
- **OWASP 2021:** A01 Broken Access Control (unsafe method; compounds CSRF)
- **NIST:** SP 800-53 Rev5 **AC-3**, **SC-23**; SSDF **PW.5**
- **Location:** `app/Bookstore.Web/Controllers/SearchController.cs:36` (`AddItemToShoppingCart`), `:47` (`AddItemToWishlist`).

**Impact.** `AddItemToShoppingCart` and `AddItemToWishlist` mutate server state but are plain (GET-reachable) actions with no HTTP-method restriction and no anti-forgery protection. They can be triggered by any cross-site `<img>`/link, enabling drive-by cart/wishlist manipulation and amplifying the CSRF exposure in F-03.

**Evidence.**
```csharp
public async Task<ActionResult> AddItemToShoppingCart(int bookId)  // SearchController.cs:36
{
    var dto = new AddToShoppingCartDto(HttpContext.GetShoppingCartCorrelationId(), bookId, 1);
    await shoppingCartService.AddToShoppingCartAsync(dto);          // state change on GET
    ...
}
```

**Remediation.**
- Convert state-changing actions to `[HttpPost]` with `[ValidateAntiForgeryToken]` and invoke them from forms/AJAX using POST.

---

### F-13 — Insufficient security logging, monitoring, and audit trail

- **Severity:** Medium
- **OWASP 2021:** A09 Security Logging and Monitoring Failures
- **NIST:** SP 800-53 Rev5 **AU-2** (Event Logging), **AU-3** (Content of Records), **AU-6** (Review/Analysis), **SI-4** (System Monitoring), **SI-11** (Error Handling); SSDF **PW.9**, **RV.1**
- **Location:** `app/Bookstore.Web/Global.asax.cs:19-24` (`Application_Error`), `app/Bookstore.Web/App_Start/LoggingSetup.cs` (NLog config, single `*`/Info rule to AWS or Debugger target), `LogMonitorConfig.json` (EventLog `Warning` + IIS file logs).

**Impact.**
- **No security-event auditing.** There is no logging of authentication successes/failures, authorization denials, admin actions (inventory/offer/order/reference-data changes), or upload rejections. Without these, incident detection and forensics are not possible, and the IDOR/CSRF/privilege issues above would leave no trail.
- **Error handling leaks instead of logs safely.** `Application_Error` logs the exception via NLog but does **not** clear the error or redirect to a safe page, and there is no `<customErrors>` (F-08), so stack traces still reach users while only a generic error is recorded.
- **No alerting / review process.** Logging routes everything at `Info` to a single target; there is no separation of security events, no alerting, and the `local` logging target is only the debugger.
- **Sensitive-data logging risk.** `logger.Error(ex)` logs full exception objects; EF/connection or token-bearing exceptions could record connection strings or PII. There is no scrubbing/redaction policy.

**Evidence.**
```csharp
// Global.asax.cs
protected void Application_Error()                           // :19
{
    var ex = Server.GetLastError();                          // :21
    var logger = LogManager.GetCurrentClassLogger();
    logger.Error(ex);                                        // :24  no Server.ClearError / safe redirect
}
```
```csharp
// LoggingSetup.cs — single catch-all Info rule, no security channel
config.LoggingRules.Add(new LoggingRule("*", LogLevel.Info, loggingTarget));
```

**Remediation.**
- Add structured audit logging for authentication (success/failure), authorization denials, admin mutations, and upload rejections, with correlation ids and actor identity — but **never** log secrets/tokens/PII (redact).
- In `Application_Error`, log a sanitized record, call `Server.ClearError()`, and return a safe error view; pair with `<customErrors mode="RemoteOnly">`.
- Route security events to a dedicated logger/target and configure CloudWatch metric filters + alarms for anomalies (repeated auth failures, admin actions).

```csharp
protected void Application_Error()
{
    var ex = Server.GetLastError();
    LogManager.GetCurrentClassLogger().Error(ex, "Unhandled exception");
    Server.ClearError();
    Response.Clear();
    Response.Redirect("~/Error");
}
```

---

### F-14 — Unpinned / unverified supply-chain artifact download in Dockerfile

- **Severity:** Low
- **OWASP 2021:** A08 Software and Data Integrity Failures
- **NIST:** SP 800-53 Rev5 **SA-12/SR-4** (supply chain), **SI-7** (Software/Information Integrity), **CM-2**; SSDF **PO.3**, **PW.4**
- **Location:** `Dockerfile:13` (downloads `LogMonitor.exe`), `:1` and `:10` (base images pinned by floating major tag).

**Impact.** `LogMonitor.exe` is fetched from a GitHub release over HTTPS with **no checksum or signature verification**, so a compromised/retagged release would be executed as the container entrypoint. Base images are pinned only to `4.8`/`...-ltsc2019` floating tags rather than immutable digests, so builds are not reproducible and could silently pull a changed image.

**Evidence.**
```dockerfile
RUN Invoke-WebRequest -Uri "https://github.com/microsoft/windows-container-tools/releases/download/v2.0.2/LogMonitor.exe" -OutFile "LogMonitor.exe"  # :13
```

**Remediation.**
- Verify the downloaded binary against a known SHA-256 hash (fail the build on mismatch).
- Pin base images by digest (`@sha256:...`).
- Consider vendoring the tool or sourcing it from an internal, scanned artifact repository.

```powershell
$expected = "<known-sha256>"
Invoke-WebRequest -Uri $url -OutFile LogMonitor.exe
if ((Get-FileHash LogMonitor.exe -Algorithm SHA256).Hash -ne $expected) { exit 1 }
```

---

### F-15 — Host-header influence on Cognito logout / return URLs

- **Severity:** Low
- **OWASP 2021:** A01 Broken Access Control / A05 Security Misconfiguration
- **NIST:** SP 800-53 Rev5 **SI-10** (Input Validation), **SC-8**; SSDF **PW.5**
- **Location:** `app/Bookstore.Web/Controllers/AuthenticationController.cs:41` (`logout_uri` built from `Request.Url.Host`/`Scheme`/`Port`); `app/Bookstore.Web/Helpers/IOwinRequestExtensions.cs:9` (`GetReturnUrl` built from `request.Host`).

**Impact.** The logout redirect URI and the OIDC return URL are constructed from the incoming request's host/scheme. If the host header is attacker-influenced (and not constrained by a host allow-list / fixed canonical host), this can contribute to redirect/host-header manipulation during the auth flow. Cognito's registered callback/logout allow-list mitigates the OIDC leg, but the logout redirect is still shaped by request data.

**Evidence.**
```csharp
var logoutUri = $"{Request.Url.Scheme}://{Request.Url.Host}:{Request.Url.Port}/";  // AuthenticationController.cs:41
```
```csharp
return $"{request.Scheme}://{request.Host}/signin-oidc";     // IOwinRequestExtensions.cs:9
```

**Remediation.**
- Build these URLs from a configured canonical base URL rather than request-derived host, and/or enforce an allowed-hosts list at the edge.

---

### F-16 — Outdated / legacy client-side components

- **Severity:** Low
- **OWASP 2021:** A06 Vulnerable and Outdated Components
- **NIST:** SP 800-53 Rev5 **SA-22** (Unsupported Components), **SI-2** (Flaw Remediation), **CM-8** (Component Inventory); SSDF **PW.4**, **RV.1**
- **Location:** `app/Bookstore.Web/packages.config`; `app/Bookstore.Data/Bookstore.Data.csproj` (PackageReference).

**Dependency inventory and assessment.** Server-side packages are generally recent as of review; the main concerns are legacy client libraries and framework end-of-life context.

| Package | Version | Assessment |
|---------|---------|-----------|
| Microsoft.AspNet.Mvc | 5.3.0 | Current for MVC 5 line; MVC 5 is in extended/maintenance mode. |
| EntityFramework | 6.5.1 | Recent EF6; no raw-SQL usage (see F-17). |
| Newtonsoft.Json | 13.0.3 | Current; no `TypeNameHandling`/deserialization gadget usage found (F-18). |
| Microsoft.IdentityModel.* / System.IdentityModel.Tokens.Jwt | 8.7.0 | Recent. |
| NLog | 5.4.0 | Recent. |
| AWSSDK.* (Core/S3/Rekognition/SSM/CloudWatchLogs) | 3.7.x | Recent. |
| Magick.NET-Q8-AnyCPU | 14.6.0 | Recent; relevant to F-10 (untrusted image decoding). |
| **jQuery** | **3.7.1** | Latest 3.x; 3.x line is maintained but client-side XSS risk if combined with unsafe DOM sinks. |
| **jQuery.Validation** | 1.21.0 | Dated; low direct risk. |
| **Modernizr** | **2.8.3** | Very old (2014), unmaintained — legacy client library; replace or remove. |
| **Bootstrap** (bundled client assets) | legacy (MVC 5 template vintage) | Confirm the shipped Bootstrap/CSS bundle version; old Bootstrap has known XSS in data-attributes. |
| .NET Framework | 4.8 | Supported but a legacy platform; new development should target modern .NET. |

> Note: specific CVE identifiers are intentionally **not** asserted here because the exact vulnerable-version boundaries for these packages could not be confirmed against a published advisory in this review. The items flagged (Modernizr 2.8.3, legacy Bootstrap, jQuery client usage) are called out as risk classes (unmaintained / legacy client libraries) rather than with fabricated CVE numbers.

**Remediation.**
- Remove or replace unmaintained client libraries (Modernizr 2.8.3); confirm and upgrade the Bootstrap bundle to a supported release.
- Add Subresource Integrity (SRI) attributes to any externally referenced scripts/styles.
- Establish a recurring dependency-scanning process (e.g. `dotnet list package --vulnerable` once on a modern SDK, or an SCA tool) and track framework modernization.

---

### F-17 — Injection (SQL / XSS) surface review

- **Severity:** Info (low residual risk)
- **OWASP 2021:** A03 Injection
- **NIST:** SP 800-53 Rev5 **SI-10** (Information Input Validation); SSDF **PW.5**
- **Location:** `app/Bookstore.Data/Repositories/*.cs` (e.g. `BookRepository.cs:89-93`); all `.cshtml` views.

**Assessment.**
- **SQL injection — LOW.** Data access is Entity Framework 6 using LINQ throughout. A repository-wide search for `SqlQuery`, `ExecuteSqlCommand`, `ExecuteSqlRaw`, and `FromSql` returned **no matches**, so there is no raw/concatenated SQL. User-supplied search terms flow through parameterized LINQ `.Where(x => x.Name.Contains(searchString) ...)`, which EF translates to parameterized `LIKE` with proper escaping. Residual caveat: `Contains`/`LIKE` on large text with leading wildcards can be a performance/DoS consideration, not an injection one.
- **XSS — LOW residual.** Razor auto-encodes output by default and a search across all `.cshtml` views for `Html.Raw`, `@Html.Raw`, `MvcHtmlString`, and `HtmlString` returned **no matches**, so there is no raw HTML emission of model data. Stored book fields (Name/Author/Summary/ISBN) and offer fields are therefore encoded on render. Residual stored-XSS risk would only arise if a future view introduces raw output or a client-side script injects unescaped data into the DOM; this should be guarded by the CSP in F-09.

**Evidence.**
```csharp
// BookRepository.cs — parameterized LINQ, no raw SQL
query = query.Where(x => x.Name.Contains(searchString) ||
                         x.Genre.Text.Contains(searchString) || ...);  // :89-93
```

**Remediation / guidance.**
- Maintain the no-raw-SQL and no-`Html.Raw` posture; if raw SQL is ever needed, use parameterized `DbSet.SqlQuery`/`SqlParameter`.
- Deploy the CSP (F-09) as XSS defense-in-depth.

---

### F-18 — SSRF and insecure-deserialization surface review

- **Severity:** Info (no sink found)
- **OWASP 2021:** A10 Server-Side Request Forgery; A08 Software and Data Integrity Failures (deserialization)
- **NIST:** SP 800-53 Rev5 **SC-7** (Boundary Protection), **SI-10**; SSDF **PW.5**
- **Location:** reviewed across `app/Bookstore.Web` and `app/Bookstore.Data`.

**Assessment.**
- **SSRF — no classic sink found.** No controller or service takes a user-supplied URL and performs an outbound fetch. Outbound calls are to fixed AWS SDK endpoints (S3, Rekognition, SSM, CloudWatch Logs) and the Cognito `MetadataAddress`, which is sourced from SSM/config, not from user input. Image upload passes a `Stream` (the uploaded bytes) to Rekognition/S3 — not a URL — so there is no fetch-by-URL path. The open-redirect (F-06) and host-header usage (F-15) are server-to-client redirects, not server-side requests. Conclusion: **no SSRF sink** under the current code. Should a feature be added that fetches a user-provided URL (e.g. "import cover from URL"), it must validate the target against an allow-list and block link-local/metadata addresses.
- **Insecure deserialization — none found.** A repository-wide search for `BinaryFormatter`, `JavaScriptSerializer`, `XmlSerializer`, `TypeNameHandling`, `LosFormatter`, and `NetDataContractSerializer` returned **no matches**. JSON handling is via Newtonsoft.Json/System.Text.Json without `TypeNameHandling`, so there is no untrusted polymorphic deserialization gadget surface.

**Remediation / guidance.**
- Keep the current posture. If URL-driven features are introduced, add SSRF protections (allow-list, DNS-rebinding/metadata-IP blocking). Never enable `TypeNameHandling.All`/`Auto` on untrusted JSON.

---

## 4. Summary Mapping Table (Finding → OWASP → NIST → Severity)

| ID | Finding | OWASP 2021 | NIST (SP 800-53 / SSDF) | Severity |
|----|---------|-----------|-------------------------|----------|
| F-01 | Unauthenticated admin via local auth | A07 | IA-2, AC-3, AC-6 / PW.1 | Critical |
| F-02 | Default creds `P@ssword1` + self-sign-up | A07 / A02 | IA-5, AC-6, CM-6 / PW.1 | Critical |
| F-03 | No CSRF tokens | A01 | SC-23, SI-10 / PW.5 | High |
| F-04 | Cart correlation-id IDOR | A01 / A04 | AC-3, AC-4, SC-8 / PW.1 | High |
| F-05 | Order lookup missing ownership check | A01 | AC-3, AC-6 / PW.1 | High |
| F-06 | Open redirect in Login | A01 | SI-10, AC-4 / PW.5 | High |
| F-07 | Over-broad IAM + DESTROY policies | A05 / A04 | AC-6, CM-6, SC-28 / PO.5 | High |
| F-08 | debug=true, no customErrors, cookie flags | A05 / A09 | CM-6, SC-8, SI-11 / PW.9 | Medium |
| F-09 | Missing security headers | A05 | SC-8, SC-18, CM-6 / PW.9 | Medium |
| F-10 | Weak file-upload validation | A04 / A05 | SI-10, SC-18 / PW.5 | Medium |
| F-11 | Plaintext DB conn string in SSM | A02 | SC-28, IA-5, SC-12/13 / PW.9 | Medium |
| F-12 | State change over GET | A01 | AC-3, SC-23 / PW.5 | Medium |
| F-13 | Logging / monitoring / error handling | A09 | AU-2, AU-3, AU-6, SI-4, SI-11 / PW.9, RV.1 | Medium |
| F-14 | Unverified Docker artifact download | A08 | SR-4, SI-7, CM-2 / PO.3, PW.4 | Low |
| F-15 | Host-header influence on auth URLs | A01 / A05 | SI-10, SC-8 / PW.5 | Low |
| F-16 | Outdated client-side components | A06 | SA-22, SI-2, CM-8 / PW.4, RV.1 | Low |
| F-17 | SQL/XSS surface review | A03 | SI-10 / PW.5 | Info |
| F-18 | SSRF / deserialization review | A10 / A08 | SC-7, SI-10 / PW.5 | Info |

---

## 5. Prioritized Remediation Roadmap

**Phase 1 — Immediate (Critical / exploitable now)**
1. **F-01:** Disable local auth outside Development; require real credential validation; stop auto-granting `Administrators`; harden the auth cookie. *(Fail-fast startup guard.)*
2. **F-02:** Remove `P@ssword1`, generate a random temporary password, force reset, add Cognito password policy + MFA, review self-sign-up escalation, remove creds from README.

**Phase 2 — High (one sprint)**
3. **F-03:** Add anti-forgery tokens to all forms and `[ValidateAntiForgeryToken]` to all state-changing POST actions.
4. **F-04 / F-05:** Enforce server-side ownership on carts and orders; stop trusting the `ShoppingCartId` cookie as an authorization key; harden the cookie.
5. **F-06:** Restrict `Login` redirects to local/allow-listed URLs.
6. **F-07:** Scope the CDK custom-resource IAM to the specific Cognito ARN; use `RETAIN`/snapshots for data-bearing resources in real environments.

**Phase 3 — Medium (hardening)**
7. **F-08 / F-09:** Turn off `debug`, add `<customErrors>`, secure/HttpOnly cookies, and the full set of security response headers; fix the Release transform.
8. **F-10:** Add real content/magic-byte validation and ImageMagick resource limits; normalize stored file names.
9. **F-11:** Keep the DB secret in Secrets Manager (or SSM `SecureString`), scoped reads.
10. **F-12:** Convert state-changing GET actions to POST + anti-forgery.
11. **F-13:** Add security/audit logging, safe error handling (`Server.ClearError` + error view), redaction, and CloudWatch alarms.

**Phase 4 — Low / ongoing**
12. **F-14:** Verify the Docker artifact by hash; pin base images by digest.
13. **F-15:** Build auth URLs from a canonical configured base; enforce allowed hosts.
14. **F-16:** Replace unmaintained client libraries, add SRI, and stand up recurring dependency scanning; plan framework modernization.
15. **F-17 / F-18:** Maintain the current no-raw-SQL, no-`Html.Raw`, no-unsafe-deserialization, no-SSRF-sink posture; apply CSP as XSS defense-in-depth and add SSRF guards if URL-fetch features are introduced.

---

*End of assessment. All cited file paths and line numbers were verified against the repository source on branch `main` at review time. No CVE identifiers are asserted; dependency concerns are described as risk classes where a specific advisory could not be confirmed.*
