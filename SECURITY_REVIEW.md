# Security Assessment: Bob's Used Books Classic

**Assessment type:** Static / manual source code review
**Standards referenced:** OWASP Top 10 (2021), NIST SP 800-53 control families (AC, SC, AU, IA, CM)
**Target:** ASP.NET MVC 5 web application (.NET Framework 4.8, Windows-only) plus AWS CDK (C#) infrastructure
**Repository root reviewed:** `/`
**Date of review:** based on the current `main` branch state at review time

---

## Executive Summary

Bob's Used Books Classic is an AWS sample e-commerce application. It ships an OWIN-based authentication layer with two modes, `local` and `aws` (Cognito), EF6 data repositories, S3-backed image storage, and a CDK infrastructure project that deploys the app to ECS on Fargate with an RDS SQL Server backend.

The review found several serious weaknesses. The most severe is a complete authentication and access-control bypass in the `local` authentication provider, which is the **default** configuration in `Web.config` and is the mode **forced** in the ECS/Fargate deployment. In that configuration, any anonymous visitor is silently granted the `Administrators` role, defeating the `[Authorize(Roles = "Administrators")]` guard on the admin area. This is compounded by a total absence of CSRF protection, an open redirect in the sign-in flow, hardcoded default credentials, and a lack of end-to-end transport encryption in the infrastructure.

Positively, the data layer uses EF6 LINQ with parameterized queries (no raw SQL was found) and Razor auto-encodes output (no `Html.Raw` usage was found), so classic injection and XSS risks are low. Dependencies have been kept relatively current, though the underlying platform (.NET Framework 4.8 / MVC 5) is legacy.

Many of these issues are typical of sample/demo code and are called out in comments as "not for production." That framing does not reduce their technical severity; it should be treated as a to-do list before any real deployment.

### Findings count by severity

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High     | 5 |
| Medium   | 5 |
| Low / Informational | 2 |
| **Total** | **13** |

### Top risks

1. **Authentication bypass granting admin (`local` mode)** - anonymous users become `Administrators`. This is the deployed default and the ECS-forced mode.
2. **No CSRF protection anywhere** - every state-changing POST (inventory, resale, address, checkout) is forgeable.
3. **No end-to-end TLS in the infrastructure** - ALB is HTTP-only, CloudFront-to-origin is HTTP, RDS is unencrypted at rest and does not enforce SSL, and the connection string is stored in plaintext SSM.
4. **Hardcoded default admin credentials** (`P@ssword1`) plus open Cognito self-sign-up.
5. **Security misconfiguration** - `debug="true"`, no custom error handling, no security headers, insecure cookies.

---

## Critical Findings

### C-1. Authentication bypass: anonymous users are granted the `Administrators` role in local mode

- **Severity:** Critical
- **OWASP:** A07:2021 Identification and Authentication Failures (also A01:2021 Broken Access Control)
- **NIST:** IA-2, AC-3, AC-6
- **Affected file:** `app/Bookstore.Web/Helpers/LocalAuthenticationMiddleware.cs`
  - Line 23: `if (context.Request.Path.Value.StartsWith("/Authentication/Login"))` - any request to the login path triggers authentication
  - Lines 29-33: an unsigned `LocalAuthentication` cookie is written and the user is redirected to `/`
  - Line 35: `else if (HttpContext.Current.Request.Cookies["LocalAuthentication"] != null)` - mere presence of the cookie re-authenticates the request
  - Lines 49-59: `CreateClaimsPrincipal` builds an identity and, on line 57, adds `new Claim(ClaimTypes.Role, "Administrators")`
- **Supporting context:**
  - `app/Bookstore.Web/Web.config` line 20: `<add key="Services/Authentication" value="local" />` - local mode is the default.
  - `app/Bookstore.Cdk/EcsStack.cs` line 60: `{ "Services/Authentication", "local" }` - local mode is forced in the ECS/Fargate deployment (comment: "Can't use Cognito hosted UI without an https redirect").
  - `app/Bookstore.Web/Areas/Admin/Controllers/AdminAreaControllerBase.cs` line 7: `[Authorize(Roles = "Administrators")]` - the admin area is guarded by exactly the role this middleware hands out.

**Description.** The local authentication middleware performs no credential check. Any visitor who requests `/Authentication/Login` is issued a `ClaimsPrincipal` that always includes the `Administrators` role, and a plaintext, unsigned cookie named `LocalAuthentication` is set. On every subsequent request the presence of that cookie (which carries no signature, token, or user binding) is sufficient to reconstruct the same admin principal.

**Impact.** In the default and the ECS-deployed configuration, this is a full authentication and authorization bypass. An anonymous, unauthenticated user obtains administrator privileges and can reach every action protected by `[Authorize(Roles = "Administrators")]`, including inventory management. Because the cookie is unsigned, it can be trivially forged or replayed. This single defect undermines the entire access-control model of the application.

**Remediation.**
- Do not deploy `local` authentication mode to any environment reachable by untrusted users. If a local/dev shortcut is required, gate it behind a compile-time flag or an environment check that cannot be enabled in production.
- Never assign privileged roles unconditionally. Local development identities should be non-privileged by default.
- If a local auth cookie must exist, make it a cryptographically signed/encrypted token (e.g., an ASP.NET auth ticket) bound to a real identity, and validate the signature on every request rather than trusting mere presence.
- Provision the ECS deployment with HTTPS (see H-5) so that Cognito-based authentication can be used instead of the local bypass.
- Add security event logging for authentication and role assignment (see A09 section).

---

## High Findings

### H-1. Hardcoded default admin password and open self-sign-up (Cognito)

- **Severity:** High
- **OWASP:** A07:2021 Identification and Authentication Failures (also A02:2021 Cryptographic Failures for credential handling)
- **NIST:** IA-5, AC-2
- **Affected files:**
  - `app/Bookstore.Cdk/CoreStack.cs` line 161: `{ "TemporaryPassword", "P@ssword1" }` in `CreateDefaultAdminUser` (admin user created at lines 149-181)
  - `app/Bookstore.Cdk/CoreStack.cs` line 124: `SelfSignUpEnabled = true` in `CreateCognitoUserPool`
  - `README.md` lines 43-44: documents Username `Admin` / Password `P@ssword1`

**Description.** The CDK provisions a Cognito user named `admin` with the fixed temporary password `P@ssword1`, which is also published in the README. The user pool additionally enables self-service sign-up (`SelfSignUpEnabled = true`).

**Impact.** A well-known, publicly documented default credential is an immediate target for credential-stuffing and unauthorized first-login takeover if the temporary password is not rotated before exposure. Open self-sign-up lets anyone create an account in the pool, expanding the attack surface (especially where account creation should be restricted or invitation-only).

**Remediation.**
- Generate the temporary password randomly (e.g., a CDK `SecretValue` / Secrets Manager generated secret) and never commit it to source or docs. Require a forced password change on first login.
- Remove the literal password from `README.md`; instead describe how to retrieve the generated secret.
- Set `SelfSignUpEnabled = false` unless open registration is an explicit product requirement; if self-sign-up is required, add email/domain verification and abuse controls.

### H-2. No CSRF protection on any state-changing request

- **Severity:** High
- **OWASP:** A01:2021 Broken Access Control (CSRF)
- **NIST:** SC-23, SI-10
- **Evidence:** A repository-wide search for `ValidateAntiForgeryToken` and `AntiForgeryToken` returns **zero** matches across `app/`. No POST action carries `[ValidateAntiForgeryToken]` and no view emits `@Html.AntiForgeryToken()`.
- **Representative affected actions:**
  - `app/Bookstore.Web/Areas/Admin/Controllers/InventoryController.cs` line 42 and line 75 (`[HttpPost]` create/update)
  - `app/Bookstore.Web/Controllers/ResaleController.cs` line 35 (`[HttpPost]`)
  - Address and checkout POST actions follow the same pattern.

**Description.** The application relies solely on cookie-based authentication (both the local cookie and the Cognito `.AspNet.Cookies` cookie) and applies no anti-forgery tokens to state-changing requests.

**Impact.** An attacker can host a page that auto-submits a forged POST to the application. If a victim with an active session (including an auto-granted admin session in local mode) visits it, the request executes with the victim's privileges: creating or modifying inventory, submitting resale offers, changing addresses, or placing orders.

**Remediation.**
- Add `@Html.AntiForgeryToken()` to every form that performs a state change and decorate the corresponding `[HttpPost]` actions with `[ValidateAntiForgeryToken]`.
- Consider a global anti-forgery filter so new POST actions are protected by default.
- Set `SameSite=Lax` (or `Strict`) on authentication cookies as defense in depth.

### H-3. Open redirect in the sign-in flow

- **Severity:** High
- **OWASP:** A01:2021 Broken Access Control (Unvalidated Redirects and Forwards)
- **NIST:** SI-10
- **Affected file:** `app/Bookstore.Web/Controllers/AuthenticationController.cs`
  - Line 10: `public ActionResult Login(string redirectUri = null)`
  - Line 14: `return Redirect(redirectUri);`

**Description.** The `Login` action redirects to a user-supplied `redirectUri` without validating that it is a local/allowed URL. Any absolute URL is accepted.

**Impact.** Attackers can craft links such as `/Authentication/Login?redirectUri=https://evil.example/phish` that appear to originate from the trusted application and then bounce the user to an attacker-controlled site. This is commonly used to lend credibility to phishing and to facilitate token/OAuth theft.

**Remediation.**
- Only redirect to local URLs: use `Url.IsLocalUrl(redirectUri)` and fall back to a safe default (e.g., `RedirectToAction("Index", "Home")`) when it is not local.
- Alternatively, maintain an allow-list of permitted redirect targets.

### H-4. Security misconfiguration in `Web.config` (debug, error handling, headers, cookies)

- **Severity:** High
- **OWASP:** A05:2021 Security Misconfiguration
- **NIST:** CM-6, SC-8, SC-23, SI-11
- **Affected files:**
  - `app/Bookstore.Web/Web.config` line 33: `<compilation debug="true" targetFramework="4.8" />`
  - `app/Bookstore.Web/Web.config`: no `<customErrors>` element and no `<system.webServer><httpProtocol><customHeaders>` (confirmed absent) - no HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, or `Referrer-Policy`
  - `app/Bookstore.Web/Web.config` line 19: `<add key="Environment" value="Development" />`
  - `app/Bookstore.Web/Web.Release.config` lines 17-30: only removes the `debug` attribute; the `<customErrors>` transform is left commented out, so release builds still ship without custom error handling
  - `app/Bookstore.Web/Helpers/LocalAuthenticationMiddleware.cs` lines 29-31: the `LocalAuthentication` cookie is created (with a one-day expiry) without `Secure` or `HttpOnly` flags. `app/Bookstore.Web/Controllers/AuthenticationController.cs` lines 24-26 (`LocalSignOut`) is the sign-out path, which likewise creates its cookie (an expired deletion cookie) without those flags

**Description.** The application is configured for development: debug compilation is on, there is no custom error page, no security response headers are emitted, and the local auth cookie lacks `Secure`/`HttpOnly`.

**Impact.**
- `debug="true"` degrades performance and can expose detailed diagnostics.
- Absent `<customErrors>` means unhandled exceptions can render full stack traces and internal details to clients (information disclosure - see also the A09 section).
- Missing security headers leave the app exposed to clickjacking, MIME sniffing, and weaker transport posture.
- A cookie without `HttpOnly` is readable by JavaScript (XSS-assisted theft); without `Secure` it can be sent over plaintext HTTP.

**Remediation.**
- Set `debug="false"` for any non-developer build (the release transform should enforce this).
- Add `<customErrors mode="On" defaultRedirect="~/Error" />` (or `RemoteOnly`) and a friendly error view; ensure no stack traces reach clients.
- Emit security headers via `<system.webServer><httpProtocol><customHeaders>` or middleware: `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a restrictive `Content-Security-Policy`, and `Referrer-Policy`.
- Create cookies with `HttpOnly = true` and `Secure = true`, and set `requireSSL="true"` on forms/cookies once TLS is in place.

### H-5. No end-to-end transport encryption in the infrastructure

- **Severity:** High
- **OWASP:** A02:2021 Cryptographic Failures (also A05:2021 Security Misconfiguration)
- **NIST:** SC-8, SC-13, SC-28
- **Affected files:**
  - `app/Bookstore.Cdk/EcsStack.cs` lines 46-72: `ApplicationLoadBalancedFargateService` is created with no `Certificate`, no `Protocol = HTTPS` listener, and no HTTP-to-HTTPS redirect - the ALB serves HTTP only. This is why local auth is forced (see C-1).
  - `app/Bookstore.Cdk/CoreStack.cs` line 106: comment confirms CloudFront-to-origin uses HTTP (only viewer-to-CloudFront is `REDIRECT_TO_HTTPS` on line 107).
  - `app/Bookstore.Cdk/DatabaseStack.cs` lines 42-67: `DatabaseInstance` sets no `StorageEncrypted = true` and enforces no SSL/TLS for client connections.
  - `app/Bookstore.Cdk/DatabaseStack.cs` lines 78-82 and `config-scripts/Update-ConnectionString.ps1` line 11: the generated connection string has no `Encrypt=true` / `TrustServerCertificate` settings.

**Description.** Traffic is unencrypted at multiple hops: client-to-application (ALB HTTP), CloudFront-to-S3 origin (HTTP), and application-to-database (no enforced SSL). RDS storage is not encrypted at rest.

**Impact.** Credentials, session cookies (including the admin-granting local cookie), personal data, and order information can be intercepted or tampered with on the network. Unencrypted RDS storage weakens data-at-rest protection. This also blocks the more secure Cognito auth path, indirectly enabling C-1.

**Remediation.**
- Attach an ACM certificate to the Fargate service and configure an HTTPS listener with automatic HTTP-to-HTTPS redirect; this also unblocks Cognito hosted-UI login.
- Set RDS `StorageEncrypted = true` (KMS) and require TLS for DB connections; add `Encrypt=true` to the connection string with proper certificate validation.
- Require HTTPS between CloudFront and its origin where supported, and add `enforceSSL` on the S3 bucket policy.

---

## Medium Findings

### M-1. Weak file-upload validation and no-op content moderation by default

- **Severity:** Medium (High in exposure if the upload path is reachable by untrusted users)
- **OWASP:** A04:2021 Insecure Design (also A05:2021)
- **NIST:** SI-10, SC-18
- **Affected files:**
  - `app/Bookstore.Web/Helpers/ImageTypesAttribute.cs` lines 24-26: validation reads `Path.GetExtension(file.FileName)` and only checks the extension against an allow-list (`imageTypes.Contains(extension, ...)`); no magic-byte/content-type inspection.
  - `app/Bookstore.Data/ImageValidationServices/LocalImageValidationService.cs` line 11: `return await Task.Run(() => true);` - the local validator always reports the image as safe.
  - `app/Bookstore.Data/FileServices/S3FileService.cs` line 39: the stored key randomizes the filename but preserves the attacker-controlled extension via `Path.GetExtension(filename)`.
  - `app/Bookstore.Web/Web.config` line 23: `Services/ImageValidationService` defaults to `local`, so in the default configuration **no content moderation runs**.

**Description.** Upload validation trusts the file extension only, and in the default `local` configuration the content-moderation service is a no-op. Rekognition-based moderation exists only in `aws` mode.

**Impact.** Content-type spoofing (e.g., a non-image or malicious payload with a `.png` extension) passes validation. Combined with no content moderation in the default mode, disallowed or malicious content can be stored and served. While files are served from S3 via CloudFront (reducing server-side execution risk), stored-content and content-injection risks remain.

**Remediation.**
- Validate the actual file content (magic bytes / decode as an image) rather than trusting the extension, and verify the reported MIME type.
- Enforce a maximum size (a `MaxFileSizeAttribute` exists - confirm it is applied) and re-encode images server-side to strip embedded payloads/metadata.
- Do not treat the local no-op validator as production-ready; require real moderation before allowing untrusted uploads.
- Set a safe `Content-Type` and `Content-Disposition` on stored objects and normalize the extension based on validated content.

### M-2. Over-permissive IAM policies (least-privilege violations)

- **Severity:** Medium
- **OWASP:** A05:2021 Security Misconfiguration
- **NIST:** AC-6 (least privilege)
- **Affected files:**
  - `app/Bookstore.Cdk/EcsStack.cs` lines 137-138: task role granted `rekognition:DetectModerationLabels` (line 137) on `Resources = new[] { "*" }` (line 138).
  - `app/Bookstore.Cdk/CoreStack.cs` line 176: `CreateDefaultAdminUser` uses `AwsCustomResourcePolicy.FromSdkCalls(... Resources = AwsCustomResourcePolicy.ANY_RESOURCE)`.

**Description.** Two policies grant actions against all resources (`*` / `ANY_RESOURCE`) rather than scoping to specific ARNs.

**Impact.** If the task role or custom-resource role is compromised, the wildcard scope broadens the blast radius. This violates least privilege.

**Remediation.**
- Scope Rekognition (and other) permissions to the minimum required; where a specific resource ARN cannot be expressed, constrain via conditions/tags.
- Scope the Cognito custom-resource policy to the specific user pool ARN instead of `ANY_RESOURCE`.

### M-3. S3 image bucket lacks encryption, public-access block, and SSL enforcement; destructive removal policy

- **Severity:** Medium
- **OWASP:** A05:2021 Security Misconfiguration (also A02:2021 for encryption)
- **NIST:** SC-28, SC-8, CM-6
- **Affected file:** `app/Bookstore.Cdk/CoreStack.cs`
  - Lines 42-50 (`CreateImageS3Bucket`, method declared at line 34): `AutoDeleteObjects = true` (line 48) and `RemovalPolicy = RemovalPolicy.DESTROY` (line 49); no `Encryption`, no `BlockPublicAccess`, no `EnforceSSL` specified.
  - Line 132: the Cognito user pool likewise uses `RemovalPolicy.DESTROY`.

**Description.** The image bucket is created without explicit server-side encryption, without an explicit public-access block, and without an SSL-only bucket policy, and it is configured to be destroyed (with its data) when the stack is deleted.

**Impact.** Missing encryption/SSL enforcement weakens data protection. The destructive removal policy risks irreversible data loss on stack deletion (the code comments acknowledge this). Relying on account-default public-access settings is fragile.

**Remediation.**
- Set `Encryption = BucketEncryption.S3_MANAGED` (or KMS), `BlockPublicAccess = BlockPublicAccess.BLOCK_ALL`, and `EnforceSSL = true`.
- Use `RemovalPolicy.RETAIN` for buckets holding real data; reserve `DESTROY`/`AutoDeleteObjects` for ephemeral demo stacks only.

### M-4. Database secrets stored and written in plaintext

- **Severity:** Medium
- **OWASP:** A02:2021 Cryptographic Failures (secrets handling)
- **NIST:** SC-28, IA-5, SC-12
- **Affected files:**
  - `app/Bookstore.Cdk/DatabaseStack.cs` lines 71-82 (`CreateConnectionString`): the connection string, including `Password={password}` (line 81), is stored as a plain `StringParameter` in SSM (line 78) - not a `SecureString` and not a Secrets Manager reference.
  - `config-scripts/Update-ConnectionString.ps1` lines 23-24: the script writes the full plaintext connection string (with credentials, assembled at line 11) directly into `Web.config`.
  - `app/Bookstore.Domain/AdminUser/DbSecrets.cs` lines 5-15: models raw DB credentials (`Username`, `Password`, host, etc.) in plaintext properties.

**Description.** `DatabaseStack.CreateConnectionString` reads the RDS-generated AWS Secrets Manager secret (`Database.Secret`, via `SecretValueFromJson` for host, username, password, and database) and then re-materializes those credentials, including the password, into a plaintext SSM `StringParameter`. In other words, a managed secret is being downgraded to plaintext: the credentials that already live in an encrypted, access-controlled Secrets Manager secret are copied verbatim into an unencrypted parameter and subsequently written into `Web.config` on the instance.

**Impact.** Anyone with read access to the SSM parameter or the filesystem/`Web.config` obtains database credentials. Plaintext parameters are not encrypted with a customer-managed key and are easier to exfiltrate than managed secrets.

**Remediation.**
- Store the connection string/credentials in AWS Secrets Manager (or an SSM `SecureString`) and grant read access via least-privilege IAM. RDS already generates a Secrets Manager secret (`Database.Secret`) - reference it directly at runtime rather than materializing a plaintext parameter.
- Avoid writing plaintext credentials into `Web.config`; retrieve secrets at runtime. If a config file must be updated, restrict its permissions and avoid logging its contents.
- Prefer IAM database authentication where feasible to remove long-lived passwords.

### M-5. Security logging and monitoring gaps (see dedicated section)

- **Severity:** Medium
- **OWASP:** A09:2021 Security Logging and Monitoring Failures
- Details and remediation are consolidated in the **Logging, Monitoring, and Error-Handling** section below.

---

## Low / Informational Findings

### L-1. Injection and XSS surface is low but should stay monitored

- **Severity:** Low / Informational
- **OWASP:** A03:2021 Injection
- **NIST:** SI-10
- **Evidence:**
  - Data access uses EF6 LINQ across `app/Bookstore.Data/Repositories/*.cs`. A search for `FromSql`, `ExecuteSqlCommand`, and `SqlQuery` returns **no** matches, so queries are parameterized and raw SQL injection risk is low.
  - A search for `Html.Raw` returns **no** matches; Razor auto-encodes output by default, so reflected/stored XSS risk is low.

**Description.** No raw SQL or unencoded output sinks were found. This is a healthy baseline, not a guarantee.

**Remediation.**
- Continue to avoid raw SQL and `Html.Raw`. If either is introduced later, use parameterization and explicit encoding.
- Maintain server-side input validation (model validation) in addition to client-side validation.
- Once CSRF (H-2) and headers/CSP (H-4) are added, the XSS posture improves further.

### L-2. Legacy platform and dependency management

- **Severity:** Low / Informational
- **OWASP:** A06:2021 Vulnerable and Outdated Components
- **NIST:** SA-22, RA-5, CM-8
- **Affected file:** `app/Bookstore.Web/packages.config`

**Description.** The application targets **.NET Framework 4.8** with **ASP.NET MVC 5** (`Microsoft.AspNet.Mvc` 5.3.0), which are in long-term maintenance rather than active feature development. Dependencies are otherwise reasonably current, for example: `EntityFramework` 6.5.1, `Newtonsoft.Json` 13.0.3, `Autofac` 8.2.1, `Microsoft.Owin` 4.2.2, the `Microsoft.IdentityModel.*` stack at 8.7.0, `NLog` 5.4.0, `jQuery` 3.7.1, and various AWSSDK packages (`AWSSDK.Core` 3.7.402.35, `AWSSDK.S3` 3.7.416.5, `AWSSDK.Rekognition` 3.7.400.129).

**Impact.** Legacy frameworks receive security fixes but no modern hardening; over time, dependency vulnerabilities accrue. No specific CVE is asserted here - this is a process finding.

**Remediation.**
- Adopt a recurring dependency-vulnerability scan: `dotnet list package --vulnerable` (or the NuGet audit feature) and/or OWASP Dependency-Check in CI.
- Track a migration path to a supported .NET (e.g., .NET 8+) to gain modern security features and longer support.
- Keep `packages.config` versions patched and pinned; review transitive dependencies.

---

## Logging, Monitoring, and Error-Handling (OWASP A09)

- **OWASP:** A09:2021 Security Logging and Monitoring Failures
- **NIST:** AU-2, AU-3, AU-6, AU-9, SI-11

### Current state (observed)

- **Logging configuration** - `app/Bookstore.Web/App_Start/LoggingSetup.cs`:
  - Lines 18-24: in `aws` mode logs go to a CloudWatch `AWSTarget` (line 20); otherwise (line 24) logging uses a `DebuggerTarget` (debugger output only).
  - Line 29: a single rule `new LoggingRule("*", LogLevel.Info, loggingTarget)`, generic info-level logging with no dedicated security channel.
  - `app/Bookstore.Web/Web.config` line 24 defaults `Services/LoggingService` to `local`, so by default there is **no durable/centralized log sink**.
- **No security event logging:** there is no logging of authentication successes/failures, admin/privileged actions, access-control denials, or the role assignment performed in `LocalAuthenticationMiddleware.CreateClaimsPrincipal` (`LocalAuthenticationMiddleware.cs` lines 49-59). Because that middleware silently grants admin (C-1), the absence of an audit trail means the bypass would leave no forensic record.
- **Error handling:** `app/Bookstore.Web/App_Start/FilterConfig.cs` lines 9-10 register a global `HandleErrorAttribute` and a global `AuthorizeAttribute`. However, `Web.config` line 33 has `debug="true"` and there is **no `<customErrors>`** (H-4), so unhandled exceptions may render full stack traces to clients. `HandleErrorAttribute` only applies to MVC action exceptions rendering the `Error` view; it does not cover all pipeline errors, and there is no evidence of structured, centralized exception logging with correlation IDs.

### Impact

Without security-relevant logging and alerting, attacks such as the authentication bypass, CSRF-driven changes, or credential misuse can occur undetected and without an audit trail, which delays detection and hampers incident response. Debug error pages can additionally leak sensitive internal detail to attackers.

### Remediation

- **Add security event logging (non-sensitive).** Emit structured audit events for: login success/failure, logout, role/claim assignment, admin/privileged actions (inventory create/update, resale approval), authorization denials (403), and input-validation failures. Include actor identity, source IP, action, resource, and outcome - and **never** log passwords, full cookies/tokens, connection strings, or PII beyond what is necessary.
- **Centralize logs.** Route logs to a durable, tamper-resistant sink (CloudWatch Logs is already wired for `aws` mode) even for non-AWS environments, and set appropriate retention. Avoid the debugger-only sink for anything but local development.
- **Add centralized, safe error handling.** Set `debug="false"` and configure `<customErrors mode="On">` (or `RemoteOnly`) with a generic error view. Add global exception handling (e.g., `Application_Error` and/or an exception filter) that logs the full exception server-side with a correlation ID while returning only a generic message and the correlation ID to the client.
- **Alerting/monitoring.** Create metric filters/alarms (e.g., CloudWatch) on repeated auth failures, spikes in 403s, and admin actions from unexpected sources.

> This section also fulfills the workspace directive to ensure the code has proper logging and error handling: the concrete guidance above (structured non-sensitive security logging plus centralized error handling with `customErrors` and global exception capture) is the recommended remediation for the gaps found in `LoggingSetup.cs`, `FilterConfig.cs`, and `Web.config`.

---

## Prioritized Remediation Roadmap

**Priority 1 - Immediate (blockers before any real deployment)**
1. **C-1:** Eliminate the local-mode admin bypass; never assign `Administrators` unconditionally; sign/validate any auth cookie. Enable HTTPS so Cognito auth can be used.
2. **H-5:** Provision end-to-end TLS (ALB HTTPS + redirect, RDS SSL + encryption at rest, CloudFront-to-origin HTTPS, S3 `EnforceSSL`).
3. **H-2:** Add anti-forgery tokens/validation to all state-changing POSTs.

**Priority 2 - High (near-term)**
4. **H-1:** Remove the hardcoded `P@ssword1`, generate secrets, force reset, and disable open self-sign-up unless required.
5. **H-3:** Fix the open redirect with `Url.IsLocalUrl` / allow-list.
6. **H-4:** Set `debug="false"`, add `<customErrors>`, security headers, and `Secure`/`HttpOnly`/`SameSite` cookies.
7. **A09 (M-5):** Add security event logging and centralized error handling.

**Priority 3 - Medium (hardening)**
8. **M-4:** Move DB secrets to Secrets Manager / SSM SecureString; stop writing plaintext credentials into `Web.config`.
9. **M-1:** Strengthen upload validation (content inspection) and require real image moderation.
10. **M-2:** Scope IAM policies to least privilege (remove `*` / `ANY_RESOURCE`).
11. **M-3:** Add S3 encryption, `BlockPublicAccess`, `EnforceSSL`; use `RETAIN` removal policy for real data.

**Priority 4 - Ongoing / informational**
12. **L-2:** Establish dependency vulnerability scanning; plan platform modernization.
13. **L-1:** Maintain parameterized queries and output encoding; keep server-side validation.

---

## Methodology and Limitations

This assessment was a **static, manual source code review** performed against the repository's `main` branch. Findings were confirmed by reading the cited source files and by targeted pattern searches (for example, confirming zero matches for `ValidateAntiForgeryToken`, raw SQL APIs, and `Html.Raw`). Every file path and line number cited was verified against the code at review time.

**Limitations:**
- The application targets **.NET Framework 4.8 (Windows-only)** and could not be built or run in the analysis environment (Linux), so **no dynamic testing** (DAST), runtime instrumentation, or deployed-configuration testing was performed.
- The repository contains **no automated tests**, so behavior was inferred from source only.
- No live AWS environment was assessed; infrastructure findings are based on the CDK source, not on a deployed stack's effective configuration.
- Dependency findings are **process recommendations**; no specific CVEs were asserted or validated. A software composition analysis (SCA) tool should be run to enumerate concrete vulnerable versions.
- Line numbers reflect the reviewed state of the files and may shift as the code changes.
