# Business Logic Playbook — Testing for Logic Flaws

## Why This Matters
Business logic flaws pay $5K-$50K because:
- No scanner finds them
- They require understanding the application
- Impact is always real (money, data, access)
- Very few hunters test for them (low competition)

## Test Categories

### 1. Price/Payment Manipulation
```
Test: Can you change the price client-side?
- Intercept checkout → change price to $0.01
- Negative quantity → refund issued?
- Negative price → money added to balance?
- Integer overflow → price wraps to $0?
- Currency confusion → pay in low-value currency, receive in high-value?
- Apply discount code after checkout started
- Apply multiple discount codes
- Remove items after discount applied → discount stays on remaining items?
```

### 2. Coupon/Promo Abuse
```
Test: Can you use a code more than once?
- Race condition: send 20 parallel redemption requests
- Apply code → remove from cart → re-apply
- Transfer code between accounts
- Modify coupon value in request
- Stack multiple coupons (if UI prevents, try API directly)
- Use expired codes (change date in request)
- Create coupon via mass assignment (POST with code field)
```

### 3. Subscription/Tier Bypass
```
Test: Can a free user access paid features?
- Request paid API endpoints with free account token
- Modify subscription field in profile update
- Cancel subscription → still have access?
- Downgrade → features persist?
- Free trial → change trial_end date in request
- Create second free trial with same payment method
```

### 4. Workflow Skip
```
Test: Can you skip required steps?
- Email verification: access app without verifying email
- MFA setup: skip MFA enrollment, still authenticate
- Terms of service: skip agreement, still use app
- Payment: access paid content without completing payment
- Onboarding: skip profile setup, access all features
- Approval: submit without manager approval (direct API call)
```

### 5. Rate Limit Bypass
```
Test: Is there any sensitive operation without rate limiting?
- OTP brute force: try 0000-9999 on /verify-otp
- Password reset: send 1000 reset emails to victim
- Login: brute force credentials
- API key generation: create unlimited keys
- Invite codes: generate unlimited invites

Bypass techniques:
- Add X-Forwarded-For: {random_ip} header
- Change User-Agent between requests
- Use HTTP/2 multiplexing (single-packet attack)
- Alternate between /api/v1/ and /api/v2/
- URL encode: /api/login vs /api/log%69n
```

### 6. Access Control Gaps
```
Test: Does the app check permissions on EVERY operation?
- User A creates resource → User B modifies/deletes it
- Delete own account → still have API access?
- Remove user from team → can still access team resources?
- Revoked API key → still works?
- Changed password → old sessions still valid?
- Disabled account → API tokens still work?
```

### 7. Data Integrity
```
Test: Can you create inconsistent state?
- Transfer $50 from Account A to B → race condition → $50 duplicated
- Vote twice in same poll (parallel requests)
- Follow yourself
- Send message to yourself (may trigger different code path)
- Create circular references (user A is admin of B, B is admin of A)
- Modify read-only fields via API (id, created_at, owner_id)
```

### 8. Information Disclosure via Error Messages
```
Test: Do errors leak internal data?
- Send invalid data types → stack trace with internal paths
- Request non-existent user → "user not found" vs "invalid credentials"
- Invalid API version → version list disclosure
- Malformed JSON → parser name and version
- SQL syntax error → database type and query structure
```

## Methodology: How to Find Business Logic Bugs
1. **Use the app normally for 30 minutes** — understand every feature
2. **Draw the workflow** — registration → verification → login → action
3. **Question every assumption** — "who verifies this?" "what if step 3 is skipped?"
4. **Test boundaries** — min/max values, empty strings, null, special chars
5. **Test state transitions** — what happens between steps? Can you go backward?
6. **Compare roles** — same endpoint, different users, different permissions?
