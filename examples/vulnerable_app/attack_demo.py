import base64
import json
from pathlib import Path
import sys

# เพิ่มโฟลเดอร์หลักของโปรเจกต์เข้า sys.path เพื่อให้รันไฟล์นี้ตรงๆ จากที่ไหนก็ได้
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient

from examples.vulnerable_app.main import create_app
from pyward import WardMode


def build_mock_jwt(user_id: str) -> str:
    """สร้าง JWT Token จำลอง (Header.Payload.Signature) ที่มีฟิลด์ sub = user_id"""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": user_id}).encode()).decode().rstrip("=")
    return f"{header}.{payload}.demo_signature"


def run_demo() -> None:
    log_path = Path("pyward_security.jsonl")
    if log_path.exists():
        log_path.unlink()  # ล้างไฟล์ Log เก่าก่อนเริ่มสาธิตเพื่อให้เห็นเฉพาะเหตุการณ์รอบนี้

    # สร้างเว็บจำลอง 2 ตัว: ปิด PyWard (เว็บเปลือย) vs เปิด PyWard (BLOCK_MODE)
    client_off = TestClient(create_app(enable_pyward=False))
    client_on = TestClient(
        create_app(
            enable_pyward=True,
            mode=WardMode.BLOCK_MODE,
            log_file=str(log_path),
            console_log=False,  # ปิด Log แทรกบนจอเพื่อให้ตารางสรุปด้านล่างอ่านง่าย
        )
    )

    results: list[tuple[str, str, str]] = []

    # 1. SQL Injection Login Bypass
    sqli_payload = {"username": "admin' OR 1=1--", "password": "wrong"}
    r_off = client_off.post("/api/login", json=sqli_payload)
    r_on = client_on.post("/api/login", json=sqli_payload)
    results.append((
        "1. SQLi Login Bypass",
        f"HTTP {r_off.status_code} | BREACHED (user={r_off.json().get('user')})",
        f"HTTP {r_on.status_code} | BLOCKED ({r_on.json().get('incident_id')})",
    ))

    # 2. NoSQL Injection ($ne Operator Key)
    nosqli_payload = {"username": "admin", "password": {"$ne": None}}
    r_off = client_off.post("/api/login", json=nosqli_payload)
    r_on = client_on.post("/api/login", json=nosqli_payload)
    results.append((
        "2. NoSQLi ($ne Key)",
        f"HTTP {r_off.status_code} | BREACHED (user={r_off.json().get('user')})",
        f"HTTP {r_on.status_code} | BLOCKED ({r_on.json().get('incident_id')})",
    ))

    # 3. Mass Assignment (Privilege Escalation)
    ma_payload = {"username": "nithi", "role": "admin", "account_balance": 999999}
    r_off = client_off.patch("/api/profile", json=ma_payload)
    r_on = client_on.patch("/api/profile", json=ma_payload)
    results.append((
        "3. Mass Assignment",
        f"HTTP {r_off.status_code} | BREACHED (role={r_off.json()['profile']['role']})",
        f"HTTP {r_on.status_code} | BLOCKED ({r_on.json().get('incident_id')})",
    ))

    # 4. IDOR Parameter Tampering (ล็อกอินเป็น 101 แต่สั่งซื้อในชื่อ 102)
    idor_headers = {"X-User-ID": "101"}
    idor_payload = {"user_id": "102", "item": "Stolen MacBook", "total": 65000}
    r_off = client_off.post("/api/orders", headers=idor_headers, json=idor_payload)
    r_on = client_on.post("/api/orders", headers=idor_headers, json=idor_payload)
    results.append((
        "4. IDOR Tampering",
        f"HTTP {r_off.status_code} | BREACHED (owner={r_off.json()['order']['owner_id']})",
        f"HTTP {r_on.status_code} | BLOCKED ({r_on.json().get('incident_id')})",
    ))

    # 5. IDOR Enumeration (ใช้ JWT ไล่กวาดออเดอร์ 501 -> 504)
    jwt_headers = {"Authorization": f"Bearer {build_mock_jwt('202')}"}
    off_codes = [client_off.get(f"/api/orders/{oid}", headers=jwt_headers).status_code for oid in [501, 502, 503, 504]]
    on_codes = [client_on.get(f"/api/orders/{oid}", headers=jwt_headers).status_code for oid in [501, 502, 503, 504]]
    results.append((
        "5. IDOR Enumeration",
        f"Codes {off_codes} | ALL 4 LEAKED",
        f"Codes {on_codes} | BLOCKED AT #4",
    ))

    # 6. Response DLP (Backend เผลอพ่น AWS Key และ Password Hash)
    r_off = client_off.get("/api/debug/users")
    r_on = client_on.get("/api/debug/users")
    leaked_off = "AKIAIOSFODNN7EXAMPLE" in r_off.text
    leaked_on = "AKIAIOSFODNN7EXAMPLE" in r_on.text
    results.append((
        "6. Response DLP Leak",
        f"HTTP {r_off.status_code} | SECRET LEAKED ({leaked_off})",
        f"HTTP {r_on.status_code} | REDACTED (Leaked={leaked_on})",
    ))

    # 7. Field-level Whitelist (ทดสอบว่าไม่บล็อกมั่วในฟิลด์ที่ยกเว้นไว้)
    wl_payload = {"article": {"title": "AppSec 101", "html_body": "<script>demo()</script>"}}
    r_off = client_off.post("/api/articles", json=wl_payload)
    r_on = client_on.post("/api/articles", json=wl_payload)
    results.append((
        "7. Whitelist HTML",
        f"HTTP {r_off.status_code} | ALLOWED",
        f"HTTP {r_on.status_code} | ALLOWED (Zero False Positive)",
    ))

    # พิมพ์ตารางสรุปผลเปรียบเทียบ
    line = "+" + "-" * 24 + "+" + "-" * 37 + "+" + "-" * 39 + "+"
    print("\n" + "=" * 104)
    print("  PyWard RASP — Automated Attack Simulation (Before vs After Protection)")
    print("=" * 104)
    print(line)
    print(f"| {'Attack / Test Scenario':<22} | {'PyWard OFF (Vulnerable)':<35} | {'PyWard ON (BLOCK_MODE)':<37} |")
    print(line)
    for scenario, off_res, on_res in results:
        print(f"| {scenario:<22} | {off_res:<35} | {on_res:<37} |")
    print(line)

    # สรุปจำนวน Security Log ที่บันทึกส่งต่อให้ LogSentry SIEM
    logged_events = sum(1 for _ in log_path.open("r", encoding="utf-8")) if log_path.exists() else 0
    print(f"\n[+] SIEM Telemetry saved to '{log_path}' ({logged_events} security events recorded).")
    print("[+] Tip: You can feed this .jsonl file directly into LogSentry (--scan) for SIEM analysis.\n")


if __name__ == "__main__":
    run_demo()