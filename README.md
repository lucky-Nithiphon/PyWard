<div align="center">

# 🛡️ PyWard
### Context-Aware Runtime Application Self-Protection (RASP) for Python

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-ASGI_Middleware-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Tests](https://img.shields.io/badge/Pytest-13_Passed-2EA44F?style=for-the-badge&logo=pytest&logoColor=white)
![Version](https://img.shields.io/badge/Release-v1.0.0-2EA44F?style=for-the-badge)

**PyWard** เป็นไลบรารีด้านความปลอดภัยระดับแอปพลิเคชัน (**Runtime Application Self-Protection — RASP**) สำหรับ **FastAPI / Starlette** พัฒนาในระดับ Pure ASGI Middleware เพื่อฝังตัวทำงานร่วมกับโค้ด Backend โดยตรง คอยตรวจสอบบริบทเชิงลึกของข้อมูล (Context-Aware Inspection) ป้องกันช่องโหว่ระดับ Business Logic และส่งออก Security Telemetry ไปวิเคราะห์ต่อในระบบ SIEM

</div>

---

## 💡 ทำไมถึงทำโปรเจกต์นี้ (Background & Learning Goal)

โปรเจกต์นี้ผมตั้งใจเขียนขึ้นมาเพื่อ **ศึกษาและทำความเข้าใจการทำงานเบื้องหลังของระบบ RASP และงานสาย Application Security (AppSec) แบบลงมือทำจริง** ครับ

หลังจากที่ได้สร้างระบบวิเคราะห์ Log ย้อนหลัง (**LogSentry**) ไปแล้ว ผมอยากขยับเข้ามาดูกลไกการป้องกันจาก **"ข้างในตัวแอปพลิเคชัน"** เพื่อพิสูจน์ให้เห็นภาพชัดๆ ว่าทำไมการมีแค่ WAF หน้าบ้านอย่างเดียวถึงยังไม่พอ ช่วงที่พัฒนาจึงลองออกแบบโครงสร้าง Python Library ขึ้นมาเอง ตั้งแต่การดักจับ ASGI Stream Replay โดยไม่ให้กระทบ FastAPI ไปจนถึงการจำลองเว็บที่มีช่องโหว่จริงแล้วยิงทดสอบเทียบก่อน-หลังเปิดใช้งาน (Nested JSON Injection, Mass Assignment, IDOR และ Response DLP) พร้อมเขียนชุดทดสอบอัตโนมัติด้วย `pytest` เพื่อคุมคุณภาพไม่ให้เกิด False Positive ครับ

> **หมายเหตุ:** โปรเจกต์นี้จัดทำขึ้นเพื่อการศึกษา วิจัย และใช้ทดสอบในสภาพแวดล้อมจำลอง (Lab) เท่านั้นครับ

---

## 🏗️ Defense-in-Depth Ecosystem

**PyWard** เป็นชั้นป้องกันระดับ Runtime ภายใต้สถาปัตยกรรม **Defense-in-Depth** ที่แบ่งหน้าที่ทำงานประสานกัน 3 ชั้น:

```text
                        [ Internet / Attacker ]
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  1. EdgeGuard WAF (Go Reverse Proxy)                                │
│     • Inline Traffic Filtering, Rate Limiting & Fast-Path Blocking  │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  2. PyWard RASP (Python ASGI Middleware) ◀── [ CURRENT REPOSITORY ] │
│     • Deep JSON Inspection, Session/IDOR Guard & Response DLP       │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                   [ Structured JSON Telemetry (.jsonl) ]
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  3. LogSentry (Java Out-of-Band Mini-SIEM)                          │
│     • Log Correlation, MITRE ATT&CK Mapping & Incident Forensics    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🧠 จุดแข็งของ PyWard RASP ที่ปิดจุดบอดของ WAF หน้าบ้าน

| มิติการตรวจสอบ | Perimeter WAF (ด่านหน้า) | PyWard RASP (ภายในแอป) |
| :--- | :--- | :--- |
| **การแกะโครงสร้างข้อมูล** | มองเห็น Request เป็นข้อความดิบ หากซ่อนใน Nested JSON หรือเข้ารหัสหลายชั้นอาจหลุดรอดได้ | แตก Nested JSON และ Array เป็นพิกัด `JSONPath` พร้อมถอดรหัส Obfuscation หลายชั้น (`PayloadNormalizer`) |
| **ตัวตนและสิทธิ์ผู้ใช้** | ไม่รู้จัก Session หรือสิทธิ์ในแอปพลิเคชัน | แกะตัวตนจาก JWT (`Authorization: Bearer`) / `X-User-ID` เพื่อตรวจจับ **IDOR** และ **Mass Assignment** |
| **การลด False Positive** | มักบล็อกทั้ง Request หากเจออักขระพิเศษ | รองรับ **Path Whitelist** และ **Field-level Whitelist** (ยกเว้นเฉพาะฟิลด์ที่กำหนดได้ เช่น `$.article.html_body`) |
| **ข้อมูลรั่วไหลขาออก (DLP)** | เน้นกรองทราฟฟิกขาเข้าเป็นหลัก | ดักจับ HTTP Response ขาออก สกัด Stack Trace, Database Error, Secret Keys และ `password_hash` ก่อนหลุด |

---

## ⚙️ Internal Pipeline Architecture

```text
Incoming HTTP Request
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Pure ASGI Middleware (Stream Buffering & Replay)         │
│    • ตรวจสอบ Path Whitelist & สกัด user_id (JWT / Header)    │
│    • บัฟเฟอร์ Request Body และทำ Stream Replay คืนให้ FastAPI │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. PayloadNormalizer & Recursive JSONPath Parser            │
│    • ถอดรหัส URL, HTML Entities, Unicode/Hex & Null Bytes   │
│    • แตก Nested JSON / Array เป็นคู่ (JSONPath, Key, Value)  │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Ingress Guard Chain (Chain of Responsibility)            │
│    ├── InjectionGuard      (SQLi, XSS, NoSQLi Key/Val, CMDi)│
│    ├── MassAssignmentGuard (Case/Unicode Privileged Fields) │
│    └── IdorGuard           (Session Mismatch & Sliding Win) │
└───────────────────────────┬─────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
       [ Threat Detected ]       [ FastAPI Endpoint ]
                │                       │
                ▼                       ▼
      • Log (.jsonl + Pretty)   ┌─────────────────────────────┐
      • BLOCK_MODE   -> 403     │ 4. Egress ResponseDlpGuard  │
      • MONITOR_MODE -> Pass    │ • จับ Stack Trace / Secrets │
                                │ • Redact -> Safe HTTP 500   │
                                └─────────────────────────────┘
```

---

## 🧪 Automated Attack Simulation (Before vs. After)

รันสคริปต์สาธิต `examples/vulnerable_app/attack_demo.py` เพื่อทดสอบยิงโจมตีเว็บ FastAPI ที่มีช่องโหว่จริงเปรียบเทียบระหว่าง **ปิด** กับ **เปิด** `PyWard`:

```powershell
python examples/vulnerable_app/attack_demo.py
```

ผลลัพธ์จริงจากการทดสอบทั้ง 7 สถานการณ์:

```text
========================================================================================================
  PyWard RASP — Automated Attack Simulation (Before vs After Protection)
========================================================================================================
+------------------------+-------------------------------------+---------------------------------------+
| Attack / Test Scenario | PyWard OFF (Vulnerable)             | PyWard ON (BLOCK_MODE)                |
+------------------------+-------------------------------------+---------------------------------------+
| 1. SQLi Login Bypass   | HTTP 200 | BREACHED (user=admin)    | HTTP 403 | BLOCKED (pw-37164923)      |
| 2. NoSQLi ($ne Key)    | HTTP 200 | BREACHED (user=admin)    | HTTP 403 | BLOCKED (pw-05eea852)      |
| 3. Mass Assignment     | HTTP 200 | BREACHED (role=admin)    | HTTP 403 | BLOCKED (pw-216000f9)      |
| 4. IDOR Tampering      | HTTP 200 | BREACHED (owner=102)     | HTTP 403 | BLOCKED (pw-933b1c3f)      |
| 5. IDOR Enumeration    | Codes [200, 200, 200, 200] | ALL 4 LEAKED | Codes [200, 200, 200, 403] | BLOCKED AT #4 |
| 6. Response DLP Leak   | HTTP 200 | SECRET LEAKED (True)     | HTTP 500 | REDACTED (Leaked=False)    |
| 7. Whitelist HTML      | HTTP 200 | ALLOWED                  | HTTP 200 | ALLOWED (Zero False Positive) |
+------------------------+-------------------------------------+---------------------------------------+
```

---

## 🚀 Quick Start (วิธีติดตั้ง ใช้งาน และทดสอบ)

### 1. ติดตั้งแพ็กเกจ (Editable Install)
```powershell
pip install -e ".[dev]"
```

### 2. การนำไปครอบใช้งานกับ FastAPI (Plug-and-Play)
```python
from fastapi import FastAPI
from pyward import PyWardMiddleware, WardConfig, WardMode

app = FastAPI()

app.add_middleware(
    PyWardMiddleware,
    config=WardConfig(
        mode=WardMode.BLOCK_MODE,             # หรือ WardMode.MONITOR_MODE
        log_file="pyward_security.jsonl",     # ส่งต่อให้ LogSentry วิเคราะห์ได้ทันที
        console_format="pretty",              # "pretty" (คนอ่านง่าย) หรือ "json" (Docker/Cloud)
        excluded_paths=["/docs", "/health"],
        excluded_fields=["$.article.html_body"],
    ),
)

@app.post("/api/profile")
async def update_profile(payload: dict):
    return {"status": "updated", "data": payload}
```

### 3. รันเว็บตัวอย่างจริงด้วย Uvicorn (พร้อมเป็น Backend ให้ WAF)
```powershell
python -m uvicorn examples.vulnerable_app.main:app --reload
```

### 4. รันชุดทดสอบอัตโนมัติ (Automated Security Tests)
```powershell
python -m pytest -v
```
ครอบคลุม 13 Test Cases ทั้งระดับ Unit และ Integration (Multi-layer Normalization, Nested JSONPath, SQLi/XSS/NoSQLi/CMDi, Stream Replay, False Positive Check, Mass Assignment, IDOR Velocity, Response DLP และ Monitor Mode)

---

## 📊 Security Telemetry (Console & SIEM JSON)

* **Human-Readable Console Output (`console_format="pretty"`):**
  ```text
  [PyWard | BLOCKED] SQL_INJECTION (PYWARD-SQLI-001)
    |- Request : POST /api/submit (IP: 127.0.0.1)
    |- Target  : JSON_BODY -> $.user.name
    |- Detail  : SQL injection pattern matched at '$.user.name'
    \_ Meta    : HTTP 403 | 110 us | ID: pw-b09167cd
  ```
* **Machine-Readable SIEM Log (`pyward_security.jsonl` — รองรับ `JsonLogParser` ของ LogSentry):**
  ```json
  {"client_ip": "127.0.0.1", "method": "POST", "path": "/api/submit", "inspection_vector": "JSON_BODY", "attack_type": "MASS_ASSIGNMENT", "rule_id": "PYWARD-MA-001", "action": "BLOCKED", "status_code": 403, "latency_us": 95, "json_path": "$.role", "detail": "Unauthorized privileged field 'role' detected in PATCH payload at '$.role'", "source": "pyward-rasp", "event_id": "pw-216000f9", "timestamp": "2026-11-25T14:00:00+07:00"}
  ```

---

## 📂 Project Structure

```text
PyWard/
├── pyproject.toml                   # Package metadata, dependencies & pytest config
├── README.md                        # เอกสารภาพรวมสถาปัตยกรรมและคู่มือการใช้งาน
├── src/pyward/
│   ├── __init__.py                  # Public API exports (PyWardMiddleware, WardConfig, WardMode)
│   ├── config.py                    # การตั้งค่า Dual-Mode, Path/Field Whitelist & Restricted Fields
│   ├── middleware/
│   │   └── asgi.py                  # Pure ASGI Middleware (Ingress Stream Replay & Egress Intercept)
│   ├── core/
│   │   ├── normalizer.py            # Multi-layer Anti-Obfuscation Decoder (URL/HTML/Unicode/Hex)
│   │   └── parser.py                # Recursive Nested JSON & Query Parameter JSONPath Parser
│   ├── guards/
│   │   ├── base.py                  # BaseGuard Interface, InspectionContext & GuardFinding
│   │   ├── injection.py             # SQLi, XSS, NoSQLi (Key & Value) & OS Command Injection Guard
│   │   ├── mass_assignment.py       # Privileged Field Escalation Guard (Case/Unicode Safe)
│   │   ├── idor.py                  # Session Mismatch & Sliding-Window Enumeration Guard
│   │   └── response_dlp.py          # Egress Stack Trace, DB Error, Secret Key & Credential Guard
│   └── telemetry/
│       └── logger.py                # Dual-Output Security Logger (Pretty Console + SIEM .jsonl)
├── examples/vulnerable_app/
│   ├── main.py                      # Vulnerable FastAPI Demo App (Toggleable PyWard RASP)
│   └── attack_demo.py               # Automated Before-vs-After Attack Simulation Script
└── tests/
    └── test_pyward.py               # Automated Security & Anti-False-Positive Suite (13 pytest cases)
```

---

## 📜 Version History (Changelog)

* **`v1.0.0` — Portfolio Readiness & Automated Security Suite (Final Release)**
  * สร้างเว็บแอป FastAPI ตัวอย่างที่มีช่องโหว่จริง (`examples/vulnerable_app/main.py`) พร้อมสวิตช์เปิด/ปิด PyWard
  * สร้างสคริปต์จำลองการโจมตีเปรียบเทียบผลลัพธ์ก่อน-หลังป้องกัน (`attack_demo.py`) ครบ 7 สถานการณ์
  * เขียนชุดทดสอบอัตโนมัติด้วย `pytest` (`tests/test_pyward.py`) ผ่านครบ 13 Test Cases ทั้ง True Positive และ False Positive
* **`v0.4.0` — Business Logic & Response DLP Guards**
  * เพิ่ม `MassAssignmentGuard` ป้องกันการแอบยัดฟิลด์สิทธิ์ต้องห้าม (รองรับ Case/Unicode Bypass)
  * เพิ่ม `IdorGuard` ตรวจจับ Session Mismatch (แกะ JWT/Header) และการไล่กวาด ID ด้วย Sliding Time Window
  * เพิ่ม `ResponseDlpGuard` ตรวจสอบ HTTP Response ขาออก สกัด Stack Trace, DB Error, AWS Keys และ `password_hash`
* **`v0.3.0` — Deep Context-Aware Injection Guard & Pretty Console**
  * สร้างพิมพ์เขียว `BaseGuard` และ `InjectionGuard` ตรวจจับ SQLi, XSS, NoSQLi และ Command Injection พร้อม Field-level Whitelist
  * อัปเกรด `SecurityLogger` แยกรูปแบบ Pretty Format บนหน้าจอ และ JSON มาตรฐานลงไฟล์ `.jsonl`
* **`v0.2.0` — Normalization & Recursive JSONPath Parser**
  * พัฒนา `PayloadNormalizer` ถอดรหัส Obfuscation หลายชั้นโดยไม่กระทบภาษาไทย และ `RequestParser` แตก Nested JSON/Array เป็นพิกัด `JSONPath`
* **`v0.1.0` — Core Scaffold & Pure ASGI Middleware**
  * วางโครงสร้าง Python Package (`pyproject.toml`), `WardConfig`, `PyWardMiddleware` พร้อมกลไก Stream Replay และ SIEM JSON Telemetry