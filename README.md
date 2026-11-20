<div align="center">

# 🛡️ PyWard
### Context-Aware Runtime Application Self-Protection (RASP) for Python

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-ASGI_Middleware-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Security](https://img.shields.io/badge/AppSec-RASP_Engine-B80000?style=for-the-badge)
![Version](https://img.shields.io/badge/Release-v0.1.0-2EA44F?style=for-the-badge)

**PyWard** เป็นไลบรารีด้านความปลอดภัยระดับแอปพลิเคชัน (**Runtime Application Self-Protection — RASP**) สำหรับ **FastAPI / Starlette** ออกแบบมาเพื่อฝังตัวทำงานร่วมกับโค้ด Backend โดยตรง คอยตรวจสอบบริบทเชิงลึกของข้อมูล (Context-Aware Inspection) ป้องกันช่องโหว่ระดับ Business Logic และส่งออก Security Telemetry ไปวิเคราะห์ต่อในระบบ SIEM

</div>

---

## 💡 ทำไมถึงทำโปรเจกต์นี้ (Background & Learning Goal)

โปรเจกต์นี้ผมตั้งใจเขียนขึ้นมาเพื่อ **ศึกษาและทำความเข้าใจการทำงานเบื้องหลังของระบบ RASP และงานสาย Application Security (AppSec) แบบลงมือทำจริง** ครับ

หลังจากที่ได้ลองสร้างระบบวิเคราะห์ Log ย้อนหลัง (**LogSentry**) ไปแล้ว ผมอยากขยับเข้ามาดูกลไกการป้องกันจาก **"ข้างในตัวแอปพลิเคชัน"** บ้าง เพื่อพิสูจน์ให้เห็นภาพชัดๆ ว่าทำไมการมีแค่ WAF หน้าบ้านอย่างเดียวถึงยังไม่พอ ช่วงที่พัฒนาผมจึงออกแบบโครงสร้าง Python Library ขึ้นมาเอง ตั้งแต่การดักจับ ASGI Stream โดยไม่ให้กระทบการทำงานของ FastAPI ไปจนถึงการจำลองช่องโหว่จริงแล้วลองยิงเทสเองทีละท่า (เช่น การซ่อน Payload ใน JSON หลายชั้น, การแอบแก้สิทธิ์ User หรือการไล่กวาด ID) เพื่อดูว่าหลุดตรงไหนแล้วค่อยๆ สร้าง Guard เข้ามาอุดช่องโหว่ทีละจุดครับ

> **หมายเหตุ:** โปรเจกต์นี้จัดทำขึ้นเพื่อการศึกษา วิจัย และใช้ทดสอบในสภาพแวดล้อมจำลอง (Lab) ส่วนตัวเท่านั้นครับ

---

## 🏗️ Defense-in-Depth Ecosystem

**PyWard** เป็นส่วนหนึ่งของสถาปัตยกรรมป้องกันเชิงลึก (**Defense-in-Depth**) ที่แบ่งหน้าที่การป้องกันออกเป็น 3 ชั้น ทำงานประสานกันตั้งแต่หน้าด่านเครือข่ายจนถึงการวิเคราะห์ย้อนหลัง:

```text
                        [ Internet / Attacker ]
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│  1. Perimeter WAF (Go Reverse Proxy)                                │
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

* **Perimeter WAF (Go):** ปราการด่านหน้าแบบ Inline Reverse Proxy คอยกรองทราฟฟิกขยะและโจมตีพื้นฐานด้วยความเร็วสูงก่อนถึงตัวแอป
* **PyWard RASP (Python — โปรเจกต์นี้):** บอดี้การ์ดที่ฝังตัวอยู่ในโค้ด Backend มองเห็นข้อมูลหลังผ่านการถอดรหัสและผูกกับ Session ผู้ใช้แล้ว
* **LogSentry (Java):** ศูนย์วิเคราะห์ Log แบบ Out-of-Band คอยรวบรวมเหตุการณ์จากทุกชั้นมาทำ Correlation แกะรอยไทม์ไลน์ผู้โจมตี และออกรายงาน Forensics

---

## 🧠 ทำไม RASP ถึงจัดการจุดบอดของ WAF หน้าบ้านได้?

| มิติการตรวจสอบ | Perimeter WAF (ด่านหน้า) | PyWard RASP (ภายในแอป) |
| :--- | :--- | :--- |
| **การแกะโครงสร้างข้อมูล** | มองเห็น HTTP Request เป็นก้อน Text ดิบๆ หากซ่อนใน Nested JSON หรือเข้ารหัสหลายชั้นอาจหลุดรอดได้ | แตกโครงสร้าง JSON ออกมาทีละฟิลด์ (`JSONPath`) พร้อมถอดรหัส Obfuscation ก่อนส่งให้ Endpoint |
| **ตัวตนและสิทธิ์ผู้ใช้** | ไม่รู้ว่า Request นี้มาจาก `user_id` ไหน หรือกำลังแอบแก้ข้อมูลข้ามสิทธิ์หรือไม่ | ผูกกับ Request Context ของแอป ตรวจจับ **IDOR** และ **Mass Assignment** (`"role": "admin"`) ได้แม่นยำ |
| **การลด False Positive** | มักบล็อกทั้ง Request หากเจออักขระพิเศษในฟิลด์ที่ไม่ควรบล็อก | ทำ **Field-level Whitelist** ได้ (เช่น ยกเว้นฟิลด์บทความ HTML แต่ยังตรวจเข้มฟิลด์อื่นใน JSON เดียวกัน) |
| **ข้อมูลรั่วไหลขาออก (DLP)** | เน้นตรวจขาเข้าเป็นหลัก | ดักจับ HTTP Response ขาออก ป้องกัน Backend เผลอพ่น Database Stack Trace หรือ Secret Key หลุด |

---

## ⚙️ Internal Pipeline Architecture

```text
Incoming HTTP Request
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│ 1. Pure ASGI Middleware (Stream Buffering & Replay)       │
│    • ตรวจสอบ Path Whitelist (/docs, /health)              │
│    • ก๊อปปี้ Request Body เก็บไว้ตรวจโดยไม่ทำให้ FastAPI ค้าง  │
└───────────────────────────┬───────────────────────────────┘
                            │
                            ▼
┌───────────────────────────────────────────────────────────┐
│ 2. Normalization & JSONPath Flattener (v0.2.0)            │
│    • ถอดรหัส URL, Unicode Escapes, HTML Entities           │
│    • แตก Nested JSON เป็นคู่ (JSONPath, Value)            │
└───────────────────────────┬───────────────────────────────┘
                            │
                            ▼
┌───────────────────────────────────────────────────────────┐
│ 3. Security Guard Engines (v0.3.0 - v0.4.0)               │
│    ├── InjectionGuard      (SQLi, XSS, NoSQLi, CMDi)      │
│    ├── MassAssignmentGuard (Restricted Fields Escalation) │
│    ├── IdorGuard           (Session Mismatch & Velocity)  │
│    └── ResponseDlpGuard    (Egress Stack Trace / Secrets) │
└───────────────────────────┬───────────────────────────────┘
                            │
               ┌────────────┴────────────┐
               ▼                         ▼
      [ Threat Detected ]         [ Clean Request ]
               │                         │
               ▼                         ▼
┌─────────────────────────┐   ┌─────────────────────────────┐
│ 4. Telemetry & Action   │   │ ส่งต่อ Stream เดิมให้ FastAPI │
│ • พ่น JSON Log ลง .jsonl │   │ ทำงานตาม Endpoint ปกติ       │
│ • BLOCK → HTTP 403      │   └─────────────────────────────┘
│ • MONITOR → ปล่อยผ่าน    │
└─────────────────────────┘
```

---

## 🚀 Quick Start (วิธีติดตั้งและเรียกใช้งาน)

### 1. ติดตั้งแพ็กเกจในโหมดพัฒนา (Editable Install)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

### 2. ตัวอย่างการนำไปครอบใช้งานกับ FastAPI
เพียง Import `PyWardMiddleware` และ `WardConfig` ไปครอบแอปพลิเคชันด้วยโค้ดไม่กี่บรรทัด:

```python
from fastapi import FastAPI
from pyward import PyWardMiddleware, WardConfig, WardMode

app = FastAPI()

# เปิดใช้งาน PyWard RASP (เลือกได้ระหว่าง BLOCK_MODE และ MONITOR_MODE)
app.add_middleware(
    PyWardMiddleware,
    config=WardConfig(
        mode=WardMode.BLOCK_MODE,
        log_file="pyward_security.jsonl",
        excluded_paths=["/docs", "/openapi.json", "/health"],
    ),
)

@app.post("/api/profile")
async def update_profile(payload: dict):
    return {"status": "updated", "data": payload}
```

### 3. ตัวอย่าง Structured Security Log (รองรับการส่งต่อให้ LogSentry)
เมื่อตรวจพบความผิดปกติ `PyWard` จะบันทึกเหตุการณ์เป็น JSON 1 บรรทัดต่อ 1 เหตุการณ์ (`.jsonl`) ตาม Schema ที่พร้อมส่งต่อให้ `JsonLogParser` ของ **LogSentry** วิเคราะห์ต่อทันที:

```json
{
  "client_ip": "127.0.0.1",
  "method": "POST",
  "path": "/api/profile",
  "inspection_vector": "JSON_BODY",
  "attack_type": "MASS_ASSIGNMENT",
  "rule_id": "PYWARD-MA-001",
  "action": "BLOCKED",
  "status_code": 403,
  "latency_us": 190,
  "json_path": "$.user.role",
  "detail": "Restricted field 'role' detected in payload",
  "source": "pyward-rasp",
  "event_id": "pw-8f91c2a0",
  "timestamp": "2026-11-21T01:15:00+07:00"
}
```

---

## 📂 Project Structure

```text
PyWard/
├── pyproject.toml                   # Package metadata, dependencies & pytest config
├── README.md                        # เอกสารภาพรวมสถาปัตยกรรมและคู่มือการใช้งาน
├── src/
│   └── pyward/
│       ├── __init__.py              # Public API exports (PyWardMiddleware, WardConfig, WardMode)
│       ├── config.py                # ระบบตั้งค่าโหมดการทำงาน (BLOCK/MONITOR) และ Whitelist Rules
│       ├── middleware/
│       │   ├── __init__.py
│       │   └── asgi.py              # Pure ASGI Middleware พร้อมกลไก Request Body Stream Replay
│       ├── core/                    # [v0.2.0] ตัวถอดรหัส Obfuscation และตัวแกะ Nested JSONPath
│       ├── guards/                  # [v0.3.0-v0.4.0] กฎตรวจจับ Injection, IDOR, Mass Assignment, DLP
│       └── telemetry/
│           ├── __init__.py
│           └── logger.py            # Structured JSON SIEM Logger (LogSentry compatible)
├── examples/
│   └── vulnerable_app/              # [v1.0.0] เว็บแอปตัวอย่างที่มีช่องโหว่และสคริปต์ทดสอบเจาะ
└── tests/                           # [v1.0.0] ชุดทดสอบอัตโนมัติด้วย pytest
```

---

## 📈 Version History & Development Roadmap

### ✅ Completed Versions
* **`v0.1.0` — Core Scaffold, Pure ASGI Middleware & SIEM Telemetry (Phase 1)**
  * วางโครงสร้าง Python Package มาตรฐาน (`src/pyward/` + `pyproject.toml`) ที่ติดตั้งผ่าน `pip` ได้จริง
  * สร้างระบบตั้งค่า `WardConfig` รองรับการสลับโหมด **`BLOCK_MODE`** และ **`MONITOR_MODE`** พร้อมระบบ Path Whitelist
  * พัฒนา `PyWardMiddleware` ระดับ **Pure ASGI** พร้อมกลไก **Stream Buffering & Replay** ทำให้ดักอ่าน Request Body ได้โดยไม่กระทบการทำงานของ FastAPI Endpoint
  * สร้าง `SecurityLogger` บันทึกเหตุการณ์ความปลอดภัยเป็นไฟล์ `.jsonl` ตาม Schema มาตรฐานที่เชื่อมต่อกับ **LogSentry** ได้ทันที

### 🚧 Upcoming Versions
* **`v0.2.0` — Normalization & Recursive JSONPath Parser (Phase 2 - In Progress)**
  * พัฒนา `Normalizer` ถอดรหัส Obfuscation หลายชั้น (URL Encoding, Unicode Escapes, HTML Entities)
  * พัฒนา `Recursive JSON Parser` แตกโครงสร้าง Nested JSON ที่ซ้อนกันหลายชั้นออกมาเป็นคู่ `(JSONPath, Value)`
* **`v0.3.0` — Deep Context-Aware Injection Guard (Phase 2)**
  * สร้าง `InjectionGuard` ตรวจจับ SQLi, XSS, NoSQL Injection (ตรวจทั้ง Key และ Value) และ OS Command Injection
  * เพิ่มระบบ **Field-level Whitelist** ยกเว้นบางฟิลด์ที่ต้องรับอักขระพิเศษตามปกติเพื่อลด False Positive
* **`v0.4.0` — Business Logic & Response DLP Guards (Phase 3)**
  * `MassAssignmentGuard`: บล็อกฟิลด์อ่อนไหวที่ไม่ได้รับอนุญาตใน Payload (เช่น `role`, `is_admin`, `account_balance`)
  * `IdorGuard`: ตรวจสอบความสอดคล้องของ `user_id` กับ Session/Token และจับพฤติกรรมการไล่กวาด ID รัวๆ (Enumeration Velocity)
  * `ResponseDlpGuard`: ตรวจสอบ HTTP Response ขาออก ป้องกันการหลุดของ Database Stack Trace และ Secret Keys
* **`v1.0.0` — Vulnerable Demo App & Automated Security Tests (Phase 4)**
  * สร้างเว็บ FastAPI ตัวอย่างที่มีช่องโหว่ครบทุกมิติ พร้อมสคริปต์ยิงทดสอบเปรียบเทียบก่อน-หลังเปิดใช้งาน `PyWard`
  * เขียนชุดทดสอบอัตโนมัติด้วย `pytest` ครอบคลุมทุก Attack Vector และ Edge Cases