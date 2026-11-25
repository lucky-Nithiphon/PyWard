import os
from typing import Any

from fastapi import FastAPI

from pyward import PyWardMiddleware, WardConfig, WardMode


def create_app(
    enable_pyward: bool = True,
    mode: WardMode = WardMode.BLOCK_MODE,
    log_file: str | None = "pyward_security.jsonl",
    console_log: bool = True,
) -> FastAPI:
    """
    App Factory สำหรับสร้างเว็บ FastAPI จำลองที่มีช่องโหว่
    สามารถสั่งเปิด/ปิด PyWard RASP ได้ผ่านพารามิเตอร์ enable_pyward เพื่อเปรียบเทียบผลลัพธ์
    """
    app = FastAPI(title="Vulnerable Demo Shop API (PyWard Showcase)")

    # ติดตั้ง PyWard RASP Middleware เพียง 1 คำสั่ง (Plug-and-Play)
    if enable_pyward:
        app.add_middleware(
            PyWardMiddleware,
            config=WardConfig(
                mode=mode,
                log_file=log_file,
                console_log=console_log,
                excluded_paths=["/health", "/docs", "/openapi.json"],
                excluded_fields=["$.article.html_body"],
            ),
        )

    # ฐานข้อมูลจำลองในหน่วยความจำ (In-Memory Mock Database)
    users_db: dict[str, dict[str, Any]] = {
        "101": {
            "user_id": "101",
            "username": "nithi",
            "role": "customer",
            "account_balance": 500,
            "password_hash": "$2b$12$nithiSecretHashValue999",
        },
        "102": {
            "user_id": "102",
            "username": "alice",
            "role": "vip",
            "account_balance": 25000,
            "password_hash": "$2b$12$aliceSecretHashValue888",
        },
    }

    orders_db: dict[int, dict[str, Any]] = {
        501: {"order_id": 501, "owner_id": "101", "item": "Mechanical Keyboard", "total": 2500},
        502: {"order_id": 502, "owner_id": "102", "item": "MacBook Pro", "total": 65000},
        503: {"order_id": 503, "owner_id": "102", "item": "Hardware Security Key", "total": 1800},
        504: {"order_id": 504, "owner_id": "102", "item": "Cloud GPU Credit", "total": 12000},
    }

    @app.get("/health")
    async def health_check() -> dict[str, str]:
        return {"status": "healthy", "pyward_enabled": str(enable_pyward)}

    # 1. ช่องโหว่ SQLi & NoSQLi: ตรวจสอบ Login แบบไม่ปลอดภัย
    @app.post("/api/login")
    async def vulnerable_login(payload: dict[str, Any]) -> dict[str, Any]:
        username = str(payload.get("username", ""))
        password = payload.get("password")

        is_sqli_bypass = "or 1=1" in username.lower()
        is_nosqli_bypass = isinstance(password, dict) and "$ne" in password

        if is_sqli_bypass or is_nosqli_bypass or (username == "nithi" and password == "pass123"):
            return {
                "status": "authenticated",
                "user": "admin" if (is_sqli_bypass or is_nosqli_bypass) else "nithi",
                "bypass_used": is_sqli_bypass or is_nosqli_bypass,
            }
        return {"status": "failed", "message": "Invalid credentials"}

    # 2. ช่องโหว่ Mass Assignment: นำทุกฟิลด์ใน JSON มาเขียนทับข้อมูลผู้ใช้ตรงๆ
    @app.patch("/api/profile")
    async def vulnerable_update_profile(payload: dict[str, Any]) -> dict[str, Any]:
        user = users_db["101"]
        user.update(payload)  # อันตราย! ถ้าส่ง {"role": "admin"} จะถูกแก้สิทธิ์ทันที
        return {
            "status": "updated",
            "profile": {
                "username": user["username"],
                "role": user["role"],
                "account_balance": user["account_balance"],
            },
        }

    # 3. ช่องโหว่ IDOR Parameter Tampering: เชื่อค่า user_id จาก JSON Body โดยไม่เทียบ Session
    @app.post("/api/orders")
    async def vulnerable_create_order(payload: dict[str, Any]) -> dict[str, Any]:
        new_id = max(orders_db.keys()) + 1
        order = {
            "order_id": new_id,
            "owner_id": str(payload.get("user_id", "101")),
            "item": payload.get("item", "Unknown Item"),
            "total": payload.get("total", 0),
        }
        orders_db[new_id] = order
        return {"status": "created", "order": order}

    # 4. ช่องโหว่ IDOR Enumeration: ดึงออเดอร์ตามเลข ID ได้ทันทีโดยไม่ตรวจเจ้าของ
    @app.get("/api/orders/{order_id}")
    async def vulnerable_get_order(order_id: int) -> dict[str, Any]:
        order = orders_db.get(order_id)
        if not order:
            return {"error": "Order not found"}
        return {"order": order}

    # 5. ช่องโหว่ Response DLP: เผลอพ่นฟิลด์ลับ (password_hash + AWS Key) หลุดออกไป
    @app.get("/api/debug/users")
    async def vulnerable_debug_dump() -> dict[str, Any]:
        return {
            "debug_aws_key": "AKIAIOSFODNN7EXAMPLE",
            "users": list(users_db.values()),
        }

    # 6. Endpoint ปกติสำหรับทดสอบ Field-level Whitelist (รับ HTML ใน $.article.html_body)
    @app.post("/api/articles")
    async def publish_article(payload: dict[str, Any]) -> dict[str, Any]:
        return {"status": "published", "article": payload.get("article", {})}

    return app


# อ่านค่าจาก Environment Variable เพื่อรองรับการรันจริงด้วยคำสั่ง uvicorn
_enable = os.getenv("PYWARD_ENABLED", "true").lower() == "true"
_mode = WardMode(os.getenv("PYWARD_MODE", "BLOCK_MODE").upper())
app = create_app(enable_pyward=_enable, mode=_mode)