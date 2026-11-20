from dataclasses import dataclass, field
from enum import Enum


class WardMode(str, Enum):
    BLOCK_MODE = "BLOCK_MODE"      # ตรวจพบการโจมตี -> บล็อกทันที (HTTP 403) + บันทึก Log
    MONITOR_MODE = "MONITOR_MODE"  # ตรวจพบการโจมตี -> ปล่อยผ่าน + บันทึก Log แจ้งเตือน


@dataclass
class WardConfig:
    """Configuration สำหรับควบคุมการทำงานของ PyWard RASP Middleware"""

    mode: WardMode = WardMode.BLOCK_MODE
    log_file: str | None = "pyward_security.jsonl"
    console_log: bool = True

    # ระบบ Whitelist / Exclusions เพื่อลด False Positive
    excluded_paths: list[str] = field(default_factory=lambda: ["/docs", "/openapi.json", "/health"])
    excluded_fields: list[str] = field(default_factory=list)  # เช่น ["$.article.html_content"]

    # การตั้งค่าการตอบกลับเมื่อบล็อกทราฟฟิก
    block_status_code: int = 403
    block_message: str = "Request blocked by PyWard RASP due to security policy violation."

    # รายชื่อ Field ต้องห้ามสำหรับ Mass Assignment Guard (ใช้ในเฟส 3)
    restricted_fields: set[str] = field(
        default_factory=lambda: {
            "role",
            "roles",
            "is_admin",
            "is_superuser",
            "is_staff",
            "permissions",
            "account_balance",
            "verified",
        }
    )

    def __post_init__(self) -> None:
        if isinstance(self.mode, str):
            self.mode = WardMode(self.mode.upper())