from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import uuid


@dataclass
class SecurityEvent:
    """โครงสร้าง Structured JSON Log ที่รองรับการส่งต่อไปยัง LogSentry SIEM"""

    client_ip: str
    method: str
    path: str
    inspection_vector: str   # เช่น QUERY_PARAM, JSON_BODY, BUSINESS_LOGIC, RESPONSE_DLP
    attack_type: str         # เช่น SQL_INJECTION, MASS_ASSIGNMENT, IDOR_ATTEMPT
    rule_id: str             # เช่น PYWARD-SQLI-001
    action: str              # "BLOCKED" หรือ "MONITORED"
    status_code: int
    latency_us: int
    user_id: str | None = None
    json_path: str | None = None
    detail: str | None = None
    source: str = "pyward-rasp"
    event_id: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.event_id:
            self.event_id = f"pw-{uuid.uuid4().hex[:8]}"
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).astimezone().isoformat()

    def to_json(self) -> str:
        payload = {k: v for k, v in asdict(self).items() if v is not None}
        return json.dumps(payload, ensure_ascii=False)


class SecurityLogger:
    """จัดการเขียน Security Telemetry ลงไฟล์ .jsonl และ/หรือ stdout"""

    def __init__(self, log_file: str | None = None, console_log: bool = True) -> None:
        self.log_file = Path(log_file) if log_file else None
        self.console_log = console_log

    def log_event(self, event: SecurityEvent) -> None:
        serialized = event.to_json()

        if self.console_log:
            print(serialized)

        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(serialized + "\n")