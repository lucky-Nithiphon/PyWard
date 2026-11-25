from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import uuid


@dataclass
class SecurityEvent:
    """โครงสร้างเหตุการณ์ความปลอดภัย รองรับทั้งการส่งออก JSON (LogSentry) และ Pretty Print"""

    client_ip: str
    method: str
    path: str
    inspection_vector: str
    attack_type: str
    rule_id: str
    action: str
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
        """แปลงเป็น JSON 1 บรรทัดสำหรับเขียนลงไฟล์ .jsonl (Machine-Readable)"""
        payload = {k: v for k, v in asdict(self).items() if v is not None}
        return json.dumps(payload, ensure_ascii=False)

    def to_pretty(self) -> str:
        """จัดรูปแบบให้อ่านง่ายบนหน้าจอ Terminal (Human-Readable)"""
        target = f"{self.inspection_vector} -> {self.json_path}" if self.json_path else self.inspection_vector
        return (
            f"\n[PyWard | {self.action}] {self.attack_type} ({self.rule_id})\n"
            f"  |- Request : {self.method} {self.path} (IP: {self.client_ip})\n"
            f"  |- Target  : {target}\n"
            f"  |- Detail  : {self.detail or '-'}\n"
            f"  \\_ Meta    : HTTP {self.status_code} | {self.latency_us} us | ID: {self.event_id}"
        )


class SecurityLogger:
    """จัดการเขียน Security Telemetry แยกช่องทาง: หน้าจอ (Pretty/JSON) และไฟล์ (.jsonl)"""

    def __init__(
        self,
        log_file: str | None = None,
        console_log: bool = True,
        console_format: str = "pretty",
    ) -> None:
        self.log_file = Path(log_file) if log_file else None
        self.console_log = console_log
        self.console_format = console_format.lower()

    def log_event(self, event: SecurityEvent) -> None:
        # 1. แสดงผลบนหน้าจอ Terminal ตามรูปแบบที่เลือก
        if self.console_log:
            if self.console_format == "json":
                print(event.to_json())
            else:
                print(event.to_pretty())

        # 2. เขียนลงไฟล์ .jsonl เป็น JSON มาตรฐานเสมอ (พร้อมส่งต่อให้ LogSentry)
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(event.to_json() + "\n")