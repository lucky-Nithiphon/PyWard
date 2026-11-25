import re

from pyward.guards.base import GuardFinding

# ประเภทเนื้อหาที่อนุญาตให้สแกน (ข้ามไฟล์ Binary เช่น รูปภาพ, PDF, วิดีโอ เพื่อไม่ให้เปลือง CPU)
_INSPECTABLE_CONTENT_TYPES: tuple[str, ...] = (
    "application/json",
    "text/",
    "application/xml",
    "application/javascript",
)

# 1. กฎตรวจจับ Stack Trace ของ Python / Framework
_STACK_TRACE_RE = re.compile(
    r'(?:Traceback \(most recent call last\):|File "[^"]+", line \d+, in )',
    re.IGNORECASE,
)

# 2. กฎตรวจจับ Error ของฐานข้อมูล (SQLite, PostgreSQL, MySQL, Oracle, SQLAlchemy)
_DB_ERROR_RE = re.compile(
    r"(?:sqlite3\.(?:Operational|Integrity|Programming)Error"
    r"|psycopg2\.\w*Error"
    r"|sqlalchemy\.exc\.\w+"
    r"|SQL syntax.*MySQL"
    r"|ORA-\d{5})",
    re.IGNORECASE,
)

# 3. กฎตรวจจับ Secret Key / Private Key / Cloud API Key
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("PEM Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("API Secret Token", re.compile(r"\b(?:sk_live_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})\b")),
]

# 4. กฎตรวจจับฟิลด์รหัสผ่านหรือกุญแจลับที่เผลอหลุดออกมาใน JSON Response
_SENSITIVE_JSON_FIELD_RE = re.compile(
    r'"(password|password_hash|hashed_password|secret_key|private_key|db_password|api_secret)"\s*:\s*"[^"]+"',
    re.IGNORECASE,
)


class ResponseDlpGuard:
    """
    ตรวจสอบ HTTP Response ขาออก (Egress Data Loss Prevention)
    ป้องกันไม่ให้ Backend เผลอพ่น Stack Trace, Database Error, Secret Keys หรือ Password Hash หลุดออกสู่ภายนอก
    """

    def __init__(self, max_body_size: int = 1_048_576) -> None:
        # จำกัดขนาด Response สูงสุดที่จะสแกน (ค่าเริ่มต้น 1 MB) เพื่อป้องกันกิน RAM/CPU เกินจำเป็น
        self.max_body_size = max_body_size

    def inspect_response(
        self,
        body_bytes: bytes,
        content_type: str = "",
    ) -> GuardFinding | None:
        # 1. ข้ามหาก Response ว่างเปล่า หรือมีขนาดใหญ่เกินเกณฑ์
        if not body_bytes or len(body_bytes) > self.max_body_size:
            return None

        # 2. ข้ามหากเป็นไฟล์ Binary (เช่น image/png, application/pdf)
        if content_type and not self._is_inspectable_content_type(content_type):
            return None

        text = body_bytes.decode("utf-8", errors="replace")

        # 3. ตรวจจับ Python / Application Stack Trace
        if _STACK_TRACE_RE.search(text):
            return GuardFinding(
                vector="RESPONSE_DLP",
                attack_type="STACK_TRACE_LEAK",
                rule_id="PYWARD-DLP-001",
                detail="Application stack trace detected in outgoing HTTP response",
            )

        # 4. ตรวจจับ Database Error Message
        if _DB_ERROR_RE.search(text):
            return GuardFinding(
                vector="RESPONSE_DLP",
                attack_type="DB_ERROR_LEAK",
                rule_id="PYWARD-DLP-002",
                detail="Database error details leaked in outgoing HTTP response",
            )

        # 5. ตรวจจับ Private Key / Cloud Secret Key
        for secret_name, pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                return GuardFinding(
                    vector="RESPONSE_DLP",
                    attack_type="SECRET_KEY_LEAK",
                    rule_id="PYWARD-DLP-003",
                    detail=f"Sensitive secret ({secret_name}) leaked in outgoing HTTP response",
                )

        # 6. ตรวจจับฟิลด์รหัสผ่านหรือ Secret ใน JSON Response
        cred_match = _SENSITIVE_JSON_FIELD_RE.search(text)
        if cred_match:
            leaked_field = cred_match.group(1)
            return GuardFinding(
                vector="RESPONSE_DLP",
                attack_type="CREDENTIAL_LEAK",
                rule_id="PYWARD-DLP-004",
                json_path=f"$.{leaked_field}",
                detail=f"Sensitive credential field '{leaked_field}' leaked in JSON response",
            )

        return None

    def _is_inspectable_content_type(self, content_type: str) -> bool:
        mime = content_type.lower().split(";")[0].strip()
        return any(mime.startswith(prefix) for prefix in _INSPECTABLE_CONTENT_TYPES)