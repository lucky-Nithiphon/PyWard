import re

from pyward.config import WardConfig
from pyward.core.parser import ParsedField
from pyward.guards.base import BaseGuard, GuardFinding, InspectionContext

# 1. กฎตรวจจับ SQL Injection (SQLi)
_SQLI_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "PYWARD-SQLI-001",
        re.compile(r"(?:'|\")?\s*\b(?:OR|AND)\b\s+(['\"]?\w+['\"]?)\s*(=|>|<|LIKE)\s*\1", re.IGNORECASE),
    ),
    (
        "PYWARD-SQLI-002",
        re.compile(r"\bUNION\b\s+(?:\bALL\b\s+)?\bSELECT\b", re.IGNORECASE),
    ),
    (
        "PYWARD-SQLI-003",
        re.compile(r"\b(?:DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+\w+\s+SET)\b", re.IGNORECASE),
    ),
    (
        "PYWARD-SQLI-004",
        re.compile(r"\b(?:SLEEP|BENCHMARK|PG_SLEEP|WAITFOR\s+DELAY)\s*\(", re.IGNORECASE),
    ),
]

# 2. กฎตรวจจับ Cross-Site Scripting (XSS)
_XSS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("PYWARD-XSS-001", re.compile(r"<\s*script[^>]*>", re.IGNORECASE)),
    ("PYWARD-XSS-002", re.compile(r"\bon[a-zA-Z]+\s*=", re.IGNORECASE)),
    ("PYWARD-XSS-003", re.compile(r"javascript\s*:", re.IGNORECASE)),
]

# 3. กฎตรวจจับ NoSQL Injection (MongoDB Operators ในชื่อ Key และ Value)
_NOSQL_KEY_RE = re.compile(
    r"^\$(?:ne|eq|gt|gte|lt|lte|in|nin|or|and|not|nor|exists|type|regex|where|expr)$",
    re.IGNORECASE,
)
_NOSQL_VALUE_RE = re.compile(r"\$(?:where|ne|gt|regex)\b", re.IGNORECASE)

# 4. กฎตรวจจับ OS Command Injection (CMDi)
_CMDI_RE = re.compile(
    r"(?:[;&|`]|&&|\|\|)\s*(?:cat|ls|dir|type|whoami|id|uname|powershell|cmd|curl|wget|sh|bash)\b",
    re.IGNORECASE,
)


class InjectionGuard(BaseGuard):
    """
    ตรวจจับการฝังโค้ดอันตรายเชิงบริบท (SQLi, XSS, NoSQLi, OS Command Injection)
    ในระดับรายฟิลด์ (JSONPath) พร้อมรองรับ Field-level Whitelist
    """

    def inspect(self, context: InspectionContext, config: WardConfig) -> GuardFinding | None:
        excluded_set = set(config.excluded_fields)

        for field in context.fields:
            # 1. ตรวจสอบ Field-level Whitelist (ถ้าฟิลด์นี้ได้รับยกเว้น ให้ข้ามไปตรวจฟิลด์ถัดไป)
            if field.json_path in excluded_set:
                continue

            finding = self._inspect_field(field)
            if finding is not None:
                return finding

        return None

    def _inspect_field(self, field: ParsedField) -> GuardFinding | None:
        # 2. ตรวจชื่อ Key ก่อน (ดักจับ NoSQL Operator Injection เช่น {"$ne": null})
        if _NOSQL_KEY_RE.match(field.normalized_key):
            return GuardFinding(
                vector=field.vector,
                attack_type="NOSQL_INJECTION",
                rule_id="PYWARD-NOSQLI-001",
                json_path=field.json_path,
                detail=f"Dangerous NoSQL operator key '{field.normalized_key}' detected",
            )

        val = field.normalized_value
        if not val:
            return None

        # 3. ตรวจ SQL Injection ใน Value
        for rule_id, pattern in _SQLI_PATTERNS:
            if pattern.search(val):
                return GuardFinding(
                    vector=field.vector,
                    attack_type="SQL_INJECTION",
                    rule_id=rule_id,
                    json_path=field.json_path,
                    detail=f"SQL injection pattern matched at '{field.json_path}'",
                )

        # 4. ตรวจ XSS ใน Value
        for rule_id, pattern in _XSS_PATTERNS:
            if pattern.search(val):
                return GuardFinding(
                    vector=field.vector,
                    attack_type="XSS",
                    rule_id=rule_id,
                    json_path=field.json_path,
                    detail=f"XSS payload detected at '{field.json_path}'",
                )

        # 5. ตรวจ NoSQL Operator ใน Value
        if _NOSQL_VALUE_RE.search(val):
            return GuardFinding(
                vector=field.vector,
                attack_type="NOSQL_INJECTION",
                rule_id="PYWARD-NOSQLI-002",
                json_path=field.json_path,
                detail=f"NoSQL operator expression detected at '{field.json_path}'",
            )

        # 6. ตรวจ OS Command Injection ใน Value
        if _CMDI_RE.search(val):
            return GuardFinding(
                vector=field.vector,
                attack_type="COMMAND_INJECTION",
                rule_id="PYWARD-CMDI-001",
                json_path=field.json_path,
                detail=f"OS command chaining detected at '{field.json_path}'",
            )

        return None