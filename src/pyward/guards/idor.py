from collections import defaultdict, deque
import re
import time

from pyward.config import WardConfig
from pyward.guards.base import BaseGuard, GuardFinding, InspectionContext

# Regex สำหรับแยกท่อนของ URL ที่เป็นตัวเลข ID (เช่น 101) หรือ UUID
_NUMERIC_ID_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# รายชื่อฟิลด์ที่บ่งบอกความเป็นเจ้าของบัญชี/ข้อมูล
_DEFAULT_IDENTITY_FIELDS: set[str] = {
    "user_id",
    "userid",
    "owner_id",
    "account_id",
    "customer_id",
}


class IdorGuard(BaseGuard):
    """
    ป้องกันช่องโหว่ IDOR / BOLA (OWASP API1:2023) แบบ 2 ชั้น:
    1. Session-ID Mismatch: ตรวจจับการแอบเปลี่ยน user_id ใน Payload/Query ไม่ตรงกับตัวตนใน Session
    2. ID Enumeration Velocity: ตรวจจับพฤติกรรมการไล่กวาด ID ไม่ซ้ำกันหลายตัวในช่วงเวลาสั้นๆ
    """

    def __init__(
        self,
        identity_fields: set[str] | None = None,
        enumeration_threshold: int = 4,
        window_seconds: float = 10.0,
    ) -> None:
        self.identity_fields = {f.lower() for f in (identity_fields or _DEFAULT_IDENTITY_FIELDS)}
        self.enumeration_threshold = enumeration_threshold
        self.window_seconds = window_seconds

        # สมุดจดประวัติแบบ Sliding Window: key = (actor, route_template) -> deque[(timestamp, object_id)]
        self._access_history: dict[tuple[str, str], deque[tuple[float, str]]] = defaultdict(deque)

    def inspect(self, context: InspectionContext, config: WardConfig) -> GuardFinding | None:
        # ชั้นที่ 1: ตรวจจับ Parameter Tampering (เทียบ user_id ใน Request กับ Session)
        tampering_finding = self._check_identity_mismatch(context, config)
        if tampering_finding is not None:
            return tampering_finding

        # ชั้นที่ 2: ตรวจจับการไล่กวาด ID รัวๆ บน URL Path (Stateful Sliding Window)
        return self._check_enumeration_velocity(context)

    def _check_identity_mismatch(
        self, context: InspectionContext, config: WardConfig
    ) -> GuardFinding | None:
        # ถ้า Request นี้ยังไม่ล็อกอิน (ไม่มี user_id ใน Session) ให้ข้ามชั้นนี้ไป
        if not context.user_id:
            return None

        session_uid = str(context.user_id).strip()
        excluded_set = set(config.excluded_fields)

        for field in context.fields:
            if field.json_path in excluded_set:
                continue

            if field.normalized_key.lower() in self.identity_fields:
                submitted_uid = field.normalized_value.strip()
                if submitted_uid and submitted_uid != session_uid:
                    return GuardFinding(
                        vector=field.vector,
                        attack_type="IDOR_TAMPERING",
                        rule_id="PYWARD-IDOR-001",
                        json_path=field.json_path,
                        detail=(
                            f"Identity mismatch at '{field.json_path}': "
                            f"session user '{session_uid}' attempted to access '{submitted_uid}'"
                        ),
                    )

        return None

    def _check_enumeration_velocity(self, context: InspectionContext) -> GuardFinding | None:
        extracted = self._extract_resource_template(context.path)
        if extracted is None:
            return None

        route_template, object_id = extracted
        # ใช้ user_id เป็นตัวระบุตัวตนก่อน หากยังไม่ล็อกอินค่อย fallback ไปใช้ client_ip
        actor = context.user_id or context.client_ip
        bucket_key = (actor, route_template)

        now = time.monotonic()
        history = self._access_history[bucket_key]

        # 1. ลบประวัติเก่าที่เลยกรอบเวลา window_seconds ออก (Sliding Window)
        cutoff = now - self.window_seconds
        while history and history[0][0] < cutoff:
            history.popleft()

        # 2. บันทึกการเข้าถึงครั้งล่าสุดลงท้ายคิว
        history.append((now, object_id))

        # 3. นับเฉพาะจำนวน Object ID ที่ "ไม่ซ้ำกัน" (ใช้ set) เพื่อกัน False Positive จากการกด Refresh
        distinct_ids = {oid for _, oid in history}
        if len(distinct_ids) >= self.enumeration_threshold:
            return GuardFinding(
                vector="BUSINESS_LOGIC",
                attack_type="IDOR_ENUMERATION",
                rule_id="PYWARD-IDOR-002",
                json_path=route_template,
                detail=(
                    f"Actor '{actor}' enumerated {len(distinct_ids)} distinct IDs on "
                    f"'{route_template}' within {self.window_seconds}s"
                ),
            )

        return None

    def _extract_resource_template(self, path: str) -> tuple[str, str] | None:
        """
        แปลง URL ที่มีตัวเลข ID หรือ UUID ให้เป็นแม่แบบเส้นทางและรหัส ID
        ตัวอย่าง: "/api/orders/501" -> ("/api/orders/{id}", "501")
        """
        segments = [seg for seg in path.split("/") if seg]
        template_parts: list[str] = []
        found_ids: list[str] = []

        for seg in segments:
            if _NUMERIC_ID_RE.match(seg) or _UUID_RE.match(seg):
                template_parts.append("{id}")
                found_ids.append(seg)
            else:
                template_parts.append(seg)

        if not found_ids:
            return None

        return "/" + "/".join(template_parts), "|".join(found_ids)