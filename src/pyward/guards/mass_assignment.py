from pyward.config import WardConfig
from pyward.guards.base import BaseGuard, GuardFinding, InspectionContext

# ตรวจสอบเฉพาะ HTTP Method ที่มีการสร้างหรือแก้ไขข้อมูล (ลด False Positive จาก GET Query)
_STATE_CHANGING_METHODS: set[str] = {"POST", "PUT", "PATCH"}


class MassAssignmentGuard(BaseGuard):
    """
    ป้องกันช่องโหว่ Mass Assignment / Privilege Escalation (OWASP API3:2023)
    ตรวจจับและบล็อกเมื่อมีผู้ส่งฟิลด์ต้องห้าม (เช่น role, is_admin, account_balance)
    ปะปนเข้ามาใน JSON Request Body ไม่ว่าจะซ่อนอยู่ลึกกี่ชั้นหรือเปลี่ยนตัวพิมพ์เล็ก-ใหญ่
    """

    def inspect(self, context: InspectionContext, config: WardConfig) -> GuardFinding | None:
        # 1. ข้ามการตรวจสอบหากไม่ใช่เมธอดสำหรับสร้าง/แก้ไขข้อมูล (เช่น GET, HEAD, OPTIONS)
        if context.method.upper() not in _STATE_CHANGING_METHODS:
            return None

        # แปลงรายชื่อฟิลด์ต้องห้ามเป็นตัวพิมพ์เล็กทั้งหมดเพื่อกันการหลบด้วย Case-Bypass (เช่น "Is_Admin")
        restricted_lower = {name.lower() for name in config.restricted_fields}
        excluded_set = set(config.excluded_fields)

        for field in context.fields:
            # 2. ตรวจเฉพาะข้อมูลที่ส่งมาใน JSON Body (ไม่ยุ่งกับ Query Parameter)
            if field.vector != "JSON_BODY":
                continue

            # 3. เคารพ Field-level Whitelist หากนักพัฒนายกเว้นพิกัดนี้ไว้เป็นกรณีพิเศษ
            if field.json_path in excluded_set:
                continue

            # 4. เปรียบเทียบชื่อ Key ที่ถอดรหัสแล้ว (ป้องกันทั้ง Case-Bypass และ Unicode Escape เช่น \u0072ole)
            clean_key_lower = field.normalized_key.lower()
            if clean_key_lower in restricted_lower:
                return GuardFinding(
                    vector=field.vector,
                    attack_type="MASS_ASSIGNMENT",
                    rule_id="PYWARD-MA-001",
                    json_path=field.json_path,
                    detail=(
                        f"Unauthorized privileged field '{field.normalized_key}' "
                        f"detected in {context.method.upper()} payload at '{field.json_path}'"
                    ),
                )

        return None