from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from pyward.config import WardConfig
from pyward.core.parser import ParsedField


@dataclass
class InspectionContext:
    """กล่องรวมบริบททั้งหมดของ HTTP Request ที่ส่งให้ Guard ทุกตัวใช้ตรวจสอบร่วมกัน"""

    method: str
    path: str
    client_ip: str
    fields: list[ParsedField] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    user_id: str | None = None


@dataclass
class GuardFinding:
    """ใบแจ้งเหตุมาตรฐาน เมื่อ Guard ตัวใดตัวหนึ่งตรวจพบพฤติกรรมอันตราย"""

    vector: str               # ช่องทางที่พบ เช่น "QUERY_PARAM", "JSON_BODY", "BUSINESS_LOGIC"
    attack_type: str          # ประเภทการโจมตี เช่น "SQL_INJECTION", "XSS", "NOSQL_INJECTION"
    rule_id: str              # รหัสกฎ เช่น "PYWARD-SQLI-001"
    json_path: str | None = None  # พิกัดฟิลด์ที่พบ เช่น "$.user.username"
    detail: str | None = None     # คำอธิบายรายละเอียดเพิ่มเติม


class BaseGuard(ABC):
    """คลาสแม่แบบ (Abstract Base Class) บังคับให้ Guard ทุกตัวต้องมีเมธอด inspect()"""

    @abstractmethod
    def inspect(self, context: InspectionContext, config: WardConfig) -> GuardFinding | None:
        """
        ตรวจสอบ InspectionContext ตามกฎของ Guard ตัวนั้นๆ
        - คืนค่า GuardFinding หากพบการโจมตี
        - คืนค่า None หากข้อมูลปลอดภัย
        """
        raise NotImplementedError