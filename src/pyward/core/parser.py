from dataclasses import dataclass
import json
from typing import Any
from urllib.parse import parse_qsl

from pyward.core.normalizer import PayloadNormalizer


@dataclass
class ParsedField:
    """เก็บข้อมูลแต่ละฟิลด์ที่แกะออกมาได้ พร้อมพิกัดและค่าที่ล้างรหัสแล้ว"""

    vector: str            # ช่องทางที่ส่งมา: "QUERY_PARAM" หรือ "JSON_BODY"
    json_path: str         # พิกัดของข้อมูล เช่น "$.user.profile.bio"
    key: str               # ชื่อ Key ดิบ เช่น "bio" หรือ "$ne"
    normalized_key: str    # ชื่อ Key ที่ถอดรหัสแล้ว (กันแฮกเกอร์ซ่อนโค้ดในชื่อ Key)
    raw_value: str         # ค่าดิบก่อนถอดรหัส
    normalized_value: str  # ค่าที่ผ่าน PayloadNormalizer แล้ว


class RequestParser:
    """
    แตกโครงสร้าง URL Query และ Nested JSON Body ที่ซ้อนกันหลายชั้น (Recursive)
    ออกมาเป็นรายการ ParsedField ที่สะอาดและพร้อมส่งให้ Guard ตรวจสอบ
    """

    def __init__(self, normalizer: PayloadNormalizer | None = None, max_depth: int = 20) -> None:
        self.normalizer = normalizer or PayloadNormalizer()
        self.max_depth = max_depth

    def parse_request(self, query_string: str, body_bytes: bytes) -> list[ParsedField]:
        fields: list[ParsedField] = []
        fields.extend(self.parse_query(query_string))
        fields.extend(self.parse_json_body(body_bytes))
        return fields

    def parse_query(self, query_string: str) -> list[ParsedField]:
        if not query_string:
            return []

        results: list[ParsedField] = []
        # แตก "id=1&search=hello" เป็นคู่ [("id", "1"), ("search", "hello")]
        for key, value in parse_qsl(query_string, keep_blank_values=True):
            results.append(
                ParsedField(
                    vector="QUERY_PARAM",
                    json_path=f"$.query.{key}",
                    key=key,
                    normalized_key=self.normalizer.normalize(key),
                    raw_value=value,
                    normalized_value=self.normalizer.normalize(value),
                )
            )
        return results

    def parse_json_body(self, body_bytes: bytes) -> list[ParsedField]:
        if not body_bytes:
            return []

        raw_text = body_bytes.decode("utf-8", errors="replace").strip()
        if not raw_text:
            return []

        try:
            parsed_data = json.loads(raw_text)
        except json.JSONDecodeError:
            # กรณีส่งข้อความดิบที่ไม่ใช่ JSON เข้ามา ให้ตรวจทั้งก้อนเป็น 1 ฟิลด์ (กันแฮกเกอร์ส่ง JSON พังๆ มาหลบตรวจ)
            return [
                ParsedField(
                    vector="JSON_BODY",
                    json_path="$",
                    key="$raw_body",
                    normalized_key="$raw_body",
                    raw_value=raw_text,
                    normalized_value=self.normalizer.normalize(raw_text),
                )
            ]

        results: list[ParsedField] = []
        self._traverse(node=parsed_data, current_path="$", current_key="$", depth=0, results=results)
        return results

    def _traverse(
        self,
        node: Any,
        current_path: str,
        current_key: str,
        depth: int,
        results: list[ParsedField],
    ) -> None:
        """เดินลึกลงไปในโครงสร้าง dict และ list ทีละชั้นแบบ Recursive"""
        if depth > self.max_depth:
            return

        if isinstance(node, dict):
            for k, v in node.items():
                key_str = str(k)
                next_path = f"{current_path}.{key_str}"
                self._traverse(v, next_path, key_str, depth + 1, results)

        elif isinstance(node, list):
            for index, item in enumerate(node):
                next_path = f"{current_path}[{index}]"
                self._traverse(item, next_path, current_key, depth + 1, results)

        else:
            # เจอข้อมูลชั้นในสุดแล้ว (String, ตัวเลข, Boolean หรือ None)
            raw_val = "null" if node is None else str(node)
            results.append(
                ParsedField(
                    vector="JSON_BODY",
                    json_path=current_path,
                    key=current_key,
                    normalized_key=self.normalizer.normalize(current_key),
                    raw_value=raw_val,
                    normalized_value=self.normalizer.normalize(raw_val),
                )
            )