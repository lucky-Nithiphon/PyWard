import html
import re
from urllib.parse import unquote

# Regex สำหรับจับรหัส Unicode (\u003c) และ Hex (\x3c) ที่มักถูกซ่อนใน JSON/String
_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
_WHITESPACE_RE = re.compile(r"\s+")


class PayloadNormalizer:
    """
    ถอดรหัสการพรางตัว (Obfuscation) หลายชั้น เพื่อเปิดเผย Payload ที่แท้จริง
    รองรับ URL Encoding, HTML Entities, Unicode/Hex Escapes และ Null Bytes
    """

    def __init__(self, max_rounds: int = 5) -> None:
        self.max_rounds = max_rounds

    def normalize(self, raw_value: str) -> str:
        if not raw_value:
            return ""

        current = raw_value

        # วนลูปถอดรหัสซ้ำจนกว่าข้อความจะไม่เปลี่ยนแปลง หรือครบจำนวนรอบสูงสุด
        for _ in range(self.max_rounds):
            decoded = self._decode_single_pass(current)
            if decoded == current:
                break
            current = decoded

        # ลบ Null Byte (\x00) และยุบช่องว่าง/ขึ้นบรรทัดใหม่ให้เป็นเว้นวรรคเดียว
        current = current.replace("\x00", "")
        current = _WHITESPACE_RE.sub(" ", current).strip()
        return current

    def _decode_single_pass(self, text: str) -> str:
        # 1. ถอดรหัส URL Encoding (เช่น %2527 -> %27 -> ')
        step1 = unquote(text)

        # 2. ถอดรหัส HTML Entities (เช่น &#39; -> ' หรือ &lt; -> <)
        step2 = html.unescape(step1)

        # 3. ถอดรหัส Unicode Escapes (เช่น \u003c -> <)
        step3 = _UNICODE_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), step2)

        # 4. ถอดรหัส Hex Escapes (เช่น \x27 -> ')
        step4 = _HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), step3)

        return step4