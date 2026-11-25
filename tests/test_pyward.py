import base64
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from pyward import PyWardMiddleware, WardConfig, WardMode
from pyward.core.normalizer import PayloadNormalizer
from pyward.core.parser import RequestParser
from pyward.guards.response_dlp import ResponseDlpGuard


def _create_test_app(
    log_path: Path,
    mode: WardMode = WardMode.BLOCK_MODE,
    excluded_fields: list[str] | None = None,
) -> FastAPI:
    """สร้าง FastAPI App สะอาดใหม่ทุกครั้งที่รันแต่ละเคส (ป้องกัน State ของ IdorGuard ปนกัน)"""
    app = FastAPI()
    app.add_middleware(
        PyWardMiddleware,
        config=WardConfig(
            mode=mode,
            log_file=str(log_path),
            console_log=False,
            excluded_paths=["/health"],
            excluded_fields=excluded_fields or ["$.article.html_body"],
        ),
    )

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/api/submit")
    async def submit(payload: dict):
        return {"received": payload}

    @app.patch("/api/profile")
    async def update_profile(payload: dict):
        return {"updated": payload}

    @app.get("/api/orders/{order_id}")
    async def get_order(order_id: int):
        return {"order_id": order_id}

    @app.get("/api/leak")
    async def leak():
        return {"id": 1, "password_hash": "$2b$12$topSecretHashValue"}

    return app


def _make_jwt(sub: str) -> str:
    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps({"sub": sub}).encode()).decode().rstrip("=")
    return f"{h}.{p}.sig"


# ==============================================================================
# 1. Unit Tests: Core Normalizer & Recursive JSONPath Parser
# ==============================================================================

def test_normalizer_decodes_multilayer_and_preserves_thai():
    normalizer = PayloadNormalizer()
    assert normalizer.normalize("%2527%5Cu0020OR%201%3D1%00--") == "' OR 1=1--"
    assert normalizer.normalize("สวัสดี &#x3C;script&#x3E;") == "สวัสดี <script>"


def test_parser_flattens_nested_json_and_arrays():
    parser = RequestParser()
    fields = parser.parse_request(
        "ref=1%2527",
        b'{"user": {"filter": {"$ne": null}}, "tags": ["a", "b"]}',
    )
    paths = {f.json_path: f for f in fields}

    assert paths["$.query.ref"].normalized_value == "1'"
    assert paths["$.user.filter.$ne"].normalized_key == "$ne"
    assert paths["$.tags[1]"].normalized_value == "b"


# ==============================================================================
# 2. Integration Tests: Injection, True Positive & False Positive
# ==============================================================================

@pytest.mark.parametrize(
    "payload, expected_attack",
    [
        ({"user": {"name": "admin%2527%20OR%201%3D1--"}}, "SQL_INJECTION"),
        ({"q": "1%2520UNION%2520SELECT%25201,2,3"}, "SQL_INJECTION"),
        ({"comment": "<img src=x onerror=alert(1)>"}, "XSS"),
        ({"password": {"$ne": None}}, "NOSQL_INJECTION"),
        ({"host": "127.0.0.1 && whoami"}, "COMMAND_INJECTION"),
    ],
)
def test_injection_guard_blocks_all_vectors_and_logs_siem_json(tmp_path: Path, payload: dict, expected_attack: str):
    log_file = tmp_path / "siem.jsonl"
    client = TestClient(_create_test_app(log_file))

    res = client.post("/api/submit", json=payload)
    assert res.status_code == 403
    assert res.headers.get("x-protected-by") == "PyWard-RASP"
    assert "incident_id" in res.json()

    # ตรวจสอบโครงสร้าง JSON Log ที่บันทึกไว้สำหรับส่งต่อให้ LogSentry
    event = json.loads(log_file.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert event["source"] == "pyward-rasp"
    assert event["attack_type"] == expected_attack
    assert event["action"] == "BLOCKED"
    assert event["status_code"] == 403


def test_clean_traffic_stream_replay_and_no_false_positives(tmp_path: Path):
    client = TestClient(_create_test_app(tmp_path / "siem.jsonl"))

    # ชื่อที่มี Single Quote (O'Connor) และคำว่า "and" ต้องไม่โดนบล็อกมั่ว
    benign_payload = {"name": "O'Connor", "bio": "Security engineer and Python developer"}
    res = client.post("/api/submit", json=benign_payload)

    assert res.status_code == 200
    assert res.json()["received"] == benign_payload  # ยืนยันว่า Stream Replay คืนข้อมูลครบ


def test_path_and_field_whitelists(tmp_path: Path):
    client = TestClient(_create_test_app(tmp_path / "siem.jsonl"))

    # 1. Path Whitelist (/health) ต้องผ่านแม้มี Query แปลกๆ
    assert client.get("/health?q=1' OR 1=1--").status_code == 200

    # 2. Field Whitelist ($.article.html_body) ต้องผ่าน แต่ฟิลด์อื่นใน JSON เดียวกันยังโดนตรวจ
    ok_res = client.post("/api/submit", json={"article": {"html_body": "<script>ok()</script>"}})
    assert ok_res.status_code == 200

    bad_res = client.post(
        "/api/submit",
        json={"article": {"html_body": "<script>ok()</script>", "author": "admin' OR 1=1--"}},
    )
    assert bad_res.status_code == 403


# ==============================================================================
# 3. Integration Tests: Mass Assignment, IDOR, Response DLP & MONITOR_MODE
# ==============================================================================

def test_mass_assignment_guard_blocks_case_and_unicode_bypass(tmp_path: Path):
    client = TestClient(_create_test_app(tmp_path / "siem.jsonl"))

    assert client.patch("/api/profile", json={"name": "Nithi", "RoLe": "admin"}).status_code == 403
    assert client.patch(
        "/api/profile",
        content=b'{"\\u0069s_admin": true}',
        headers={"content-type": "application/json"},
    ).status_code == 403


def test_idor_tampering_and_enumeration_velocity(tmp_path: Path):
    client = TestClient(_create_test_app(tmp_path / "siem.jsonl"))

    # 1. Parameter Tampering: ล็อกอินเป็น 101 แต่ส่ง user_id=102 -> 403
    assert client.post("/api/submit", headers={"X-User-ID": "101"}, json={"user_id": "102"}).status_code == 403
    assert client.post("/api/submit", headers={"X-User-ID": "101"}, json={"user_id": "101"}).status_code == 200

    # 2. Refresh เลขเดิม 5 ครั้ง -> ต้องไม่บล็อก
    for _ in range(5):
        assert client.get("/api/orders/501", headers={"X-User-ID": "101"}).status_code == 200

    # 3. ใช้ JWT ของ user 202 ไล่กวาด 4 เลขไม่ซ้ำกัน -> รอบที่ 4 ต้องโดน 403
    jwt_headers = {"Authorization": f"Bearer {_make_jwt('202')}"}
    codes = [client.get(f"/api/orders/{oid}", headers=jwt_headers).status_code for oid in [501, 502, 503, 504]]
    assert codes == [200, 200, 200, 403]


def test_response_dlp_redacts_secrets_and_skips_binary(tmp_path: Path):
    client = TestClient(_create_test_app(tmp_path / "siem.jsonl"))

    res = client.get("/api/leak")
    assert res.status_code == 500
    assert "topSecretHashValue" not in res.text

    # ตรวจระดับ Unit เพิ่มเติมว่าไฟล์รูปภาพ Binary จะถูกข้าม
    dlp = ResponseDlpGuard()
    assert dlp.inspect_response(b"\x89PNG\r\nAKIAIOSFODNN7EXAMPLE", "image/png") is None


def test_monitor_mode_allows_request_but_logs_event(tmp_path: Path):
    log_file = tmp_path / "monitor.jsonl"
    client = TestClient(_create_test_app(log_file, mode=WardMode.MONITOR_MODE))

    res = client.post("/api/submit", json={"name": "admin' OR 1=1--"})
    assert res.status_code == 200

    event = json.loads(log_file.read_text(encoding="utf-8").strip())
    assert event["action"] == "MONITORED"
    assert event["status_code"] == 200