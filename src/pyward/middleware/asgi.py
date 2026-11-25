import base64
import json
import time
from typing import Any, Awaitable, Callable

from pyward.config import WardConfig, WardMode
from pyward.core.parser import RequestParser
from pyward.guards.base import BaseGuard, GuardFinding, InspectionContext
from pyward.guards.idor import IdorGuard
from pyward.guards.injection import InjectionGuard
from pyward.guards.mass_assignment import MassAssignmentGuard
from pyward.guards.response_dlp import ResponseDlpGuard
from pyward.telemetry.logger import SecurityEvent, SecurityLogger

ASGIApp = Callable[
    [
        dict[str, Any],
        Callable[[], Awaitable[dict[str, Any]]],
        Callable[[dict[str, Any]], Awaitable[None]],
    ],
    Awaitable[None],
]


class PyWardMiddleware:
    """
    Pure ASGI Security Middleware สำหรับ FastAPI / Starlette
    ครบวงจรทั้งขาเข้า (Ingress: Injection, Mass Assignment, IDOR)
    และขาออก (Egress: Response DLP ป้องกันข้อมูลลับและ Stack Trace รั่วไหล)
    """

    def __init__(
        self,
        app: ASGIApp,
        config: WardConfig | None = None,
        guards: list[BaseGuard] | None = None,
        response_dlp: ResponseDlpGuard | None = None,
    ) -> None:
        self.app = app
        self.config = config or WardConfig()
        self.logger = SecurityLogger(
            log_file=self.config.log_file,
            console_log=self.config.console_log,
            console_format=self.config.console_format,
        )
        self.parser = RequestParser()

        # ขบวน Guard ขาเข้า (ทำงานเรียงตามลำดับ: Injection -> Mass Assignment -> IDOR)
        self.guards: list[BaseGuard] = (
            guards
            if guards is not None
            else [
                InjectionGuard(),
                MassAssignmentGuard(),
                IdorGuard(),
            ]
        )

        # ด่านตรวจขาออก (Egress Data Loss Prevention)
        self.response_dlp = response_dlp if response_dlp is not None else ResponseDlpGuard()

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "/")

        # 1. ตรวจสอบ Path Whitelist (เช่น /docs, /health)
        if self._is_path_excluded(path):
            await self.app(scope, receive, send)
            return

        start_time = time.perf_counter()

        # 2. อ่าน Request Body อย่างปลอดภัยและเตรียม Stream Replay คืนให้ FastAPI
        body_bytes, replay_receive = await self._buffer_request_body(receive)

        # 3. ดึงข้อมูลบริบทและตัวตนผู้ใช้ (Headers + JWT/X-User-ID)
        method: str = scope.get("method", "GET")
        client_info = scope.get("client")
        client_ip: str = client_info[0] if client_info else "unknown"
        query_string: str = scope.get("query_string", b"").decode("utf-8", errors="replace")
        headers: dict[str, str] = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }
        user_id = self._extract_user_id(headers)

        # 4. ตรวจสอบขาเข้า (Ingress Pipeline: Parser -> Injection / Mass Assignment / IDOR)
        finding = self._run_inspection_pipeline(
            method=method,
            path=path,
            client_ip=client_ip,
            query_string=query_string,
            body_bytes=body_bytes,
            headers=headers,
            user_id=user_id,
        )

        if finding is not None:
            latency_us = int((time.perf_counter() - start_time) * 1_000_000)
            is_blocking = self.config.mode == WardMode.BLOCK_MODE
            action = "BLOCKED" if is_blocking else "MONITORED"
            status_code = self.config.block_status_code if is_blocking else 200

            event = SecurityEvent(
                client_ip=client_ip,
                method=method,
                path=path,
                inspection_vector=finding.vector,
                attack_type=finding.attack_type,
                rule_id=finding.rule_id,
                action=action,
                status_code=status_code,
                latency_us=latency_us,
                user_id=user_id,
                json_path=finding.json_path,
                detail=finding.detail,
            )
            self.logger.log_event(event)

            if is_blocking:
                await self._send_block_response(send, event.event_id)
                return

        # 5. ห่อหุ้มท่อขาออก (Egress Wrapper) เพื่อตรวจสอบ Response DLP ก่อนส่งกลับให้ผู้ใช้
        response_start: dict[str, Any] | None = None
        response_chunks: list[bytes] = []

        async def intercept_send(message: dict[str, Any]) -> None:
            nonlocal response_start

            if message["type"] == "http.response.start":
                response_start = message
                return

            if message["type"] == "http.response.body":
                response_chunks.append(message.get("body", b""))
                if message.get("more_body", False):
                    return

                full_res_body = b"".join(response_chunks)
                content_type = self._get_response_content_type(response_start)

                dlp_finding = self.response_dlp.inspect_response(full_res_body, content_type)
                if dlp_finding is not None:
                    latency_us = int((time.perf_counter() - start_time) * 1_000_000)
                    is_blocking = self.config.mode == WardMode.BLOCK_MODE
                    action = "BLOCKED" if is_blocking else "MONITORED"
                    orig_status = response_start.get("status", 200) if response_start else 200
                    logged_status = 500 if is_blocking else orig_status

                    event = SecurityEvent(
                        client_ip=client_ip,
                        method=method,
                        path=path,
                        inspection_vector=dlp_finding.vector,
                        attack_type=dlp_finding.attack_type,
                        rule_id=dlp_finding.rule_id,
                        action=action,
                        status_code=logged_status,
                        latency_us=latency_us,
                        user_id=user_id,
                        json_path=dlp_finding.json_path,
                        detail=dlp_finding.detail,
                    )
                    self.logger.log_event(event)

                    if is_blocking:
                        await self._send_dlp_block_response(send, event.event_id)
                        return

                # Response ปลอดภัย (หรืออยู่ใน MONITOR_MODE) -> ปล่อยส่งออกตามปกติ
                if response_start is not None:
                    await send(response_start)
                await send({"type": "http.response.body", "body": full_res_body, "more_body": False})
                return

            await send(message)

        # 6. ส่งต่อ Request ที่ปลอดภัยไปยัง FastAPI Endpoint โดยดักรับขาออกผ่าน intercept_send
        await self.app(scope, replay_receive, intercept_send)

    def _is_path_excluded(self, path: str) -> bool:
        return any(
            path == excluded or path.startswith(excluded.rstrip("/") + "/")
            for excluded in self.config.excluded_paths
        )

    def _extract_user_id(self, headers: dict[str, str]) -> str | None:
        """
        ดึงตัวตนผู้ใช้งาน (user_id) จาก Request Headers:
        1. ลองแกะ JWT Payload (Authorization: Bearer <token>) หาฟิลด์ 'sub' หรือ 'user_id'
        2. หากไม่มี JWT ให้ fallback ไปอ่านจาก Header 'X-User-ID'
        """
        auth_header = headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
            parts = token.split(".")
            if len(parts) == 3:
                try:
                    # เติม padding '=' ให้ครบตามมาตรฐาน Base64URL ก่อนถอดรหัส
                    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
                    uid = payload.get("sub") or payload.get("user_id")
                    if uid is not None:
                        return str(uid).strip()
                except Exception:
                    pass

        if "x-user-id" in headers:
            return headers["x-user-id"].strip() or None

        return None

    def _get_response_content_type(self, response_start: dict[str, Any] | None) -> str:
        if not response_start:
            return ""
        for k, v in response_start.get("headers", []):
            if k.decode("latin-1").lower() == "content-type":
                return v.decode("latin-1")
        return ""

    async def _buffer_request_body(
        self, receive: Callable[[], Awaitable[dict[str, Any]]]
    ) -> tuple[bytes, Callable[[], Awaitable[dict[str, Any]]]]:
        chunks: list[bytes] = []
        more_body = True

        while more_body:
            message = await receive()
            if message["type"] == "http.request":
                chunks.append(message.get("body", b""))
                more_body = message.get("more_body", False)
            elif message["type"] == "http.disconnect":
                more_body = False

        full_body = b"".join(chunks)
        body_sent = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": full_body, "more_body": False}
            return {"type": "http.disconnect"}

        return full_body, replay_receive

    def _run_inspection_pipeline(
        self,
        method: str,
        path: str,
        client_ip: str,
        query_string: str,
        body_bytes: bytes,
        headers: dict[str, str],
        user_id: str | None,
    ) -> GuardFinding | None:
        fields = self.parser.parse_request(query_string, body_bytes)

        context = InspectionContext(
            method=method,
            path=path,
            client_ip=client_ip,
            fields=fields,
            headers=headers,
            user_id=user_id,
        )

        for guard in self.guards:
            finding = guard.inspect(context, self.config)
            if finding is not None:
                return finding

        return None

    async def _send_block_response(
        self, send: Callable[[dict[str, Any]], Awaitable[None]], event_id: str
    ) -> None:
        payload = json.dumps(
            {
                "error": "Forbidden",
                "message": self.config.block_message,
                "incident_id": event_id,
            }
        ).encode("utf-8")

        await send(
            {
                "type": "http.response.start",
                "status": self.config.block_status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode("ascii")),
                    (b"x-protected-by", b"PyWard-RASP"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})

    async def _send_dlp_block_response(
        self, send: Callable[[dict[str, Any]], Awaitable[None]], event_id: str
    ) -> None:
        """ตอบกลับข้อความ Error กลางที่ปลอดภัยแทน Response ที่มีข้อมูลลับรั่วไหล"""
        payload = json.dumps(
            {
                "error": "Internal Server Error",
                "message": "Response redacted by PyWard RASP to prevent sensitive data exposure.",
                "incident_id": event_id,
            }
        ).encode("utf-8")

        await send(
            {
                "type": "http.response.start",
                "status": 500,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode("ascii")),
                    (b"x-protected-by", b"PyWard-RASP"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})