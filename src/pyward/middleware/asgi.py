import json
import time
from typing import Any, Awaitable, Callable

from pyward.config import WardConfig, WardMode
from pyward.core.parser import RequestParser
from pyward.guards.base import BaseGuard, GuardFinding, InspectionContext
from pyward.guards.injection import InjectionGuard
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
    ดักจับ Request Stream, แกะโครงสร้าง JSON/Query, ส่งตรวจผ่านขบวน Guard และบันทึก SIEM Log
    """

    def __init__(
        self,
        app: ASGIApp,
        config: WardConfig | None = None,
        guards: list[BaseGuard] | None = None,
    ) -> None:
        self.app = app
        self.config = config or WardConfig()
        self.logger = SecurityLogger(
            log_file=self.config.log_file,
            console_log=self.config.console_log,
        )
        # ตัวแกะข้อมูล (v0.2.0) และขบวน Guard ตรวจจับภัยคุกคาม (v0.3.0)
        self.parser = RequestParser()
        self.guards: list[BaseGuard] = guards if guards is not None else [InjectionGuard()]

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

        # 3. ดึงข้อมูลบริบทพื้นฐานจาก ASGI Scope
        method: str = scope.get("method", "GET")
        client_info = scope.get("client")
        client_ip: str = client_info[0] if client_info else "unknown"
        query_string: str = scope.get("query_string", b"").decode("utf-8", errors="replace")
        headers: dict[str, str] = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }

        # 4. ส่งข้อมูลเข้าสู่ Inspection Pipeline (Parser -> Guards)
        finding = self._run_inspection_pipeline(
            method=method,
            path=path,
            client_ip=client_ip,
            query_string=query_string,
            body_bytes=body_bytes,
            headers=headers,
        )

        # 5. ตัดสินใจเมื่อตรวจพบการโจมตี (บันทึก Log + บล็อกหรือปล่อยผ่านตามโหมด)
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
                json_path=finding.json_path,
                detail=finding.detail,
            )
            self.logger.log_event(event)

            if is_blocking:
                await self._send_block_response(send, event.event_id)
                return

        # 6. ส่งต่อ Request ที่ปลอดภัย (พร้อม Body Stream เดิม) ไปยัง FastAPI Endpoint
        await self.app(scope, replay_receive, send)

    def _is_path_excluded(self, path: str) -> bool:
        return any(
            path == excluded or path.startswith(excluded.rstrip("/") + "/")
            for excluded in self.config.excluded_paths
        )

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
    ) -> GuardFinding | None:
        """แกะโครงสร้าง Request แล้วส่งต่อให้ Guard ทุกตัวในขบวนตรวจสอบตามลำดับ"""
        fields = self.parser.parse_request(query_string, body_bytes)

        context = InspectionContext(
            method=method,
            path=path,
            client_ip=client_ip,
            fields=fields,
            headers=headers,
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