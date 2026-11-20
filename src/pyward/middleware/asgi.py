import json
import time
from typing import Any, Callable, Awaitable

from pyward.config import WardConfig, WardMode
from pyward.telemetry.logger import SecurityEvent, SecurityLogger

ASGIApp = Callable[[dict[str, Any], Callable[[], Awaitable[dict[str, Any]]], Callable[[dict[str, Any]], Awaitable[None]]], Awaitable[None]]


class PyWardMiddleware:
    """
    Pure ASGI Security Middleware สำหรับ FastAPI / Starlette
    ทำหน้าที่ดักจับ Request/Response Stream, ตรวจสอบบริบทเชิงลึก และบังคับใช้นโยบายความปลอดภัย
    """

    def __init__(self, app: ASGIApp, config: WardConfig | None = None) -> None:
        self.app = app
        self.config = config or WardConfig()
        self.logger = SecurityLogger(
            log_file=self.config.log_file,
            console_log=self.config.console_log,
        )

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        # ทำงานเฉพาะ HTTP Request (ข้าม WebSocket หรือ Lifespan events)
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "/")

        # 1. ตรวจสอบ Path Whitelist
        if self._is_path_excluded(path):
            await self.app(scope, receive, send)
            return

        start_time = time.perf_counter()

        # 2. อ่าน Request Body อย่างปลอดภัยและเตรียม Stream Replay ให้ FastAPI ใช้งานต่อ
        body_bytes, replay_receive = await self._buffer_request_body(receive)

        # 3. ดึงข้อมูลพื้นฐานของ Request
        method: str = scope.get("method", "GET")
        client_info = scope.get("client")
        client_ip: str = client_info[0] if client_info else "unknown"
        query_string: str = scope.get("query_string", b"").decode("utf-8", errors="replace")

        # 4. จุดเชื่อมต่อ Inspection Pipeline (จะเติม Guards ในเฟสที่ 2 และ 3)
        finding = self._run_inspection_pipeline(
            method=method,
            path=path,
            query_string=query_string,
            body_bytes=body_bytes,
            scope=scope,
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
                inspection_vector=finding["vector"],
                attack_type=finding["attack_type"],
                rule_id=finding["rule_id"],
                action=action,
                status_code=status_code,
                latency_us=latency_us,
                json_path=finding.get("json_path"),
                detail=finding.get("detail"),
            )
            self.logger.log_event(event)

            if is_blocking:
                await self._send_block_response(send, event.event_id)
                return

        # 5. ส่งต่อ Request ที่ปลอดภัย (พร้อม Body Stream เดิม) ไปยัง FastAPI Endpoint
        await self.app(scope, replay_receive, send)

    def _is_path_excluded(self, path: str) -> bool:
        return any(path == excluded or path.startswith(excluded.rstrip("/") + "/") for excluded in self.config.excluded_paths)

    async def _buffer_request_body(
        self, receive: Callable[[], Awaitable[dict[str, Any]]]
    ) -> tuple[bytes, Callable[[], Awaitable[dict[str, Any]]]]:
        """อ่าน Body ทั้งหมดเก็บไว้ใน Memory และสร้างฟังก์ชัน receive ใหม่เพื่อคืนค่าให้ Endpoint"""
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
        query_string: str,
        body_bytes: bytes,
        scope: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Placeholder สำหรับเชื่อมต่อ Normalizer และ Guards ในเฟส 2 และ 3"""
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