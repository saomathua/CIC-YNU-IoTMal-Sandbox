"""Mandatory API allowlist for requests coming from the QEMU guest (CT-01, design §5).

The client address is taken from the ASGI scope, i.e. the real TCP peer as
seen by uvicorn (server.py runs uvicorn with proxy_headers=False). Forwarding
headers such as X-Forwarded-For are never consulted.
"""
import ipaddress
import json
import logging
from typing import Callable, Optional

from isolation import constants as C
from isolation import current_task

logger = logging.getLogger(__name__)


def _peer_ip(scope) -> Optional[ipaddress._BaseAddress]:
    client = scope.get("client")
    if not client:
        return None
    try:
        ip = ipaddress.ip_address(client[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip


def is_guest(scope) -> bool:
    ip = _peer_ip(scope)
    # Unknown peers are treated as guest traffic: deny by default.
    return ip is None or ip in C.GUEST_NET


def guest_allowed(method: str, path: str, base_url: str, task_id: Optional[str]) -> bool:
    if not task_id:
        return False
    allowed = {
        ("GET", f"{base_url}/get-task/{task_id}/file"),
        ("POST", f"{base_url}/update-task/{task_id}/strace"),
        ("POST", f"{base_url}/update-task/{task_id}/sar"),
    }
    return (method, path) in allowed


class GuestAllowlistMiddleware:
    def __init__(self, app, base_url: str,
                 current: Callable[[], Optional[str]] = lambda: current_task.get_current()):
        self.app = app
        self.base_url = base_url.rstrip("/")
        self.current = current

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket") or not is_guest(scope):
            return await self.app(scope, receive, send)

        method = scope.get("method", "WEBSOCKET") if scope["type"] == "http" else "WEBSOCKET"
        path = scope.get("path", "")
        if scope["type"] == "http" and guest_allowed(method, path, self.base_url, self.current()):
            return await self.app(scope, receive, send)

        client = scope.get("client")
        logger.warning("guest request denied: client=%s method=%s path=%s", client, method, path)
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps({"detail": "forbidden"}).encode()
        await send({"type": "http.response.start", "status": 403,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
