from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 5055
    open_browser: bool = True
    debug: bool = False
    production: bool = False

    @classmethod
    def from_env(cls) -> "ServerConfig":
        return cls(
            host=os.getenv("SNMP_WALKER_HOST", "127.0.0.1"),
            port=parse_port(os.getenv("SNMP_WALKER_PORT"), 5055),
            open_browser=parse_bool(os.getenv("SNMP_WALKER_OPEN_BROWSER"), True),
            debug=parse_bool(os.getenv("SNMP_WALKER_DEBUG"), False),
            production=parse_bool(os.getenv("SNMP_WALKER_PRODUCTION"), False),
        )


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_port(value: str | None, default: int) -> int:
    try:
        port = int(value or default)
    except (TypeError, ValueError):
        return default
    return max(1, min(65535, port))
