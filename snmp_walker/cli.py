from __future__ import annotations

import argparse
import logging
import threading
import time
import webbrowser

from .config import ServerConfig
from .web import create_app


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    log = logging.getLogger("snmp_walker")
    log.setLevel(level)
    if log.handlers:
        return
    fh = logging.FileHandler("snmp_walker.log")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s"))
    log.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    log.addHandler(ch)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the SNMP Walker Legacy Network web app.")
    parser.add_argument("--host", default=None, help="Bind address. Use 0.0.0.0 on a server.")
    parser.add_argument("--port", type=int, default=None, help="TCP port to listen on.")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser automatically.")
    parser.add_argument("--debug", action="store_true", help="Run Flask debug mode.")
    parser.add_argument("--production", action="store_true", help="Run with Waitress instead of Flask's dev server.")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    env_config = ServerConfig.from_env()
    host = args.host or env_config.host
    port = args.port or env_config.port
    open_browser = env_config.open_browser and not args.no_browser
    debug = env_config.debug or args.debug
    production = env_config.production or args.production

    setup_logging(debug)
    app = create_app()
    if open_browser and host in {"127.0.0.1", "localhost"}:
        threading.Thread(target=open_browser_later, args=(port,), daemon=True).start()
    if production:
        from waitress import serve

        serve(app, host=host, port=port)
    else:
        app.run(host=host, port=port, debug=debug)


def open_browser_later(port: int) -> None:
    time.sleep(1)
    webbrowser.open(f"http://127.0.0.1:{port}")
