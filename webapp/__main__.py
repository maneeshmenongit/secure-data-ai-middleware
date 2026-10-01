"""Run the demo console: uv run --group webapp python -m webapp"""

from __future__ import annotations

import argparse

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def check_host(host: str) -> None:
    if host not in LOOPBACK:
        raise SystemExit(f"refusing to bind to {host!r}: the demo console is local-only (use 127.0.0.1)")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="DataSec demo console")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    check_host(args.host)

    from dotenv import load_dotenv
    import uvicorn

    load_dotenv()  # API keys stay server-side; nothing here prints them
    from .app import create_app

    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
