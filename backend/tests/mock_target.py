import asyncio
import contextlib
from threading import Thread

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse


def build_app() -> FastAPI:
    app = FastAPI(title="AETHER Mock Target")

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return """
        <html>
          <head>
            <title>Mock Target</title>
          </head>
          <body>
            <h1>Mock Target</h1>
            <p>This fixture intentionally omits common security headers.</p>
            <iframe src="/admin" title="admin" style="width:100%;height:240px;border:1px solid #ccc;"></iframe>
          </body>
        </html>
        """

    @app.get("/admin", response_class=HTMLResponse)
    async def admin() -> str:
        return "<html><body><h2>Admin Console</h2><p>Frameable by design for header-audit validation.</p></body></html>"

    @app.get("/api/debug", response_class=JSONResponse)
    async def api_debug() -> dict:
        return {
            "mode": "debug",
            "notes": [
                "Missing HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy headers are expected.",
                "Use this fixture only for local validation.",
            ],
        }

    @app.get("/healthz", response_class=PlainTextResponse)
    async def healthcheck() -> str:
        return "ok"

    return app


app = build_app()


def run_server(port: int) -> uvicorn.Server:
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = Thread(target=server.run, daemon=True)
    thread.start()
    server._thread = thread  # type: ignore[attr-defined]
    return server


async def main() -> None:
    ports = [8001, 8080, 3000, 5000]
    servers = [run_server(port) for port in ports]

    print("Mock target online:")
    for port in ports:
        print(f"  http://127.0.0.1:{port}")
    print("Use http://127.0.0.1:8001 as the scan target to verify open-port and header findings.")

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.should_exit = True
            thread = getattr(server, "_thread", None)
            if thread is not None:
                thread.join(timeout=5)


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
