"""FastAPI application factory."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from hb_zayfer.web.routes import router
import hb_zayfer as hbz

STATIC_DIR = Path(__file__).parent / "static"

# Bearer token for API authentication.
# Set HB_ZAYFER_API_TOKEN env-var to require token auth on every request.
# If unset, the API is openly accessible (suitable for local-only use).
_API_TOKEN: str | None = os.environ.get("HB_ZAYFER_API_TOKEN")


def create_app() -> FastAPI:
    """Create and configure the FastAPI app."""
    app = FastAPI(
        title="HB_Zayfer",
        description="Encryption/Decryption Suite — Web Interface",
        version=hbz.version(),
    )

    # CORS — restrict to localhost origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Bearer-token auth middleware (if token is configured)
    @app.middleware("http")
    async def _auth_middleware(request: Request, call_next):
        if _API_TOKEN is not None:
            # Allow static files and docs without auth
            path = request.url.path
            if not (path.startswith("/static") or path == "/" or path.startswith("/docs") or path.startswith("/openapi")):
                auth = request.headers.get("authorization", "")
                if auth != f"Bearer {_API_TOKEN}":
                    return JSONResponse({"detail": "Unauthorized"}, status_code=401)
        return await call_next(request)

    app.include_router(router, prefix="/api")

    # Serve static files (HTML/JS/CSS)
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static-assets")
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="spa")

    return app


def main() -> None:
    """Run the web server via uvicorn."""
    import uvicorn

    app = create_app()
    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
