"""FastAPI application factory and resource lifespan."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .batchworker import build_worker
from .config import AUDIO_WORKERS, DEFAULT_MODEL, logger
from .model import get_model, load_model
from .routes import router
from .security import AuthMiddleware, is_auth_enabled


def _shutdown_pool(pool: ThreadPoolExecutor) -> None:
    pool.shutdown(wait=True, cancel_futures=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.ready = False
    app.state.worker = None
    app.state.audio_pool = ThreadPoolExecutor(
        max_workers=AUDIO_WORKERS, thread_name_prefix="audio"
    )
    try:
        logger.info("Lifespan startup: loading default model")
        await asyncio.to_thread(load_model, DEFAULT_MODEL)
        app.state.worker = build_worker(get_model)
        await app.state.worker.start()
        app.state.ready = True
        logger.info("Service ready")
        yield
    finally:
        app.state.ready = False
        logger.info("Lifespan shutdown")
        if app.state.worker is not None:
            await app.state.worker.stop()
        await asyncio.to_thread(_shutdown_pool, app.state.audio_pool)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Parakeet TDT 0.6B v3 (optimized)",
        version="1.1.0",
        description=(
            "High-throughput OpenAI-compatible ASR service for "
            "Parakeet TDT 0.6B v3."
        ),
        lifespan=lifespan,
        # Docs (/docs, /redoc, /openapi.json) are served and protected by the
        # same credentials as everything else via AuthMiddleware (added below).
        # Their "Try it out" calls carry the caller's credentials (click
        # "Authorize" and paste the API_KEY as Bearer).
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    app.include_router(router)
    # AuthMiddleware is added LAST so Starlette wraps it as the outermost
    # layer: it runs before routing and therefore also protects FastAPI's
    # built-in docs (/docs, /redoc, /openapi.json) and any mounted sub-app,
    # none of which are covered by router-level dependencies. /health and
    # /healthz stay open for orchestrators and the Docker HEALTHCHECK.
    app.add_middleware(AuthMiddleware)
    if is_auth_enabled():
        logger.info(
            "Authentication enabled: /docs, /redoc, /openapi.json and all "
            "API/UI routes require credentials. /health and /healthz remain "
            "open for orchestrators and the Docker HEALTHCHECK."
        )
    return app


app = create_app()
