"""FastAPI application entry point."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import init_db
from .ingester import get_ingestion_loop
from .routers import alerts, chat, feedback, stats, enhancements

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    loop = get_ingestion_loop()
    loop.start()
    yield
    loop.stop()


app = FastAPI(
    title="AI SOC Analyst Assistant",
    description="AI-assisted alert analysis, threat prioritization, and incident response.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router)
app.include_router(chat.router)
app.include_router(feedback.router)
app.include_router(stats.router)
app.include_router(enhancements.router)


@app.get("/")
def root():
    return {"service": "AI SOC Analyst Assistant", "docs": "/docs", "health": "/health"}
