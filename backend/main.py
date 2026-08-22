from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from db import init_db, migrate_db

# Import routers
from auth.router import router as auth_router
from vault.router import router as vault_router
from firewall.router import router as firewall_router
from integrity.router import router as integrity_router
from phishing.router import router as phishing_router
from network.router import router as network_router
from alerts.router import router as alerts_router
from reports.router import router as reports_router
from settings.router import router as settings_router, start_scheduler, stop_scheduler
from security_score.router import router as security_score_router
from logs_router import router as logs_router
from timeline.router import router as timeline_router
from activity_monitor.router import router as activity_router
from activity_monitor.daemon import start_activity_monitor, stop_activity_monitor

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database schema on application startup
    init_db()
    # Apply safe schema migrations (Lock 3 tables, new columns)
    migrate_db()
    # Start automated background backup scheduler
    start_scheduler()
    # Start activity monitor daemon (if enabled in settings)
    start_activity_monitor()
    yield
    # Stop background scheduler cleanly on shutdown
    stop_scheduler()
    # Stop activity monitor daemon
    stop_activity_monitor()

app = FastAPI(title="LogVigil API", lifespan=lifespan)

# Allow requests from the React development server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Hello LogVigil"}

# Register all routes
app.include_router(auth_router)
app.include_router(vault_router)
app.include_router(firewall_router)
app.include_router(integrity_router)
app.include_router(phishing_router)
app.include_router(network_router)
app.include_router(alerts_router)
app.include_router(reports_router)
app.include_router(settings_router)
app.include_router(security_score_router)
app.include_router(logs_router)
app.include_router(timeline_router)
app.include_router(activity_router)
