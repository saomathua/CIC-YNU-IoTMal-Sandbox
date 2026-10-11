import uvicorn
from fastapi import FastAPI

from router import healthcheck, sandbox_router
from util.lifespan_handlers import lifespan
from config.settings import app_settings
from isolation.apifilter import GuestAllowlistMiddleware

app = FastAPI(lifespan=lifespan)

# Mandatory guest API allowlist (CT-01): requests from the guest network may only
# reach the current task's file download and log upload routes.
app.add_middleware(GuestAllowlistMiddleware, base_url=app_settings.app_base_url)

# Add Routers here.
app.include_router(healthcheck.router)
app.include_router(sandbox_router.router)


def uvicorn_options() -> dict:
    return dict(host=app_settings.host, port=app_settings.port,
                limit_concurrency=app_settings.app_limit_concurrency, backlog=app_settings.app_backlog,
                timeout_keep_alive=app_settings.app_timeout_keep_alive, log_level="info",
                # The client address must be the real TCP peer; never trust
                # X-Forwarded-For / Forwarded headers (the guest could set them).
                proxy_headers=False, forwarded_allow_ips="")


if __name__ == "__main__":
    uvicorn.run(app, **uvicorn_options())
