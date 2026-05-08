from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes_analyze import router as analyze_router
from app.api.routes_ui import router as ui_router
from app.api.routes_upload import router as upload_router
from app.core.config import settings


def create_app() -> FastAPI:
    app = FastAPI(title=settings.APP_NAME)
    app.include_router(ui_router)
    app.include_router(upload_router)
    app.include_router(analyze_router)
    app.mount('/static', StaticFiles(directory='app/static'), name='static')
    return app


app = create_app()
