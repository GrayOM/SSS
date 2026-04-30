from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.core.config import settings


def create_app() -> FastAPI:
    app = FastAPI(title=settings.APP_NAME)
    app.include_router(router)
    app.mount('/static', StaticFiles(directory='app/static'), name='static')
    return app


app = create_app()
