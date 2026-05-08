from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = BASE_DIR / 'templates'

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get('/', response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name='index.html',
        context={},
    )
