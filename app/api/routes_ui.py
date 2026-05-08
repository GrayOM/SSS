<<<<<<< codex/design-project-folder-structure-c81r2e
from pathlib import Path

=======
>>>>>>> main
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
<<<<<<< codex/design-project-folder-structure-c81r2e

BASE_DIR = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = BASE_DIR / 'templates'

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
=======
templates = Jinja2Templates(directory='app/templates')
>>>>>>> main


@router.get('/', response_class=HTMLResponse)
def index(request: Request):
<<<<<<< codex/design-project-folder-structure-c81r2e
    return templates.TemplateResponse(
        request=request,
        name='index.html',
        context={},
    )
=======
    return templates.TemplateResponse('index.html', {'request': request})
>>>>>>> main
