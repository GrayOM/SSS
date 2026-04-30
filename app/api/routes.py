import os
import shutil
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.core.config import settings
from app.models.schemas import FileAnalysisResult, UploadAnalysisResponse
from app.services.file_filter_service import should_include_file
from app.services.zip_service import ZipSecurityError, extract_zip, prepare_workspace

router = APIRouter()
templates = Jinja2Templates(directory='app/templates')


@router.get('/health')
def health() -> dict[str, str]:
    return {'status': 'ok'}


@router.get('/', response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse('index.html', {'request': request})


@router.post('/api/upload', response_model=UploadAnalysisResponse)
async def upload_zip(file: UploadFile = File(...)):
    if not file.filename.lower().endswith('.zip'):
        raise HTTPException(status_code=400, detail='Only ZIP files are allowed')

    os.makedirs(settings.TMP_DIR, exist_ok=True)
    workspace = Path(prepare_workspace())
    upload_path = workspace / file.filename

    try:
        content = await file.read()
        if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
            raise HTTPException(status_code=413, detail='Upload exceeds 20MB limit')

        upload_path.write_bytes(content)

        try:
            extracted_dir = extract_zip(upload_path, workspace)
        except ZipSecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f'Invalid ZIP: {exc}') from exc

        results: list[FileAnalysisResult] = []
        included_count = 0
        excluded_count = 0
        scanned = 0

        for path in extracted_dir.rglob('*'):
            if not path.is_file():
                continue
            scanned += 1
            include, reason = should_include_file(path)
            if include:
                included_count += 1
            else:
                excluded_count += 1

            results.append(
                FileAnalysisResult(
                    path=str(path.relative_to(extracted_dir)),
                    extension=path.suffix.lower(),
                    size=path.stat().st_size,
                    reason=reason,
                )
            )

        return UploadAnalysisResponse(
            total_files_scanned=scanned,
            included_count=included_count,
            excluded_count=excluded_count,
            files=results,
        )
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
