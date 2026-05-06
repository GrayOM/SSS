import os
import shutil
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.core.config import settings
from app.models.schemas import UploadAnalysisResponse
from app.services.scan_service import scan_extracted_directory
from app.services.zip_service import ZipSecurityError, extract_zip, prepare_workspace

router = APIRouter(prefix='/api')


@router.get('/health')
def health() -> dict[str, str]:
    return {'status': 'ok'}


@router.post('/upload', response_model=UploadAnalysisResponse)
async def upload_zip(file: UploadFile = File(...)):
    safe_name = Path(file.filename or '').name
    if not safe_name or safe_name != file.filename or not safe_name.lower().endswith('.zip'):
        raise HTTPException(status_code=400, detail='Invalid ZIP filename')

    os.makedirs(settings.TMP_DIR, exist_ok=True)
    workspace = Path(prepare_workspace())
    upload_path = workspace / safe_name

    try:
        content = await file.read()
        if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
            raise HTTPException(status_code=413, detail='Upload exceeds 20MB limit')

        # ZIP local file header signature check (PK\x03\x04)
        if len(content) < 2 or not content.startswith(b'PK'):
            raise HTTPException(status_code=400, detail='Invalid ZIP signature')

        upload_path.write_bytes(content)

        try:
            extracted_dir = extract_zip(upload_path, workspace)
        except ZipSecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f'Invalid ZIP: {exc}') from exc

        return scan_extracted_directory(extracted_dir)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
