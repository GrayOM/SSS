import os
from pathlib import Path

from fastapi import HTTPException, UploadFile

from app.core.config import settings
from app.services.zip_service import ZipSecurityError, extract_zip, prepare_workspace


async def prepare_uploaded_zip(file: UploadFile) -> tuple[Path, Path]:
    safe_name = Path(file.filename or '').name
    if not safe_name or safe_name != file.filename or not safe_name.lower().endswith('.zip'):
        raise HTTPException(status_code=400, detail='Invalid ZIP filename')

    os.makedirs(settings.TMP_DIR, exist_ok=True)
    workspace = Path(prepare_workspace())
    upload_path = workspace / safe_name

    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail='Upload exceeds size limit')

    if len(content) < 2 or not content.startswith(b'PK'):
        raise HTTPException(status_code=400, detail='Invalid ZIP signature')

    upload_path.write_bytes(content)

    try:
        extracted_dir = extract_zip(upload_path, workspace)
    except ZipSecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f'Invalid ZIP: {exc}') from exc

    return workspace, extracted_dir
