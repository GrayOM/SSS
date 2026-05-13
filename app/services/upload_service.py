import os
import shutil
from pathlib import Path

from fastapi import HTTPException, UploadFile

from app.core.config import settings
from app.services.zip_service import ZipSecurityError, extract_zip, prepare_workspace


async def prepare_uploaded_zip(file: UploadFile) -> tuple[Path, Path]:
    workspace: Path | None = None
    try:
        safe_name = Path(file.filename or '').name
        if not safe_name or safe_name != file.filename or not safe_name.lower().endswith('.zip'):
            raise HTTPException(status_code=400, detail='Invalid ZIP filename')

        os.makedirs(settings.TMP_DIR, exist_ok=True)
        workspace = Path(prepare_workspace())
        upload_path = workspace / safe_name

        max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        total = 0
        first_bytes = b''
        with upload_path.open('wb') as dst:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise HTTPException(status_code=413, detail='Upload exceeds size limit')
                if len(first_bytes) < 4:
                    first_bytes += chunk[: 4 - len(first_bytes)]
                dst.write(chunk)

        if len(first_bytes) < 2 or not first_bytes.startswith(b'PK'):
            raise HTTPException(status_code=400, detail='Invalid ZIP signature')

        try:
            extracted_dir = extract_zip(upload_path, workspace)
        except ZipSecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f'Invalid ZIP: {exc}') from exc

        return workspace, extracted_dir
    except Exception:
        if workspace is not None:
            shutil.rmtree(workspace, ignore_errors=True)
        raise
