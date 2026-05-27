import shutil

from fastapi import APIRouter, File, UploadFile

from app.models.schemas import UploadAnalysisResponse
from app.services.scan_service import scan_extracted_directory
from app.services.upload_service import prepare_uploaded_zip

router = APIRouter(prefix='/api')


@router.get('/health')
def health() -> dict[str, str]:
    return {'status': 'ok'}


@router.post('/upload', response_model=UploadAnalysisResponse)
async def upload_zip(file: UploadFile = File(...)):
    workspace, extracted_dir = await prepare_uploaded_zip(file)
    try:
        return scan_extracted_directory(extracted_dir)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
