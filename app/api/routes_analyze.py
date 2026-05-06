import shutil

from fastapi import APIRouter, File, UploadFile

from app.models.schemas import FullAnalysisResponse
from app.services.analysis_service import analyze_chunks
from app.services.chunk_service import build_chunks
from app.services.file_content_loader import load_file_contents
from app.services.scan_service import scan_extracted_directory
from app.services.upload_service import prepare_uploaded_zip

router = APIRouter(prefix='/api')


@router.post('/analyze', response_model=FullAnalysisResponse)
async def analyze_zip(file: UploadFile = File(...)):
    workspace, extracted_dir = await prepare_uploaded_zip(file)
    try:
        upload_result = scan_extracted_directory(extracted_dir)
        content_result = load_file_contents(extracted_dir, upload_result)
        chunk_result = build_chunks(content_result.files)
        analysis_result = analyze_chunks(chunk_result.chunks)
        return FullAnalysisResponse(
            upload=upload_result,
            content_load=content_result,
            chunks=chunk_result,
            analysis=analysis_result,
        )
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
