import shutil

from fastapi import APIRouter, File, UploadFile

from app.models.schemas import FullAnalysisResponse
from app.services.analysis_service import analyze_chunks
from app.services.chunk_service import build_chunks
from app.services.console_poc_analysis_service import analyze_console_exploitability
from app.services.file_content_loader import load_file_contents
from app.services.response_mapper import to_safe_chunk_result, to_safe_content_load_result
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
        readable_result = analyze_console_exploitability(content_result.files)
        return FullAnalysisResponse(
            upload=upload_result,
            content_load=to_safe_content_load_result(content_result),
            chunks=to_safe_chunk_result(chunk_result),
            analysis=analysis_result.model_copy(update={'skipped_chunks': []}),
            readable_analysis=readable_result,
        )
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
