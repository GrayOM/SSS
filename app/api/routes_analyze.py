import shutil

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.core.config import settings
from app.models.schemas import FullAnalysisResponse, RuntimeTrafficImportResult
from app.services.analysis_service import analyze_chunks
from app.services.chunk_service import build_chunks
from app.services.console_poc_analysis_service import analyze_console_exploitability, get_console_poc_analyzer
from app.services.file_content_loader import load_file_contents
from app.services.analysis_run_repository import save_analysis_run
from app.services.response_mapper import to_safe_analysis_result, to_safe_chunk_result, to_safe_content_load_result
from app.services.runtime_traffic_service import enrich_analysis_with_runtime_traffic, import_runtime_traffic
from app.services.scan_service import scan_extracted_directory
from app.services.upload_service import prepare_uploaded_zip

router = APIRouter(prefix='/api')


async def _run_source_zip_analysis(file: UploadFile) -> FullAnalysisResponse:
    workspace, extracted_dir = await prepare_uploaded_zip(file)
    try:
        try:
            upload_result = scan_extracted_directory(extracted_dir)
        except Exception as exc:
            raise HTTPException(status_code=500, detail='Scan stage failed') from exc
        try:
            content_result = load_file_contents(extracted_dir, upload_result)
        except Exception as exc:
            raise HTTPException(status_code=500, detail='Content load stage failed') from exc
        try:
            chunk_result = build_chunks(content_result.files)
        except Exception as exc:
            raise HTTPException(status_code=500, detail='Chunk build stage failed') from exc
        try:
            analysis_result = analyze_chunks(chunk_result.chunks)
        except Exception as exc:
            raise HTTPException(status_code=502, detail='Analysis backend failed') from exc
        try:
            readable_analyzer = get_console_poc_analyzer()
            readable_result = analyze_console_exploitability(content_result.files, analyzer=readable_analyzer)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail='Readable analysis backend failed') from exc
        analysis_debug = getattr(readable_analyzer, 'last_debug', None)
        response = FullAnalysisResponse(
            upload=upload_result,
            content_load=to_safe_content_load_result(content_result),
            chunks=to_safe_chunk_result(chunk_result),
            analysis=to_safe_analysis_result(analysis_result),
            readable_analysis=readable_result,
            analysis_debug=analysis_debug,
            analysis_notes=[
                'analysis is legacy chunk analyzer output.',
                'readable_analysis is console-oriented readable finding output.',
            ],
        )
        save_analysis_run(file.filename or '', response)
        return response
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


async def _read_optional_upload(file: UploadFile | None) -> bytes | None:
    if file is None or not hasattr(file, 'filename') or not (hasattr(file, 'read') or hasattr(file, 'file')):
        return None
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    total = 0
    chunks: list[bytes] = []
    raw_file = getattr(file, 'file', None)
    while True:
        chunk = raw_file.read(1024 * 1024) if raw_file is not None else await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(status_code=413, detail='Traffic upload exceeds size limit')
        chunks.append(chunk)
    return b''.join(chunks)


def _optional_upload_filename(file: UploadFile | None) -> str | None:
    return file.filename if file is not None and hasattr(file, 'filename') else None


def _optional_form_text(value: str | None) -> str | None:
    return value if isinstance(value, str) else None


@router.post('/analyze', response_model=FullAnalysisResponse)
async def analyze_zip(file: UploadFile = File(...)):
    return await _run_source_zip_analysis(file)


@router.post('/analyze-with-traffic', response_model=FullAnalysisResponse)
async def analyze_zip_with_traffic(
    source_zip: UploadFile = File(...),
    traffic_file: UploadFile | None = File(None),
    traffic_text: str | None = Form(None),
):
    response = await _run_source_zip_analysis(source_zip)
    traffic_bytes = await _read_optional_upload(traffic_file)
    traffic_result = import_runtime_traffic(
        filename=_optional_upload_filename(traffic_file),
        content=traffic_bytes,
        text=_optional_form_text(traffic_text),
    )
    if not traffic_result.provided:
        response.analysis_notes.append('No runtime traffic provided; source-only analysis used.')
    else:
        traffic_result = enrich_analysis_with_runtime_traffic(response.readable_analysis, traffic_result)
    response.runtime_traffic = traffic_result
    return response


@router.post('/import-traffic', response_model=RuntimeTrafficImportResult)
async def import_traffic(
    traffic_file: UploadFile | None = File(None),
    traffic_text: str | None = Form(None),
):
    traffic_bytes = await _read_optional_upload(traffic_file)
    return import_runtime_traffic(
        filename=_optional_upload_filename(traffic_file),
        content=traffic_bytes,
        text=_optional_form_text(traffic_text),
    )
