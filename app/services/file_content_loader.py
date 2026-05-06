import hashlib
from pathlib import Path

from app.core.config import settings
from app.models.schemas import FileAnalysisResult, FileContent, FileContentLoadResult, UploadAnalysisResponse


def _is_within_base(path: Path, base: Path) -> bool:
    if hasattr(path, 'is_relative_to'):
        return path.is_relative_to(base)
    base_str = str(base)
    path_str = str(path)
    return path_str == base_str or path_str.startswith(base_str + '/')


def _skipped(file_result: FileAnalysisResult, reason: str, reason_code: str) -> FileAnalysisResult:
    return file_result.model_copy(update={'include': False, 'reason': reason, 'reason_code': reason_code})


def load_file_contents(extracted_dir: Path, scan_result: UploadAnalysisResponse) -> FileContentLoadResult:
    base_dir = extracted_dir.resolve()
    loaded: list[FileContent] = []
    skipped: list[FileAnalysisResult] = []

    for file_result in scan_result.files:
        if not file_result.include:
            skipped.append(_skipped(file_result, file_result.reason, 'SKIPPED_NOT_INCLUDED'))
            continue

        candidate_path = (base_dir / file_result.path).resolve()
        if not _is_within_base(candidate_path, base_dir):
            skipped.append(_skipped(file_result, 'path traversal attempt', 'SKIPPED_PATH_TRAVERSAL'))
            continue

        if not candidate_path.exists():
            skipped.append(_skipped(file_result, 'file not found', 'SKIPPED_NOT_FOUND'))
            continue

        if not candidate_path.is_file():
            skipped.append(_skipped(file_result, 'not a regular file', 'SKIPPED_NOT_FILE'))
            continue

        if candidate_path.stat().st_size > settings.MAX_FILE_SIZE_BYTES:
            skipped.append(_skipped(file_result, 'file too large', 'SKIPPED_TOO_LARGE'))
            continue

        try:
            raw = candidate_path.read_bytes()
        except OSError:
            skipped.append(_skipped(file_result, 'failed to read file', 'SKIPPED_READ_ERROR'))
            continue

        try:
            content = raw.decode('utf-8')
        except UnicodeDecodeError:
            skipped.append(_skipped(file_result, 'decode failed', 'SKIPPED_DECODE_ERROR'))
            continue

        content_hash = hashlib.sha256(raw).hexdigest()
        loaded.append(
            FileContent(
                path=file_result.path,
                extension=file_result.extension,
                size=file_result.size,
                priority=file_result.priority,
                reason_code=file_result.reason_code,
                content_hash=content_hash,
                content=content,
            )
        )

    return FileContentLoadResult(
        total_candidates=len(scan_result.files),
        loaded_count=len(loaded),
        skipped_count=len(skipped),
        files=loaded,
        skipped=skipped,
    )
