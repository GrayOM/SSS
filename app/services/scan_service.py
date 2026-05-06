from pathlib import Path

from app.models.schemas import FileAnalysisResult, UploadAnalysisResponse
from app.services.file_filter_service import should_include_file


def scan_extracted_directory(extracted_dir: Path) -> UploadAnalysisResponse:
    results: list[FileAnalysisResult] = []
    included_count = 0
    excluded_count = 0
    scanned = 0

    for path in extracted_dir.rglob('*'):
        if not path.is_file():
            continue
        scanned += 1
        decision = should_include_file(path)

        if decision.include:
            included_count += 1
        else:
            excluded_count += 1

        results.append(
            FileAnalysisResult(
                path=str(path.relative_to(extracted_dir)),
                extension=path.suffix.lower(),
                size=path.stat().st_size,
                reason=decision.reason,
                reason_code=decision.reason_code,
                priority=decision.priority,
                content_hash=None,
            )
        )

    return UploadAnalysisResponse(
        total_files_scanned=scanned,
        included_count=included_count,
        excluded_count=excluded_count,
        files=results,
    )
