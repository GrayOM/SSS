from app.models.schemas import (
    AnalysisResult,
    ChunkBuildResult,
    ChunkSummaryResult,
    CodeChunkSummary,
    FileContentLoadResult,
    FileContentSummary,
    FileContentSummaryResult,
)


def to_safe_content_load_result(content_result: FileContentLoadResult) -> FileContentSummaryResult:
    return FileContentSummaryResult(
        total_candidates=content_result.total_candidates,
        loaded_count=content_result.loaded_count,
        skipped_count=content_result.skipped_count,
        files=[
            FileContentSummary(
                path=f.path, extension=f.extension, size=f.size, priority=f.priority, reason_code=f.reason_code, content_hash=f.content_hash
            )
            for f in content_result.files
        ],
        skipped=content_result.skipped,
    )


def to_safe_chunk_result(chunk_result: ChunkBuildResult) -> ChunkSummaryResult:
    return ChunkSummaryResult(
        total_files=chunk_result.total_files,
        total_chunks=chunk_result.total_chunks,
        files_chunked=chunk_result.files_chunked,
        files_skipped=chunk_result.files_skipped,
        chunks=[
            CodeChunkSummary(
                source_path=c.source_path,
                extension=c.extension,
                priority=c.priority,
                source_content_hash=c.source_content_hash,
                chunk_index=c.chunk_index,
                total_chunks=c.total_chunks,
                start_line=c.start_line,
                end_line=c.end_line,
                chunk_hash=c.chunk_hash,
            )
            for c in chunk_result.chunks
        ],
        skipped=[
            FileContentSummary(
                path=f.path, extension=f.extension, size=f.size, priority=f.priority, reason_code=f.reason_code, content_hash=f.content_hash
            )
            for f in chunk_result.skipped
        ],
    )


def to_safe_analysis_result(result: AnalysisResult) -> AnalysisResult:
    return result.model_copy(update={'skipped_chunks': []})
