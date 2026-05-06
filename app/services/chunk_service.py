import hashlib

from app.core.config import settings
from app.models.schemas import ChunkBuildResult, CodeChunk, FileContent


def build_chunks(file_contents: list[FileContent]) -> ChunkBuildResult:
    max_lines = settings.MAX_CHUNK_LINES
    overlap = settings.CHUNK_OVERLAP_LINES

    if overlap >= max_lines:
        raise ValueError('CHUNK_OVERLAP_LINES must be smaller than MAX_CHUNK_LINES')

    chunks: list[CodeChunk] = []
    skipped: list[FileContent] = []
    files_chunked = 0

    for file_content in file_contents:
        if not file_content.content:
            skipped.append(file_content)
            continue

        lines = file_content.content.splitlines()
        if not lines:
            skipped.append(file_content)
            continue

        file_chunk_specs: list[tuple[int, int]] = []
        if len(lines) <= max_lines:
            file_chunk_specs.append((1, len(lines)))
        else:
            start = 1
            while start <= len(lines):
                end = min(start + max_lines - 1, len(lines))
                file_chunk_specs.append((start, end))
                if end == len(lines):
                    break
                start = end - overlap + 1

        total_for_file = len(file_chunk_specs)
        files_chunked += 1

        for idx, (start_line, end_line) in enumerate(file_chunk_specs):
            chunk_content = '\n'.join(lines[start_line - 1:end_line])
            chunk_hash = hashlib.sha256(chunk_content.encode('utf-8')).hexdigest()

            chunks.append(
                CodeChunk(
                    source_path=file_content.path,
                    extension=file_content.extension,
                    priority=file_content.priority,
                    source_content_hash=file_content.content_hash,
                    chunk_index=idx,
                    total_chunks=total_for_file,
                    start_line=start_line,
                    end_line=end_line,
                    chunk_hash=chunk_hash,
                    content=chunk_content,
                )
            )

    return ChunkBuildResult(
        total_files=len(file_contents),
        total_chunks=len(chunks),
        files_chunked=files_chunked,
        files_skipped=len(skipped),
        chunks=chunks,
        skipped=skipped,
    )
