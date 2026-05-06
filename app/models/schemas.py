from pydantic import BaseModel


class InclusionDecision(BaseModel):
    include: bool
    reason: str
    reason_code: str
    priority: int


class FileAnalysisResult(BaseModel):
    path: str
    extension: str
    size: int
    reason: str
    reason_code: str
    priority: int
    content_hash: str | None = None


class UploadAnalysisResponse(BaseModel):
    total_files_scanned: int
    included_count: int
    excluded_count: int
    files: list[FileAnalysisResult]
