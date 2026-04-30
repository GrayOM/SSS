from pydantic import BaseModel


class FileAnalysisResult(BaseModel):
    path: str
    extension: str
    size: int
    reason: str


class UploadAnalysisResponse(BaseModel):
    total_files_scanned: int
    included_count: int
    excluded_count: int
    files: list[FileAnalysisResult]
