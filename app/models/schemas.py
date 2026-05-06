from pydantic import BaseModel, Field


class InclusionDecision(BaseModel):
    include: bool
    reason: str
    reason_code: str
    priority: int


class FileAnalysisResult(BaseModel):
    path: str
    extension: str
    size: int
    include: bool
    reason: str
    reason_code: str
    priority: int
    content_hash: str | None = None


class UploadAnalysisResponse(BaseModel):
    total_files_scanned: int
    included_count: int
    excluded_count: int
    files: list[FileAnalysisResult]


class FileContent(BaseModel):
    path: str
    extension: str
    size: int
    priority: int
    reason_code: str
    content_hash: str
    content: str


class FileContentLoadResult(BaseModel):
    total_candidates: int
    loaded_count: int
    skipped_count: int
    files: list[FileContent]
    skipped: list[FileAnalysisResult]


class CodeChunk(BaseModel):
    source_path: str
    extension: str
    priority: int
    source_content_hash: str
    chunk_index: int
    total_chunks: int
    start_line: int
    end_line: int
    chunk_hash: str
    content: str


class ChunkBuildResult(BaseModel):
    total_files: int
    total_chunks: int
    files_chunked: int
    files_skipped: int
    chunks: list[CodeChunk]
    skipped: list[FileContent]


class AnalysisEvidence(BaseModel):
    source_path: str
    start_line: int
    end_line: int
    snippet: str
    reason: str


class VulnerabilityFinding(BaseModel):
    id: str
    vulnerability_type: str
    severity: str
    confidence: str
    source_path: str
    start_line: int
    end_line: int
    evidence: list[AnalysisEvidence]
    attack_scenario: list[str]
    safe_poc: str | None = None
    impact: str
    root_cause: str
    remediation: str
    related_cwe: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    total_chunks: int
    analyzed_chunks: int
    finding_count: int
    findings: list[VulnerabilityFinding]
    skipped_chunks: list[CodeChunk] = Field(default_factory=list)
