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


class ConsoleSafePoc(BaseModel):
    poc_type: str
    description: str
    preconditions: list[str]
    steps: list[str]
    code: str | None = None
    expected_result: str
    safety: str


class ReadableEvidence(BaseModel):
    source_path: str
    start_line: int
    end_line: int
    snippet: str
    reason: str
    data_flow: list[str] = Field(default_factory=list)


class ReadableFinding(BaseModel):
    id: str
    title: str
    vulnerability_type: str
    severity: str
    confidence: str
    affected_files: list[str]
    summary: str
    evidence: list[ReadableEvidence]
    console_poc: ConsoleSafePoc | None = None
    attack_scenario: list[str]
    impact: str
    root_cause: str
    remediation: str
    verification_notes: list[str] = Field(default_factory=list)
    related_cwe: list[str] = Field(default_factory=list)


class ReadableAnalysisResult(BaseModel):
    finding_count: int
    findings: list[ReadableFinding]
    analyzed_focus: list[str] = Field(default_factory=list)


class FileContentSummary(BaseModel):
    path: str
    extension: str
    size: int
    priority: int
    reason_code: str
    content_hash: str


class FileContentSummaryResult(BaseModel):
    total_candidates: int
    loaded_count: int
    skipped_count: int
    files: list[FileContentSummary]
    skipped: list[FileAnalysisResult]


class CodeChunkSummary(BaseModel):
    source_path: str
    extension: str
    priority: int
    source_content_hash: str
    chunk_index: int
    total_chunks: int
    start_line: int
    end_line: int
    chunk_hash: str


class ChunkSummaryResult(BaseModel):
    total_files: int
    total_chunks: int
    files_chunked: int
    files_skipped: int
    chunks: list[CodeChunkSummary]
    skipped: list[FileContentSummary]


class FullAnalysisResponse(BaseModel):
    upload: UploadAnalysisResponse
    content_load: FileContentSummaryResult
    chunks: ChunkSummaryResult
    analysis: AnalysisResult
    readable_analysis: ReadableAnalysisResult | None = None
