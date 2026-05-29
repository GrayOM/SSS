from typing import Any

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


class BreakpointHint(BaseModel):
    source_path: str
    start_line: int
    end_line: int
    function_name: str | None = None
    reason: str
    watch_variables: list[str] = Field(default_factory=list)


class ConsoleVerificationPlaybook(BaseModel):
    strategy: str
    breakpoints: list[BreakpointHint] = Field(default_factory=list)
    console_steps: list[str] = Field(default_factory=list)
    console_code: str | None = None
    expected_observation: str
    limitations: list[str] = Field(default_factory=list)


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
    verification_playbook: ConsoleVerificationPlaybook | None = None


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
    verification_playbook: ConsoleVerificationPlaybook | None = None
    poc_generation_status: str | None = None
    poc_generation_reason: str | None = None
    observational_poc: ConsoleSafePoc | None = None
    manual_poc_plan: list[str] = Field(default_factory=list)


class ConsoleVerificationPlaybookSummary(BaseModel):
    id: str
    title: str
    source_path: str
    function_name: str | None = None
    endpoint: str | None = None
    method: str | None = None
    page_hint: str | None = None
    user_action_hint: str | None = None
    risk_type: str
    confidence: str
    console_code: str | None = None
    setup_steps: list[str] = Field(default_factory=list)
    proof_steps: list[str] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    failure_criteria: list[str] = Field(default_factory=list)
    evidence_to_capture: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ProjectRoute(BaseModel):
    path: str | None = None
    component: str | None = None
    source_path: str
    line: int | None = None


class ProjectPage(BaseModel):
    source_path: str
    component_name: str | None = None
    route_paths: list[str] = Field(default_factory=list)
    page_hint: str | None = None
    title_texts: list[str] = Field(default_factory=list)


class UiEventCandidate(BaseModel):
    source_path: str
    handler_name: str | None = None
    ui_event: str
    element_text: str | None = None
    disabled_expression: str | None = None
    nearby_title: str | None = None
    start_line: int
    end_line: int


class ApiInventoryItem(BaseModel):
    source_path: str
    function_name: str | None = None
    method: str
    endpoint: str
    sink: str
    parameters: list[str] = Field(default_factory=list)
    start_line: int
    end_line: int
    ui_event_handler: str | None = None
    ui_event_text: str | None = None
    ui_event_type: str | None = None
    interaction_confidence: str | None = None
    risk_category: str | None = None


class BusinessFlow(BaseModel):
    flow_type: str
    source_paths: list[str] = Field(default_factory=list)
    handlers: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    confidence: str = 'medium'
    reasons: list[str] = Field(default_factory=list)


class ProjectUnderstandingResult(BaseModel):
    framework: str | None = None
    routes: list[ProjectRoute] = Field(default_factory=list)
    pages: list[ProjectPage] = Field(default_factory=list)
    ui_events: list[UiEventCandidate] = Field(default_factory=list)
    api_inventory: list[ApiInventoryItem] = Field(default_factory=list)
    business_flows: list[BusinessFlow] = Field(default_factory=list)
    auth_sources: list[str] = Field(default_factory=list)
    storage_keys: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)


class ReadableAnalysisResult(BaseModel):
    finding_count: int
    findings: list[ReadableFinding]
    analyzed_focus: list[str] = Field(default_factory=list)
    executive_findings: list[ReadableFinding] = Field(default_factory=list)
    verification_playbooks: list[ConsoleVerificationPlaybookSummary] = Field(default_factory=list)
    review_candidates: list[ReadableFinding] = Field(default_factory=list)
    project_understanding: ProjectUnderstandingResult | None = None


class AnalysisDebugDropReason(BaseModel):
    index: int | None = None
    stage: str
    reason: str
    item_summary: dict[str, Any] | None = None


class AiAnalysisDebug(BaseModel):
    scope: str = 'readable_analysis'
    backend: str
    model: str | None = None
    configured: bool = False
    called: bool = False
    call_count: int = 0
    candidate_count: int = 0
    raw_item_count: int = 0
    accepted_item_count: int = 0
    dropped_item_count: int = 0
    drop_reasons: list[AnalysisDebugDropReason] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


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
    analysis_debug: AiAnalysisDebug | None = None
    analysis_notes: list[str] = Field(default_factory=list)


class AnalysisRunSummary(BaseModel):
    id: int
    original_filename: str
    created_at: str
    backend: str
    included_file_count: int
    skipped_file_count: int
    finding_count: int
    verification_playbook_count: int
    review_candidate_count: int


class AnalysisRunDetail(AnalysisRunSummary):
    result: dict[str, Any]


class ApiCallCandidate(BaseModel):
    source_path: str
    method: str
    endpoint: str
    parameters: list[str] = Field(default_factory=list)
    start_line: int
    end_line: int
    snippet: str
    sink: str
    confidence: str
    notes: list[str] = Field(default_factory=list)


class CandidateExtractionResult(BaseModel):
    total_candidates: int
    candidates: list[ApiCallCandidate] = Field(default_factory=list)
