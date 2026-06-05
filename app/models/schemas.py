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




class FindingDataFlow(BaseModel):
    user_action: str | None = None
    handler: str | None = None
    api_call_or_sink: str
    missing_guard_or_validation: str


class BreakpointPlan(BaseModel):
    file: str
    line: int
    function: str | None = None
    when_to_pause: str
    what_variable_or_request_to_check: str


class PocInjectionPlan(BaseModel):
    where_to_paste_code: str = 'Browser DevTools Console'
    when_to_run: str
    required_user_action: str



class ReadableFinding(BaseModel):
    id: str
    title: str
    vulnerability_type: str
    severity: str
    confidence: str
    affected_files: list[str]
    summary: str
    evidence: list[ReadableEvidence]
    # Finding lifecycle: raw_signal | review_candidate | runtime_verification_candidate | confirmed_finding
    status: str = 'review_candidate'
    # Generic security rule category (XSS, IDOR/BOLA, Business Logic Manipulation, ...)
    category: str | None = None
    console_poc: ConsoleSafePoc | None = None
    vulnerability_title: str | None = None
    source_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    function_name: str | None = None
    vulnerable_code_summary: str | None = None
    why_exploitable: str | None = None
    data_flow: FindingDataFlow | None = None
    breakpoint_plan: BreakpointPlan | None = None
    poc_injection_plan: PocInjectionPlan | None = None
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
    vulnerability_title: str | None = None
    source_path: str
    start_line: int | None = None
    end_line: int | None = None
    function_name: str | None = None
    endpoint: str | None = None
    method: str | None = None
    page_hint: str | None = None
    user_action_hint: str | None = None
    risk_type: str
    confidence: str
    vulnerable_code_summary: str | None = None
    root_cause: str | None = None
    why_exploitable: str | None = None
    data_flow: FindingDataFlow | None = None
    breakpoint_plan: BreakpointPlan | None = None
    poc_injection_plan: PocInjectionPlan | None = None
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


class SourceFileManifest(BaseModel):
    source_path: str
    framework_hint: str = 'unknown'
    pages: list[dict[str, Any]] = Field(default_factory=list)
    forms: list[dict[str, Any]] = Field(default_factory=list)
    buttons: list[dict[str, Any]] = Field(default_factory=list)
    ui_triggers: list[dict[str, Any]] = Field(default_factory=list)
    event_handlers: list[dict[str, Any]] = Field(default_factory=list)
    api_calls: list[dict[str, Any]] = Field(default_factory=list)
    storage_usage: list[dict[str, Any]] = Field(default_factory=list)
    dangerous_sinks: list[dict[str, Any]] = Field(default_factory=list)
    validation_guard_hints: list[dict[str, Any]] = Field(default_factory=list)
    linked_script_references: list[dict[str, Any]] = Field(default_factory=list)
    inline_script_blocks: list[dict[str, Any]] = Field(default_factory=list)


class BusinessFlow(BaseModel):
    flow_type: str
    source_paths: list[str] = Field(default_factory=list)
    handlers: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    confidence: str = 'medium'
    reasons: list[str] = Field(default_factory=list)


class ProjectUnderstandingResult(BaseModel):
    framework: str | None = None
    # source_react | source_vue_or_spa | jquery_html | static_html | bundled_spa | mixed_frontend | unknown
    project_type: str = 'unknown'
    normalized_manifest: list[SourceFileManifest] = Field(default_factory=list)
    routes: list[ProjectRoute] = Field(default_factory=list)
    pages: list[ProjectPage] = Field(default_factory=list)
    ui_events: list[UiEventCandidate] = Field(default_factory=list)
    api_inventory: list[ApiInventoryItem] = Field(default_factory=list)
    business_flows: list[BusinessFlow] = Field(default_factory=list)
    auth_sources: list[str] = Field(default_factory=list)
    storage_keys: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)


class ProjectProfile(BaseModel):
    """Emitted before findings. Describes the scanned project's shape and analysis statistics."""
    # source_react | source_vue_or_spa | jquery_html | static_html | bundled_spa | mixed_frontend | unknown
    project_type: str = 'unknown'
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    api_clients: list[str] = Field(default_factory=list)
    scanned_files: int = 0
    analyzed_files: int = 0
    excluded_vendor_files: int = 0
    raw_signals: int = 0
    review_candidates: int = 0
    runtime_verification_candidates: int = 0
    confirmed_findings: int = 0
    duplicate_findings_removed: int = 0
    noise_ratio: float = 0.0
    top_blockers: list[str] = Field(default_factory=list)


class ReadableAnalysisResult(BaseModel):
    finding_count: int
    findings: list[ReadableFinding]
    analyzed_focus: list[str] = Field(default_factory=list)
    common_console_helper: str | None = None
    executive_findings: list[ReadableFinding] = Field(default_factory=list)
    # Runtime Verification Candidates: frontend evidence with enough context to verify at runtime.
    # Not confirmed vulnerabilities — requires real test session to confirm.
    verification_playbooks: list[ConsoleVerificationPlaybookSummary] = Field(default_factory=list)
    review_candidates: list[ReadableFinding] = Field(default_factory=list)
    project_understanding: ProjectUnderstandingResult | None = None
    project_profile: ProjectProfile | None = None


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
    runtime_traffic: 'RuntimeTrafficImportResult | None' = None


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


class CapturedHttpResponse(BaseModel):
    status_code: int | None = None
    content_type: str | None = None
    body_preview: str | None = None
    redacted_headers: dict[str, str] = Field(default_factory=dict)


class CapturedHttpRequest(BaseModel):
    source_format: str
    method: str
    full_url: str
    scheme: str | None = None
    host: str | None = None
    path: str
    query_params: dict[str, list[str]] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    redacted_headers: dict[str, str] = Field(default_factory=dict)
    cookies_present: bool = False
    authorization_present: bool = False
    csrf_token_present: bool = False
    content_type: str | None = None
    body_text: str | None = None
    body_json: Any | None = None
    body_form: dict[str, list[str]] = Field(default_factory=dict)
    body_keys: list[str] = Field(default_factory=list)
    request_index: int
    timestamp: str | None = None
    response: CapturedHttpResponse | None = None


class RuntimeGeneratedPoc(BaseModel):
    poc_type: str
    title: str
    code: str | None = None
    safety: str
    mutation_guidance: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class RuntimeRequestCorrelation(BaseModel):
    finding_id: str
    finding_title: str
    lifecycle_status: str
    request_index: int
    method: str
    source_endpoint: str | None = None
    captured_path: str
    score: int
    reasons: list[str] = Field(default_factory=list)
    placeholder_mapping: dict[str, str] = Field(default_factory=dict)
    mutable_parameters: list[str] = Field(default_factory=list)
    generated_pocs: list[RuntimeGeneratedPoc] = Field(default_factory=list)


class RuntimeTrafficImportResult(BaseModel):
    provided: bool = False
    source_format: str | None = None
    request_count: int = 0
    requests: list[CapturedHttpRequest] = Field(default_factory=list)
    correlations: list[RuntimeRequestCorrelation] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
