from app.models.schemas import CodeChunk


def build_analysis_prompt(chunk: CodeChunk) -> str:
    return f"""
You are a security analysis assistant.
Analyze the following code chunk and return JSON only.

Rules:
- Evidence 기반 분석을 수행하라.
- 코드 근거가 없으면 finding을 생성하지 마라.
- safe PoC만 허용한다.
- destructive exploit, 데이터 삭제/변조, 권한 상승, 외부 연결은 금지한다.
- findings가 없으면 반드시 {{"findings": []}} 를 반환하라.
- markdown code fence를 사용하지 마라.
- JSON 외 설명 문장을 출력하지 마라.
- severity는 low, medium, high, critical 중 하나만 사용하라.
- confidence는 low, medium, high 중 하나만 사용하라.
- snippet은 제공된 코드에서 직접 인용한 짧은 부분만 사용하라.
- 코드 근거 없는 추정은 금지한다.
- 응답은 반드시 JSON 객체만 반환하라.

Chunk metadata:
- source_path: {chunk.source_path}
- extension: {chunk.extension}
- start_line: {chunk.start_line}
- end_line: {chunk.end_line}

Chunk content:
{chunk.content}

Return schema example:
{{
  "findings": [
    {{
      "vulnerability_type": "DOM XSS",
      "severity": "high",
      "confidence": "medium",
      "source_path": "src/app.js",
      "start_line": 1,
      "end_line": 20,
      "evidence": [
        {{
          "source_path": "src/app.js",
          "start_line": 1,
          "end_line": 20,
          "snippet": "...",
          "reason": "외부 입력이 검증 없이 innerHTML에 전달됨"
        }}
      ],
      "attack_scenario": [
        "공격자가 입력값을 조작한다",
        "조작된 값이 DOM sink에 전달된다",
        "브라우저에서 스크립트가 실행될 수 있다"
      ],
      "safe_poc": "<img src=x onerror=alert(1)>",
      "impact": "사용자 브라우저에서 임의 스크립트 실행 가능",
      "root_cause": "외부 입력이 검증/인코딩 없이 위험 sink에 전달됨",
      "remediation": "textContent 사용 또는 DOMPurify 등 sanitizer 적용",
      "related_cwe": ["CWE-79"]
    }}
  ]
}}
""".strip()


from app.models.schemas import FileContent


def build_console_poc_analysis_prompt(files: list[FileContent]) -> str:
    sections = []
    for f in files[:20]:
        excerpt = f.content[:1200]
        sections.append(f"[FILE] {f.path}\n{excerpt}")

    return (
        "You are a security analysis assistant. Return JSON only.\n"
        "Find console-verifiable vulnerability flows in JS/HTML.\n"
        "Focus on source -> state/storage/API/DOM sink data flow.\n"
        "Do not create findings without code evidence.\n"
        "If none, return {\"findings\": []}.\n"
        "Do not use markdown code fences. No explanation outside JSON.\n"
        "Console PoC must be non-destructive verification only.\n"
        "Ban data deletion, payment actions, privilege change, external exfiltration, command execution.\n"
        "JSON schema example: {\"findings\":[{\"id\":\"x\",\"title\":\"...\",\"vulnerability_type\":\"...\",\"severity\":\"low|medium|high|critical\",\"confidence\":\"low|medium|high\",\"affected_files\":[\"...\"],\"summary\":\"...\",\"evidence\":[{\"source_path\":\"...\",\"start_line\":1,\"end_line\":2,\"snippet\":\"...\",\"reason\":\"...\",\"data_flow\":[\"source->sink\"]}],\"console_poc\":{\"poc_type\":\"browser_console\",\"description\":\"...\",\"preconditions\":[\"...\"],\"steps\":[\"...\"],\"code\":\"...\",\"expected_result\":\"...\",\"safety\":\"...\"},\"attack_scenario\":[\"...\"],\"impact\":\"...\",\"root_cause\":\"...\",\"remediation\":\"...\",\"verification_notes\":[\"...\"],\"related_cwe\":[\"CWE-79\"]}]}.\n\n"
        + "\n\n".join(sections)
    )
