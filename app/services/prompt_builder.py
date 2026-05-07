from app.models.schemas import CodeChunk, FileContent


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
""".strip()


CONSOLE_KEYS = [
    'userType','role','isAdmin','ADMIN','localStorage','sessionStorage','cookie','innerHTML','outerHTML','insertAdjacentHTML',
    'document.write','eval','Function','location','document.URL','postMessage','input.value','price','amount','status',
    'productId','userId','payment','order','auction','axios','fetch','FormData'
]


def _keyword_snippets(content: str, max_snippets: int = 5, window: int = 300) -> list[str]:
    snippets: list[str] = []
    lowered = content.lower()
    for key in CONSOLE_KEYS:
        i = lowered.find(key.lower())
        if i == -1:
            continue
        start = max(0, i - window)
        end = min(len(content), i + window)
        snippet = content[start:end]
        if snippet not in snippets:
            snippets.append(snippet)
        if len(snippets) >= max_snippets:
            break
    if not snippets:
        snippets.append(content[:600])
    return snippets


def build_console_poc_analysis_prompt(files: list[FileContent]) -> str:
    sections = []
    for f in files[:20]:
        snippets = _keyword_snippets(f.content)
        for idx, s in enumerate(snippets, 1):
            sections.append(f"[FILE] {f.path} [SNIPPET {idx}]\n{s}")

    return (
        'You are a security analysis assistant. Return JSON only.\n'
        'Find console-verifiable vulnerability flows in JS/HTML.\n'
        'Focus on source -> state/storage/API/DOM sink data flow.\n'
        'Do not create findings without code evidence.\n'
        'If none, return {"findings": []}.\n'
        'Do not use markdown code fences. No explanation outside JSON.\n'
        'Console PoC must be non-destructive verification only.\n'
        'Ban data deletion, payment actions, privilege change, external exfiltration, command execution.\n'
        'Respond with JSON object containing findings array and readable finding fields.\n\n'
        + '\n\n'.join(sections)
    )
