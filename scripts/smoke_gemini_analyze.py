<<<<<<< codex/design-project-folder-structure-rcjbnn
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

=======
>>>>>>> main
from app.core.config import settings
from app.models.schemas import CodeChunk
from app.services.ai_clients import GeminiClient
from app.services.analysis_service import GeminiAnalyzer


def main() -> int:
    if not settings.GEMINI_API_KEY:
        print('GEMINI_API_KEY is not set. Skipping Gemini smoke test.')
        return 0

    chunk = CodeChunk(
        source_path='smoke/sample.js',
        extension='.js',
        priority=1,
        source_content_hash='smoke-source-hash',
        chunk_index=0,
        total_chunks=1,
        start_line=1,
        end_line=2,
        chunk_hash='smoke-chunk-hash',
        content='const input = location.hash;\ndocument.getElementById("app").innerHTML = input;',
    )

    try:
        client = GeminiClient(settings.GEMINI_API_KEY, settings.GEMINI_MODEL)
        analyzer = GeminiAnalyzer(client)
        findings = analyzer.analyze_chunk(chunk)

        vuln_types = [f.vulnerability_type for f in findings]
        sev_conf = [f'{f.severity}/{f.confidence}' for f in findings]

        print(f'Model: {settings.GEMINI_MODEL}')
        print(f'Finding count: {len(findings)}')
        print(f'Vulnerability types: {vuln_types}')
        print(f'Severity/Confidence: {sev_conf}')
        return 0
    except Exception as exc:
        print('Gemini smoke test failed')
        print(f'Error type: {type(exc).__name__}')
<<<<<<< codex/design-project-folder-structure-rcjbnn
        print('Check GEMINI_API_KEY, GEMINI_MODEL, quota, and network connectivity.')
=======
        print(f'Error message: {str(exc)}')
>>>>>>> main
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
