from pathlib import Path

from app.core.config import settings
from app.models.schemas import InclusionDecision

# priority 기준:
# 1 (HIGH)   - 직접 작성 소스: .js .ts .jsx .tsx .vue .mjs .cjs
# 2 (MEDIUM) - 설정/데이터:    package.json, Dockerfile, config 파일, .json
# 3 (LOW)    - 마크업/템플릿:  .html .ejs .hbs .pug
PRIORITY_SOURCE = 1
PRIORITY_CONFIG = 2
PRIORITY_TEMPLATE = 3

SOURCE_EXTENSIONS   = {'.js', '.ts', '.jsx', '.tsx', '.vue', '.mjs', '.cjs'}
TEMPLATE_EXTENSIONS = {'.html', '.ejs', '.hbs', '.pug'}
CONFIG_EXTENSIONS   = {'.json'}
INCLUDE_FILENAMES   = {'package.json', 'dockerfile', 'docker-compose.yml', 'docker-compose.yaml'}
ALLOWED_ENV_FILES   = {'.env.example', '.env.sample'}
CONFIG_KEYWORDS     = {'config'}
EXCLUDED_DIRS       = {
    'node_modules', 'vendor', 'dist', 'build', 'coverage',
    '.git', '__pycache__', 'libs', 'cdn'
}
EXCLUDED_PATTERNS   = ('.min.js', '.bundle.js', '.chunk.js', 'bundle.js', 'webpack')


def _decision(include: bool, reason: str, reason_code: str, priority: int) -> InclusionDecision:
    return InclusionDecision(
        include=include, reason=reason, reason_code=reason_code, priority=priority
    )


def _is_binary(file_path: Path) -> bool:
    try:
        with file_path.open('rb') as f:
            return b'\x00' in f.read(4096)
    except OSError:
        return True


def should_include_file(file_path: Path) -> InclusionDecision:
    parts = {p.lower() for p in file_path.parts}
    name  = file_path.name.lower()

    if parts & EXCLUDED_DIRS:
        return _decision(False, 'excluded directory', 'EXCLUDED_DIR', 100)
    if not file_path.is_file():
        return _decision(False, 'not a regular file', 'EXCLUDED_EXTENSION', 100)
    if file_path.stat().st_size > settings.MAX_FILE_SIZE_BYTES:
        return _decision(False, 'file too large', 'EXCLUDED_TOO_LARGE', 100)
    if _is_binary(file_path):
        return _decision(False, 'binary file', 'EXCLUDED_BINARY', 100)
    if any(p in name for p in EXCLUDED_PATTERNS):
        return _decision(False, 'minified/build artifact', 'EXCLUDED_MINIFIED', 100)

    if name in ALLOWED_ENV_FILES:
        return _decision(True, 'allowed env sample', 'INCLUDED_CONFIG', PRIORITY_CONFIG)
    if name.endswith('.env'):
        return _decision(False, 'real env excluded', 'EXCLUDED_EXTENSION', 100)

    ext = file_path.suffix.lower()
    if ext in SOURCE_EXTENSIONS:
        return _decision(True, 'source file', 'INCLUDED_SOURCE', PRIORITY_SOURCE)
    if ext in TEMPLATE_EXTENSIONS:
        return _decision(True, 'template file', 'INCLUDED_TEMPLATE', PRIORITY_TEMPLATE)
    if ext in CONFIG_EXTENSIONS:
        return _decision(True, 'data/config file', 'INCLUDED_CONFIG', PRIORITY_CONFIG)
    if name in INCLUDE_FILENAMES:
        return _decision(True, 'key filename', 'INCLUDED_CONFIG', PRIORITY_CONFIG)
    if any(k in name for k in CONFIG_KEYWORDS):
        return _decision(True, 'config keyword', 'INCLUDED_CONFIG', PRIORITY_CONFIG)

    return _decision(False, 'extension not allowed', 'EXCLUDED_EXTENSION', 100)
