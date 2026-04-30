from pathlib import Path

from app.core.config import settings

INCLUDE_EXTENSIONS = {'.js', '.html', '.json', '.mjs', '.cjs'}
INCLUDE_FILENAMES = {'package.json', 'dockerfile', 'docker-compose.yml', 'docker-compose.yaml'}
CONFIG_KEYWORDS = {'config', '.env.example', '.env.sample'}
EXCLUDED_DIR_NAMES = {'node_modules', 'vendor', 'dist', 'build', '.git', '__pycache__'}
EXCLUDED_FILE_PATTERNS = {'jquery', 'bootstrap', '.min.js', 'bundle.js'}


def _is_binary(file_path: Path) -> bool:
    try:
        with file_path.open('rb') as f:
            chunk = f.read(1024)
        return b'\x00' in chunk
    except OSError:
        return True


def should_include_file(file_path: Path) -> tuple[bool, str]:
    normalized = str(file_path).lower()
    file_name = file_path.name.lower()

    if any(dir_name in normalized.split('/') for dir_name in EXCLUDED_DIR_NAMES):
        return False, 'excluded directory'

    if any(pattern in file_name for pattern in EXCLUDED_FILE_PATTERNS):
        return False, 'excluded library/build artifact pattern'

    if not file_path.is_file():
        return False, 'not a regular file'

    size = file_path.stat().st_size
    if size > settings.MAX_FILE_SIZE_BYTES:
        return False, 'file too large'

    if _is_binary(file_path):
        return False, 'binary file excluded'

    extension = file_path.suffix.lower()
    if extension in INCLUDE_EXTENSIONS:
        return True, 'included extension'

    if file_name in INCLUDE_FILENAMES:
        return True, 'included filename'

    if any(keyword in file_name for keyword in CONFIG_KEYWORDS):
        return True, 'included config file'

    return False, 'extension not allowed'
