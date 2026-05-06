from pathlib import Path

from app.core.config import settings
from app.models.schemas import InclusionDecision

# Inclusion priority policy for future AI analysis queueing:
# 1 = directly-authored source code (.js/.ts/.jsx/.tsx/.vue/.mjs/.cjs)
# 2 = config/data files (package.json, Dockerfile, docker-compose*, config*, .json)
# 3 = markup/template files (.html/.ejs/.hbs/.pug)
PRIORITY_SOURCE = 1
PRIORITY_CONFIG = 2
PRIORITY_TEMPLATE = 3

INCLUDE_EXTENSIONS = {
    '.js', '.html', '.json', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', '.vue', '.ejs', '.hbs', '.pug'
}
SOURCE_EXTENSIONS = {'.js', '.ts', '.jsx', '.tsx', '.vue', '.mjs', '.cjs'}
TEMPLATE_EXTENSIONS = {'.html', '.ejs', '.hbs', '.pug'}
INCLUDE_EXTENSIONS = {
    '.js', '.html', '.json', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', '.vue', '.ejs', '.hbs', '.pug'
}
INCLUDE_FILENAMES = {'package.json', 'dockerfile', 'docker-compose.yml', 'docker-compose.yaml'}
ALLOWED_ENV_FILENAMES = {'.env.example', '.env.sample'}
CONFIG_KEYWORDS = {'config'}
EXCLUDED_DIR_NAMES = {'node_modules', 'vendor', 'dist', 'build', 'coverage', '.git', '__pycache__', 'libs', 'cdn'}
EXCLUDED_FILE_PATTERNS = ('.min.js', '.bundle.js', '.chunk.js', 'bundle.js', 'webpack')
INCLUDE_EXTENSIONS = {'.js', '.html', '.json', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', '.vue', '.ejs', '.hbs', '.pug'}
INCLUDE_FILENAMES = {'package.json', 'dockerfile', 'docker-compose.yml', 'docker-compose.yaml'}
CONFIG_KEYWORDS = {'config', '.env.example', '.env.sample'}
EXCLUDED_DIR_NAMES = {'node_modules', 'vendor', 'dist', 'build', 'coverage', '.git', '__pycache__'}
EXCLUDED_FILE_PATTERNS = {'.min.js', 'bundle.js', 'webpack'}


def _decision(include: bool, reason: str, reason_code: str, priority: int) -> InclusionDecision:
    return InclusionDecision(include=include, reason=reason, reason_code=reason_code, priority=priority)

INCLUDE_EXTENSIONS = {'.js', '.html', '.json', '.mjs', '.cjs'}
INCLUDE_FILENAMES = {'package.json', 'dockerfile', 'docker-compose.yml', 'docker-compose.yaml'}
CONFIG_KEYWORDS = {'config', '.env.example', '.env.sample'}
EXCLUDED_DIR_NAMES = {'node_modules', 'vendor', 'dist', 'build', '.git', '__pycache__'}
EXCLUDED_FILE_PATTERNS = {'jquery', 'bootstrap', '.min.js', 'bundle.js'}

def _is_binary(file_path: Path) -> bool:
    try:
        with file_path.open('rb') as f:
            return b'\x00' in f.read(4096)
            chunk = f.read(4096)

            chunk = f.read(1024)
        return b'\x00' in chunk
    except OSError:
        return True


def should_include_file(file_path: Path) -> InclusionDecision:
    normalized_parts = {part.lower() for part in file_path.parts}
    file_name = file_path.name.lower()

    if normalized_parts.intersection(EXCLUDED_DIR_NAMES):
        return _decision(False, 'excluded directory', 'EXCLUDED_DIR', 100)

    if not file_path.is_file():
        return _decision(False, 'not a regular file', 'EXCLUDED_EXTENSION', 100)

    if file_path.stat().st_size > settings.MAX_FILE_SIZE_BYTES:
        return _decision(False, 'file too large', 'EXCLUDED_TOO_LARGE', 100)

    if _is_binary(file_path):
        return _decision(False, 'binary file excluded', 'EXCLUDED_BINARY', 100)

    if any(pattern in file_name for pattern in EXCLUDED_FILE_PATTERNS):
        return _decision(False, 'excluded minified/build output', 'EXCLUDED_MINIFIED', 100)

    if file_name in ALLOWED_ENV_FILENAMES:
        return _decision(True, 'included allowed env sample file', 'INCLUDED_CONFIG', PRIORITY_CONFIG)

    if file_name.endswith('.env'):
        return _decision(False, 'real env files are excluded', 'EXCLUDED_EXTENSION', 100)

    extension = file_path.suffix.lower()
    if extension in SOURCE_EXTENSIONS:
        return _decision(True, 'included source extension', 'INCLUDED_SOURCE', PRIORITY_SOURCE)

    if extension in TEMPLATE_EXTENSIONS:
        return _decision(True, 'included template extension', 'INCLUDED_SOURCE', PRIORITY_TEMPLATE)

    if extension == '.json':
        return _decision(True, 'included data extension', 'INCLUDED_CONFIG', PRIORITY_CONFIG)

    if file_name in INCLUDE_FILENAMES:
        return _decision(True, 'included key filename', 'INCLUDED_CONFIG', PRIORITY_CONFIG)

    if any(keyword in file_name for keyword in CONFIG_KEYWORDS):
        return _decision(True, 'included config file', 'INCLUDED_CONFIG', PRIORITY_CONFIG)

    if extension in INCLUDE_EXTENSIONS:
        return _decision(True, 'included extension', 'INCLUDED_SOURCE', PRIORITY_SOURCE)

    return _decision(False, 'extension not allowed', 'EXCLUDED_EXTENSION', 100)
    normalized_parts = [part.lower() for part in file_path.parts]
    file_name = file_path.name.lower()

    if any(dir_name in normalized_parts for dir_name in EXCLUDED_DIR_NAMES):
        return _decision(False, 'excluded directory', 'EXCLUDED_DIR', 100)

    if not file_path.is_file():
        return _decision(False, 'not a regular file', 'EXCLUDED_EXTENSION', 5)

    size = file_path.stat().st_size
    if size > settings.MAX_FILE_SIZE_BYTES:
        return _decision(False, 'file too large', 'EXCLUDED_TOO_LARGE', 95)

    if _is_binary(file_path):
        return _decision(False, 'binary file excluded', 'EXCLUDED_BINARY', 90)

    if any(pattern in file_name for pattern in EXCLUDED_FILE_PATTERNS):
        return _decision(False, 'excluded minified/build output', 'EXCLUDED_MINIFIED', 80)

    if file_name in ALLOWED_ENV_FILENAMES:
        return _decision(True, 'included allowed env sample file', 'INCLUDED_CONFIG', 70)

    if file_name.endswith('.env'):
        return _decision(False, 'real env files are excluded', 'EXCLUDED_EXTENSION', 20)

    extension = file_path.suffix.lower()
    if extension in INCLUDE_EXTENSIONS:
        return _decision(True, 'included source extension', 'INCLUDED_SOURCE', 50)

    if file_name in INCLUDE_FILENAMES:
        return _decision(True, 'included key filename', 'INCLUDED_SOURCE', 60)

    if any(keyword in file_name for keyword in CONFIG_KEYWORDS):
        return _decision(True, 'included config file', 'INCLUDED_CONFIG', 55)

    return _decision(False, 'extension not allowed', 'EXCLUDED_EXTENSION', 10)
  
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
