import shutil
import stat
import tempfile
from pathlib import Path
from zipfile import ZipFile

from app.core.config import settings


class ZipSecurityError(Exception):
    pass


def _safe_extract(zip_file: ZipFile, extract_to: Path) -> None:
    base_path = extract_to.resolve()
    total_uncompressed = 0

    members = zip_file.infolist()
    if len(members) > settings.MAX_ZIP_MEMBERS:
        raise ZipSecurityError(f'Too many zip members: {len(members)}')

    max_uncompressed = settings.MAX_UNCOMPRESSED_SIZE_MB * 1024 * 1024

    for member in members:
        mode = (member.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise ZipSecurityError(f'Symlink entry is not allowed: {member.filename}')

        member_path = (extract_to / member.filename).resolve()
        if not str(member_path).startswith(str(base_path)):
            raise ZipSecurityError(f'ZIP Slip detected: {member.filename}')

        total_uncompressed += member.file_size
        if total_uncompressed > max_uncompressed:
            raise ZipSecurityError('Uncompressed size limit exceeded')

        if member.is_dir():
            member_path.mkdir(parents=True, exist_ok=True)
            continue

        member_path.parent.mkdir(parents=True, exist_ok=True)
        with zip_file.open(member) as source, open(member_path, 'wb') as target:
            shutil.copyfileobj(source, target)


def prepare_workspace() -> str:
    return tempfile.mkdtemp(prefix='upload_', dir=settings.TMP_DIR)


def extract_zip(upload_path: Path, workspace: Path) -> Path:
    extracted_dir = workspace / 'extracted'
    extracted_dir.mkdir(parents=True, exist_ok=True)
    with ZipFile(upload_path, 'r') as zf:
        _safe_extract(zf, extracted_dir)
    return extracted_dir
