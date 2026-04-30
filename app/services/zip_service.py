import os
import shutil
import stat
import tempfile
from pathlib import Path
from zipfile import ZipFile

from app.core.config import settings


class ZipSecurityError(Exception):
    pass


def _ensure_within_base(member_path: Path, base_path: Path, member_name: str) -> None:
    # Path.is_relative_to is available from Python 3.9+.
    if hasattr(member_path, 'is_relative_to'):
        if not member_path.is_relative_to(base_path):
            raise ZipSecurityError(f'ZIP Slip detected: {member_name}')
        return

    base_prefix = str(base_path) + os.sep
    if str(member_path) != str(base_path) and not str(member_path).startswith(base_prefix):
        raise ZipSecurityError(f'ZIP Slip detected: {member_name}')


def _safe_extract(zip_file: ZipFile, extract_to: Path) -> None:
    base_path = extract_to.resolve()
    members = zip_file.infolist()

    if len(members) > settings.MAX_ZIP_MEMBERS:
        raise ZipSecurityError(f'Too many zip members: {len(members)}')

    max_uncompressed = settings.MAX_UNCOMPRESSED_SIZE_MB * 1024 * 1024
    total_uncompressed = 0

    for member in members:
        mode = (member.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise ZipSecurityError(f'Symlink entry is not allowed: {member.filename}')

        total_uncompressed += member.file_size
        if total_uncompressed > max_uncompressed:
            raise ZipSecurityError('Uncompressed size limit exceeded')

        member_path = (extract_to / member.filename).resolve()
        _ensure_within_base(member_path, base_path, member.filename)

        if member.is_dir():
            member_path.mkdir(parents=True, exist_ok=True)
            continue

        member_path.parent.mkdir(parents=True, exist_ok=True)
        with zip_file.open(member) as source, member_path.open('wb') as target:
            shutil.copyfileobj(source, target)


def prepare_workspace() -> str:
    return tempfile.mkdtemp(prefix='upload_', dir=settings.TMP_DIR)


def extract_zip(upload_path: Path, workspace: Path) -> Path:
    extracted_dir = workspace / 'extracted'
    extracted_dir.mkdir(parents=True, exist_ok=True)
    with ZipFile(upload_path, 'r') as zf:
        _safe_extract(zf, extracted_dir)
    return extracted_dir
