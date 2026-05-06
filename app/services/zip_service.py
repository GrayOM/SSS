import os
import stat
import tempfile
from pathlib import Path
from zipfile import ZipFile

from app.core.config import settings


class ZipSecurityError(Exception):
    pass


def _ensure_within_base(member_path: Path, base_path: Path, member_name: str) -> None:
    # Path.is_relative_to is Python 3.9+
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
    meta_total_uncompressed = sum(m.file_size for m in members)
    if meta_total_uncompressed > max_uncompressed:
        raise ZipSecurityError('Uncompressed size limit exceeded')

    written_total = 0
    for member in members:
        if stat.S_ISLNK((member.external_attr >> 16) & 0xFFFF):
            raise ZipSecurityError(f'Symlink not allowed: {member.filename}')

        member_path = (extract_to / member.filename).resolve()
        _ensure_within_base(member_path, base_path, member.filename)

        if member.is_dir():
            member_path.mkdir(parents=True, exist_ok=True)
            continue

        member_path.parent.mkdir(parents=True, exist_ok=True)
        with zip_file.open(member) as src, member_path.open('wb') as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                written_total += len(chunk)
                if written_total > max_uncompressed:
                    raise ZipSecurityError('Uncompressed size limit exceeded during extraction')
                dst.write(chunk)


def prepare_workspace() -> str:
    return tempfile.mkdtemp(prefix='upload_', dir=settings.TMP_DIR)


def extract_zip(upload_path: Path, workspace: Path) -> Path:
    extracted_dir = workspace / 'extracted'
    extracted_dir.mkdir(parents=True, exist_ok=True)
    with ZipFile(upload_path, 'r') as zf:
        _safe_extract(zf, extracted_dir)
    return extracted_dir
