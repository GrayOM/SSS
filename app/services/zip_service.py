import os
import stat
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from zipfile import ZipFile

from app.core.config import settings


class ZipSecurityError(Exception):
    pass


def _ensure_within_base(member_path: Path, base_path: Path, member_name: str) -> None:
    if hasattr(member_path, 'is_relative_to'):
        if not member_path.is_relative_to(base_path):
            raise ZipSecurityError(f'ZIP Slip detected: {member_name}')
        return
    base_prefix = str(base_path) + os.sep
    if str(member_path) != str(base_path) and not str(member_path).startswith(base_prefix):
        raise ZipSecurityError(f'ZIP Slip detected: {member_name}')


def _is_unix_symlink(member) -> bool:
    mode = (member.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode) or (member.create_system == 3 and stat.S_ISLNK(mode))


def _is_special_file_mode(mode: int) -> bool:
    return stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)


def _safe_extract(zip_file: ZipFile, extract_to: Path) -> None:
    base_path = extract_to.resolve()
    members = zip_file.infolist()

    if len(members) > settings.MAX_ZIP_MEMBERS:
        raise ZipSecurityError(f'Too many zip members: {len(members)}')

    max_uncompressed = settings.MAX_UNCOMPRESSED_SIZE_MB * 1024 * 1024
    if sum(m.file_size for m in members) > max_uncompressed:
        raise ZipSecurityError('Uncompressed size limit exceeded')

    written_total = 0
    for member in members:
        name = member.filename
        if PurePosixPath(name).is_absolute() or PureWindowsPath(name).is_absolute():
            raise ZipSecurityError(f'Absolute path not allowed: {name}')

        target_path = (extract_to / name).resolve()
        _ensure_within_base(target_path, base_path, name)

        mode = (member.external_attr >> 16) & 0xFFFF
        if _is_unix_symlink(member):
            raise ZipSecurityError(f'Symlink not allowed: {name}')
        if _is_special_file_mode(mode):
            raise ZipSecurityError(f'Special file not allowed: {name}')

        if member.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
            continue

        target_path.parent.mkdir(parents=True, exist_ok=True)
        with zip_file.open(member) as src, target_path.open('wb') as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                written_total += len(chunk)
                if written_total > max_uncompressed:
                    raise ZipSecurityError('Uncompressed size limit exceeded during extraction')
                dst.write(chunk)

        resolved_written = target_path.resolve()
        _ensure_within_base(resolved_written, base_path, name)


def prepare_workspace() -> str:
    return tempfile.mkdtemp(prefix='upload_', dir=settings.TMP_DIR)


def extract_zip(upload_path: Path, workspace: Path) -> Path:
    extracted_dir = workspace / 'extracted'
    extracted_dir.mkdir(parents=True, exist_ok=True)
    with ZipFile(upload_path, 'r') as zf:
        _safe_extract(zf, extracted_dir)
    return extracted_dir
