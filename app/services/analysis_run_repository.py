import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from app.core.config import settings
from app.models.schemas import AnalysisRunDetail, AnalysisRunSummary, FullAnalysisResponse


def _db_path() -> Path:
    return Path(settings.ANALYSIS_DB_PATH)


def _connect() -> sqlite3.Connection:
    db_path = _db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
    finally:
        conn.close()


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS analysis_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_filename TEXT NOT NULL,
            created_at TEXT NOT NULL,
            backend TEXT NOT NULL,
            included_file_count INTEGER NOT NULL,
            skipped_file_count INTEGER NOT NULL,
            finding_count INTEGER NOT NULL,
            verification_playbook_count INTEGER NOT NULL,
            review_candidate_count INTEGER NOT NULL,
            result_json TEXT NOT NULL
        )
        '''
    )
    conn.execute(
        'CREATE INDEX IF NOT EXISTS idx_analysis_runs_created_at ON analysis_runs(created_at DESC)'
    )
    conn.commit()


def _strip_raw_content(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_raw_content(item)
            for key, item in value.items()
            if key != 'content'
        }
    if isinstance(value, list):
        return [_strip_raw_content(item) for item in value]
    return value


def _row_to_summary(row: sqlite3.Row) -> AnalysisRunSummary:
    return AnalysisRunSummary(
        id=row['id'],
        original_filename=row['original_filename'],
        created_at=row['created_at'],
        backend=row['backend'],
        included_file_count=row['included_file_count'],
        skipped_file_count=row['skipped_file_count'],
        finding_count=row['finding_count'],
        verification_playbook_count=row['verification_playbook_count'],
        review_candidate_count=row['review_candidate_count'],
    )


def save_analysis_run(original_filename: str, result: FullAnalysisResponse) -> AnalysisRunDetail:
    safe_result = _strip_raw_content(result.model_dump(mode='json'))
    readable = result.readable_analysis
    analysis_debug = result.analysis_debug
    backend = analysis_debug.backend if analysis_debug else settings.ANALYZER_BACKEND
    finding_count = readable.finding_count if readable else result.analysis.finding_count
    verification_playbook_count = len(readable.verification_playbooks) if readable else 0
    review_candidate_count = len(readable.review_candidates) if readable else 0
    created_at = datetime.now(timezone.utc).isoformat()

    with _connection() as conn:
        _ensure_schema(conn)
        cursor = conn.execute(
            '''
            INSERT INTO analysis_runs (
                original_filename,
                created_at,
                backend,
                included_file_count,
                skipped_file_count,
                finding_count,
                verification_playbook_count,
                review_candidate_count,
                result_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                original_filename,
                created_at,
                backend,
                result.upload.included_count,
                result.upload.excluded_count,
                finding_count,
                verification_playbook_count,
                review_candidate_count,
                json.dumps(safe_result, ensure_ascii=False),
            ),
        )
        conn.commit()
        run_id = int(cursor.lastrowid)

    saved = get_analysis_run(run_id)
    if saved is None:
        raise RuntimeError('Saved analysis run could not be loaded')
    return saved


def list_analysis_runs() -> list[AnalysisRunSummary]:
    with _connection() as conn:
        _ensure_schema(conn)
        rows = conn.execute(
            '''
            SELECT id, original_filename, created_at, backend, included_file_count,
                   skipped_file_count, finding_count, verification_playbook_count,
                   review_candidate_count
            FROM analysis_runs
            ORDER BY created_at DESC, id DESC
            '''
        ).fetchall()
    return [_row_to_summary(row) for row in rows]


def get_analysis_run(run_id: int) -> AnalysisRunDetail | None:
    with _connection() as conn:
        _ensure_schema(conn)
        row = conn.execute(
            '''
            SELECT id, original_filename, created_at, backend, included_file_count,
                   skipped_file_count, finding_count, verification_playbook_count,
                   review_candidate_count, result_json
            FROM analysis_runs
            WHERE id = ?
            ''',
            (run_id,),
        ).fetchone()
    if row is None:
        return None
    summary = _row_to_summary(row)
    return AnalysisRunDetail(
        **summary.model_dump(),
        result=json.loads(row['result_json']),
    )
