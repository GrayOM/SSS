import hashlib
import unittest

from app.core.config import settings
from app.models.schemas import FileContent
from app.services.chunk_service import build_chunks


class ChunkServiceTests(unittest.TestCase):
    def test_short_file_single_chunk(self):
        file_content = FileContent(
            path='a.js', extension='.js', size=10, priority=1,
            reason_code='INCLUDED_SOURCE', content_hash='h', content='line1\nline2'
        )
        result = build_chunks([file_content])
        self.assertEqual(result.total_chunks, 1)
        self.assertEqual(result.chunks[0].start_line, 1)
        self.assertEqual(result.chunks[0].end_line, 2)

    def test_long_file_multiple_chunks(self):
        original_max = settings.MAX_CHUNK_LINES
        original_overlap = settings.CHUNK_OVERLAP_LINES
        settings.MAX_CHUNK_LINES = 200
        settings.CHUNK_OVERLAP_LINES = 20
        try:
            content = '\n'.join([f'line{i}' for i in range(1, 451)])
            file_content = FileContent(
                path='big.js', extension='.js', size=len(content), priority=1,
                reason_code='INCLUDED_SOURCE', content_hash='h', content=content
            )
            result = build_chunks([file_content])
            self.assertEqual(result.total_chunks, 3)
            self.assertEqual((result.chunks[0].start_line, result.chunks[0].end_line), (1, 200))
            self.assertEqual((result.chunks[1].start_line, result.chunks[1].end_line), (181, 380))
            self.assertEqual((result.chunks[2].start_line, result.chunks[2].end_line), (361, 450))
        finally:
            settings.MAX_CHUNK_LINES = original_max
            settings.CHUNK_OVERLAP_LINES = original_overlap

    def test_overlap_applied(self):
        original_max = settings.MAX_CHUNK_LINES
        original_overlap = settings.CHUNK_OVERLAP_LINES
        settings.MAX_CHUNK_LINES = 5
        settings.CHUNK_OVERLAP_LINES = 2
        try:
            content = '\n'.join([str(i) for i in range(1, 10)])
            result = build_chunks([FileContent(
                path='x.js', extension='.js', size=len(content), priority=1,
                reason_code='INCLUDED_SOURCE', content_hash='h', content=content
            )])
            self.assertEqual(result.total_chunks, 3)
            self.assertEqual((result.chunks[0].start_line, result.chunks[0].end_line), (1, 5))
            self.assertEqual((result.chunks[1].start_line, result.chunks[1].end_line), (4, 8))
            self.assertEqual((result.chunks[2].start_line, result.chunks[2].end_line), (7, 9))
        finally:
            settings.MAX_CHUNK_LINES = original_max
            settings.CHUNK_OVERLAP_LINES = original_overlap

    def test_chunk_hash_matches_sha256(self):
        content = 'a\nb\nc'
        result = build_chunks([FileContent(
            path='h.js', extension='.js', size=5, priority=1,
            reason_code='INCLUDED_SOURCE', content_hash='src-h', content=content
        )])
        expected = hashlib.sha256(content.encode('utf-8')).hexdigest()
        self.assertEqual(result.chunks[0].chunk_hash, expected)

    def test_empty_content_skipped(self):
        result = build_chunks([FileContent(
            path='e.js', extension='.js', size=0, priority=1,
            reason_code='INCLUDED_SOURCE', content_hash='h', content=''
        )])
        self.assertEqual(result.files_skipped, 1)
        self.assertEqual(result.total_chunks, 0)

    def test_counts_correct(self):
        f1 = FileContent(path='a.js', extension='.js', size=1, priority=1, reason_code='INCLUDED_SOURCE', content_hash='h1', content='x')
        f2 = FileContent(path='b.js', extension='.js', size=0, priority=1, reason_code='INCLUDED_SOURCE', content_hash='h2', content='')
        result = build_chunks([f1, f2])
        self.assertEqual(result.total_files, 2)
        self.assertEqual(result.files_chunked, 1)
        self.assertEqual(result.files_skipped, 1)

    def test_invalid_overlap_raises(self):
        original_max = settings.MAX_CHUNK_LINES
        original_overlap = settings.CHUNK_OVERLAP_LINES
        settings.MAX_CHUNK_LINES = 10
        settings.CHUNK_OVERLAP_LINES = 10
        try:
            with self.assertRaises(ValueError):
                build_chunks([])
        finally:
            settings.MAX_CHUNK_LINES = original_max
            settings.CHUNK_OVERLAP_LINES = original_overlap

    def test_max_chunk_lines_zero_raises(self):
        original_max = settings.MAX_CHUNK_LINES
        original_overlap = settings.CHUNK_OVERLAP_LINES
        settings.MAX_CHUNK_LINES = 0
        settings.CHUNK_OVERLAP_LINES = 0
        try:
            with self.assertRaises(ValueError):
                build_chunks([])
        finally:
            settings.MAX_CHUNK_LINES = original_max
            settings.CHUNK_OVERLAP_LINES = original_overlap

    def test_negative_overlap_raises(self):
        original_max = settings.MAX_CHUNK_LINES
        original_overlap = settings.CHUNK_OVERLAP_LINES
        settings.MAX_CHUNK_LINES = 10
        settings.CHUNK_OVERLAP_LINES = -1
        try:
            with self.assertRaises(ValueError):
                build_chunks([])
        finally:
            settings.MAX_CHUNK_LINES = original_max
            settings.CHUNK_OVERLAP_LINES = original_overlap


if __name__ == '__main__':
    unittest.main()
