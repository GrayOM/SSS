import unittest
from pathlib import Path


class DockerignoreTests(unittest.TestCase):
    def test_dockerignore_exists_and_blocks_env(self):
        content = Path('.dockerignore').read_text()
        self.assertIn('.env', content)


if __name__ == '__main__':
    unittest.main()
