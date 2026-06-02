import compileall
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_compileall_passes_for_app_and_tests():
    assert compileall.compile_dir(str(ROOT / 'app'), quiet=1)
    assert compileall.compile_dir(str(ROOT / 'tests'), quiet=1)
