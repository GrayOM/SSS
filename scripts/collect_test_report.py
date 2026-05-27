from __future__ import annotations
import argparse
import json
import re
from pathlib import Path


def classify(lines: list[str]) -> dict[str, int]:
    text = "\n".join(lines)
    cats = {
        "UnicodeDecodeError": len(re.findall(r"UnicodeDecodeError", text)),
        "AssertionError": len(re.findall(r"AssertionError", text)),
        "ImportError": len(re.findall(r"ImportError|ModuleNotFoundError", text)),
        "Missing fixture": len(re.findall(r"fixture .* not found|FileNotFoundError", text)),
        "Anonymization failure": len(re.findall(r"fixture_anonymization|legacy sample", text, re.I)),
        "PoC coverage failure": len(re.findall(r"poc_generation_rate|promoted_without_console_code|candidates_without_any_poc", text, re.I)),
    }
    return cats


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    p = Path(args.log)
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    text = "\n".join(lines)

    m = re.search(r"=+\s*(\d+) failed,\s*(\d+) passed", text)
    if m:
        failed, passed = int(m.group(1)), int(m.group(2))
    else:
        m2 = re.search(r"=+\s*(\d+) passed", text)
        passed = int(m2.group(1)) if m2 else 0
        failed = 0 if passed else len(re.findall(r"\bFAILED\b", text))

    fail_files = sorted(set(re.findall(r"(tests/[^:\s]+\.py)::.*?FAILED", text)))
    cats = classify(lines)

    compact = {
        "failed_test_count": failed,
        "passed_test_count": passed,
        "failed_files": fail_files,
        "failure_categories": cats,
        "codex_compact_summary": f"failed={failed}, passed={passed}, top_failures={[k for k,v in cats.items() if v>0]}"
    }

    Path(args.out).write_text(json.dumps(compact, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(compact, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
