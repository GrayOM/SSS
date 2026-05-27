#!/usr/bin/env python
import argparse
import json
from app.services.analysis_quality_evaluator import evaluate_analysis_quality

p = argparse.ArgumentParser()
p.add_argument('--result', required=True)
p.add_argument('--expectation', required=True)
a = p.parse_args()
res = json.load(open(a.result))
exp = json.load(open(a.expectation))
r = evaluate_analysis_quality(res, exp)
print(f"[{'PASS' if r.passed else 'FAIL'}] {exp.get('sample_id', 'sample')}")
print('score:', r.score)
print('failures:')
if r.failures:
    for x in r.failures:
        print('-', x)
else:
    print('- none')
print('warnings:')
if r.warnings:
    for x in r.warnings:
        print('-', x)
else:
    print('- none')
print('metrics:')
print(json.dumps(r.metrics, ensure_ascii=False, indent=2))
