#!/usr/bin/env python3
"""Literal audit: string literals >= 12 chars in a rule source that occur in a benchmark corpus.
Usage: python3 -I tests/bench/literal_audit.py RULE.rs CASES.jsonl [CASES.jsonl ...]"""
import json, re, sys
src = open(sys.argv[1], encoding="utf-8").read()
src = re.sub(r"#\[cfg\(test\)\].*", "", src, flags=re.S)  # tests may quote corpora-shaped text
lits = {m for m in re.findall(r'"((?:[^"\\]|\\.){12,})"', src)}
corp = ""
for f in sys.argv[2:]:
    for line in open(f, encoding="utf-8"):
        corp += json.loads(line)["content"].lower() + "\n"
bad = sorted(l for l in lits if l.lower() in corp)
print(f"{len(lits)} literals >= 12 chars; {len(bad)} violations")
for b in bad:
    print("  VIOLATION:", b)
sys.exit(1 if bad else 0)
