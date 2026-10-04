#!/usr/bin/env python3
"""Validate .whytrace files against schemas/whytrace-v1.schema.json.

usage: scripts/validate-whytrace.py FILE_OR_DIR...
Requires the `jsonschema` package (pip install jsonschema).
"""
import json
import pathlib
import sys

import jsonschema

root = pathlib.Path(__file__).resolve().parent.parent
schema = json.loads((root / "schemas" / "whytrace-v1.schema.json").read_text())
jsonschema.Draft202012Validator.check_schema(schema)
validator = jsonschema.Draft202012Validator(schema)

files = []
for arg in sys.argv[1:]:
    p = pathlib.Path(arg)
    files.extend(sorted(p.glob("*.whytrace")) if p.is_dir() else [p])
if not files:
    sys.exit("no .whytrace files given")

failed = 0
for f in files:
    errors = list(validator.iter_errors(json.loads(f.read_text())))
    for e in errors[:5]:
        print(f"{f}: {e.message} at /{'/'.join(map(str, e.path))}")
    failed += bool(errors)
print(f"{len(files) - failed}/{len(files)} traces valid")
sys.exit(1 if failed else 0)
