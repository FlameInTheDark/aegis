#!/usr/bin/env python3
"""Cross-reference nullable Postgres columns with Go repo SELECT lists.

Finds potential pgx 'cannot scan NULL into *string/*time.Time' bombs:
nullable TEXT/UUID/INET/CIDR columns that appear in a repo SELECT list
(either bare, ::text, or inside COALESCE) — COALESCE ones are already fixed.
"""
import re, os, glob, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIG = os.path.join(ROOT, "migrations/postgres")
REPO = os.path.join(ROOT, "internal/repository/postgres")

# 1. parse migrations: table -> [(column, type)] where column is nullable
tables = {}
create_re = re.compile(r"CREATE TABLE (\w+) \((.*?)\n\);", re.S)
col_re = re.compile(r"^\s{4}(\w+)\s+([A-Z]+)\b(.*)$", re.M)
for path in sorted(glob.glob(os.path.join(MIG, "*.up.sql"))):
    sql = open(path).read()
    for m in create_re.finditer(sql):
        tname, body = m.group(1), m.group(2)
        cols = {}
        for cm in col_re.finditer(body):
            col, typ, rest = cm.group(1), cm.group(2), cm.group(3)
            if "NOT NULL" in rest or "PRIMARY KEY" in rest:
                continue
            if typ in ("TEXT", "UUID", "INET", "CIDR", "TIMESTAMPTZ", "JSONB"):
                cols[col] = typ
        if cols:
            tables.setdefault(tname, {}).update(cols)

print("== nullable text-like columns per table ==")
for t, cols in sorted(tables.items()):
    print(f"  {t}: {cols}")

# 2. scan repo .go files for Select lists mentioning those columns
go_src = {}
for path in glob.glob(os.path.join(REPO, "*.go")):
    if path.endswith("_test.go"):
        continue
    go_src[os.path.basename(path)] = open(path).read()

print("\n== SELECT sites touching nullable columns ==")
for tname, cols in sorted(tables.items()):
    for col, typ in sorted(cols.items()):
        for fname, src in sorted(go_src.items()):
            # find Select(...) blocks that mention both the table and the column
            for sm in re.finditer(r"Select\(([^;]*?)\)\s*\.?From\(\"" + tname + r"\"", src, re.S):
                block = sm.group(1)
                if re.search(r"\b" + col + r"\b", block):
                    fixed = "COALESCE" in block and col in block.split("COALESCE", 1)[-1] if "COALESCE" in block else False
                    # crude: is the column mention inside a COALESCE anywhere in block?
                    coalesced = any(
                        f"COALESCE({col}" in block.replace(" ", "").replace(f"COALESCE({col}::text", f"COALESCE({col}")
                        for _ in [0]
                    )
                    tag = "OK (coalesced)" if f"COALESCE({col}" in block.replace(" ", "") or f"COALESCE({col}::text" in block.replace(" ", "") else "BOMB"
                    print(f"  [{tag}] {tname}.{col} ({typ})  <-  {fname}")
                    lines = block.strip().splitlines()
                    for ln in lines[:6]:
                        print(f"      | {ln.strip()[:120]}")
                    break  # one representative select per table/col/file
