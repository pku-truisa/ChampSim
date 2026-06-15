#!/usr/bin/env python3
"""
Synthetic test for little_object_analyzer.py v7 — covers all 7 type groups.
Uses the analyzer from tracer/nopin-object (the only copy).
No PIN required.
"""

import struct, os, sys, subprocess, re

# Use analyzer from nopin-object (the canonical copy)
ANALYZER = os.path.join(os.path.dirname(__file__), '..', '..', 'nopin-object', 'little_object_analyzer.py')

PASS = 0; FAIL = 0

def check(cond, msg):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  ✅ PASS: {msg}")
    else: FAIL += 1; print(f"  ❌ FAIL: {msg}")

def wr(f, t, a1, a2, r):
    f.write(struct.pack("<QQQB7s", a1, a2, r, t, b'\x00'*7))

def gen(fp):
    with open(fp, "wb") as f:
        # Phase 1: malloc/free basics (type 1 = malloc/new, type 2 = free/delete)
        wr(f, 1, 100, 0, 0x1000); wr(f, 1, 200, 0, 0x2000)
        wr(f, 1, 50, 0, 0x3000);  wr(f, 2, 0x1000, 0, 0)
        wr(f, 1, 300, 0, 0x4000)
        # Phase 2: calloc (type 3)
        wr(f, 3, 400, 0, 0x5000)
        # Phase 3: mmap/munmap (type 6, 7)
        wr(f, 6, 4096, 0, 0x6000); wr(f, 7, 0x6000, 4096, 0)
        # Phase 4-5: realloc (type 4)
        wr(f, 4, 0x2000, 500, 0x7000); wr(f, 4, 0x4000, 800, 0x4000)
        # Phase 6: posix_memalign (type 5)
        wr(f, 5, 256, 64, 0x8000)
        # Phase 7: More malloc-like (type 1)
        wr(f, 1, 128, 0, 0x9000); wr(f, 1, 64, 0, 0xA000)
        wr(f, 1, 256, 0, 0xB000); wr(f, 1, 1024, 0, 0xC000)
        wr(f, 1, 512, 0, 0xD000)
        # Phase 8: More calloc (type 3)
        wr(f, 3, 500, 0, 0xE000); wr(f, 3, 600, 0, 0xF000)
        wr(f, 3, 1000, 0, 0x10000)
        # Phase 9: More realloc (type 4)
        wr(f, 4, 0xE000, 1200, 0x11000); wr(f, 4, 0xF000, 800, 0x12000)
        wr(f, 4, 0x10000, 2000, 0x13000)
        # Phase 10: free/delete (type 2) — tracked
        wr(f, 2, 0xB000, 0, 0); wr(f, 2, 0x9000, 0, 0)
        # Phase 11: more frees (type 2) — orphan
        wr(f, 2, 0x14000, 0, 0); wr(f, 2, 0x15000, 0, 0); wr(f, 2, 0x16000, 0, 0)
        # Phase 12: mop-up munmap + free
        wr(f, 2, 0xDEAD, 0, 0); wr(f, 7, 0xBEEF, 8192, 0)

def main():
    global PASS, FAIL
    print("=" * 70)
    print("7-Type Synthetic Test (v7 analyzer, pin-object)")
    print("=" * 70)
    td = os.path.dirname(os.path.abspath(__file__))
    tp = os.path.join(td, "synth.bin")

    gen(tp)
    sz = os.path.getsize(tp)
    check(sz > 0, f"Trace created ({sz} bytes)")
    check(sz % 32 == 0, f"Multiple of 32 ({sz//32} records)")

    r = subprocess.run(["python3", ANALYZER, "-i", tp], capture_output=True, text=True, cwd=td)
    print(r.stdout.strip()[:500] + "..." if len(r.stdout) > 500 else r.stdout)

    rl = tp.replace('.bin', '.result.log')
    check(os.path.exists(rl), "result.log exists")

    txt = open(rl).read()
    m = re.search(r'Total Alloc calls:\s+(\d+)', txt)
    total_alloc = int(m.group(1)) if m else 0
    m = re.search(r'Total Free calls:\s+(\d+)', txt)
    total_free = int(m.group(1)) if m else 0

    # Expected allocs:
    #   malloc(1): 4(base) + 5(more) = 9
    #   calloc(3): 1 + 3 = 4
    #   realloc(4): 2 + 3 = 5
    #   posix_memalign(5): 1
    #   mmap(6): 1
    #   Total alloc: 20
    check(total_alloc == 20, f"Total Alloc = {total_alloc} (expected 20)")
    # Expected frees:
    #   free(2): 1 + 2 + 3 + 1 = 7
    #   munmap(7): 1 + 1 = 2
    #   Total free: 9
    check(total_free == 9, f"Total Free = {total_free} (expected 9)")

    # Verify all 7 type groups present
    TYPE_MAP = {
        1: 'malloc/new', 2: 'free/delete', 3: 'calloc',
        4: 'realloc', 5: 'posix_memalign', 6: 'mmap', 7: 'munmap'
    }

    seen = set()
    for line in txt.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                code = int(parts[-2])
                seen.add(code)
            except (ValueError, IndexError): pass

    missing = [TYPE_MAP.get(c, f"code {c}") for c in range(1, 8) if c not in seen]
    check(len(missing) == 0, f"All 7 type groups covered (missing: {missing})")

    # Verify breakdown counts by type
    m1 = re.search(r'malloc/new\s+1\s+(\d+)', txt)
    count_malloc = int(m1.group(1)) if m1 else 0
    check(count_malloc == 9, f"malloc/new count = {count_malloc} (expected 9)")

    m2 = re.search(r'calloc\s+3\s+(\d+)', txt)
    count_calloc = int(m2.group(1)) if m2 else 0
    check(count_calloc == 4, f"calloc count = {count_calloc} (expected 4)")

    m3 = re.search(r'realloc\s+4\s+(\d+)', txt)
    count_realloc = int(m3.group(1)) if m3 else 0
    check(count_realloc == 5, f"realloc count = {count_realloc} (expected 5)")

    m4 = re.search(r'posix_memalign\s+5\s+(\d+)', txt)
    count_posix = int(m4.group(1)) if m4 else 0
    check(count_posix == 1, f"posix_memalign count = {count_posix} (expected 1)")

    m5 = re.search(r'mmap\s+6\s+(\d+)', txt)
    count_mmap = int(m5.group(1)) if m5 else 0
    check(count_mmap == 1, f"mmap count = {count_mmap} (expected 1)")

    m6 = re.search(r'free/delete\s+2\s+(\d+)', txt)
    count_free = int(m6.group(1)) if m6 else 0
    check(count_free == 7, f"free/delete count = {count_free} (expected 7)")

    m7 = re.search(r'munmap\s+7\s+(\d+)', txt)
    count_munmap = int(m7.group(1)) if m7 else 0
    check(count_munmap == 2, f"munmap count = {count_munmap} (expected 2)")

    print(f"\nResults: {PASS} passed, {FAIL} failed / {PASS+FAIL}")
    if FAIL:
        print("⚠️  FAILURES")
        print(txt[-1000:])
    else:
        print("🎉 ALL PASSED")

    for f in [tp, rl]:
        if os.path.exists(f): os.remove(f)

    return FAIL

if __name__ == '__main__':
    sys.exit(main())