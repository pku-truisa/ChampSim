#!/usr/bin/env python3
"""
Synthetic test for little_object_analyzer.py v5 — covers all 23 symbols (Fortran 24-39 removed).
No PIN required.
"""

import struct, os, sys, subprocess, re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

ANALYZER = os.path.join(os.path.dirname(__file__), '..', 'little_object_analyzer.py')

PASS = 0; FAIL = 0

def check(cond, msg):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  ✅ PASS: {msg}")
    else: FAIL += 1; print(f"  ❌ FAIL: {msg}")

def wr(f, t, a1, a2, r):
    f.write(struct.pack("<QQQB7s", a1, a2, r, t, b'\x00'*7))

def gen(fp):
    with open(fp, "wb") as f:
        # Phase 1: malloc/free basics
        wr(f, 1, 100, 0, 0x1000); wr(f, 1, 200, 0, 0x2000)
        wr(f, 1, 50, 0, 0x3000);  wr(f, 18, 0x1000, 0, 0)
        wr(f, 1, 300, 0, 0x4000)
        # Phase 2: calloc
        wr(f, 7, 400, 0, 0x5000)
        # Phase 3: mmap/munmap
        wr(f, 16, 4096, 0, 0x6000); wr(f, 17, 0x6000, 4096, 0)
        # Phase 4-5: realloc
        wr(f, 11, 0x2000, 500, 0x7000); wr(f, 11, 0x4000, 800, 0x4000)
        # Phase 6: posix_memalign
        wr(f, 15, 256, 64, 0x8000)
        # Phase 7: ALL malloc-like (2-6)
        wr(f, 2, 128, 0, 0x9000); wr(f, 3, 64, 0, 0xA000)
        wr(f, 4, 256, 0, 0xB000); wr(f, 5, 1024, 0, 0xC000)
        wr(f, 6, 512, 0, 0xD000)
        # Phase 8: ALL calloc-like (8-10)
        wr(f, 8, 500, 0, 0xE000); wr(f, 9, 600, 0, 0xF000)
        wr(f, 10, 1000, 0, 0x10000)
        # Phase 9: ALL realloc-like (12-14)
        wr(f, 12, 0xE000, 1200, 0x11000); wr(f, 13, 0xF000, 800, 0x12000)
        wr(f, 14, 0x10000, 2000, 0x13000)
        # Phase 10: delete (22,23) — tracked
        wr(f, 22, 0xB000, 0, 0); wr(f, 23, 0x9000, 0, 0)
        # Phase 11: custom free (19-21) — orphan
        wr(f, 19, 0x14000, 0, 0); wr(f, 20, 0x15000, 0, 0); wr(f, 21, 0x16000, 0, 0)
        # Phase 12: mop-up orphan
        wr(f, 18, 0xDEAD, 0, 0); wr(f, 17, 0xBEEF, 8192, 0)

def main():
    global PASS, FAIL
    print("=" * 70)
    print("23-Symbol Synthetic Test (v5, Fortran symbols removed)")
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

    # Expected: 4(malloc1)+1(calloc7)+1(mmap16)+2(realloc11)+1(posix15)
    #   +5(malloc2-6)+3(calloc8-10)+3(realloc12-14) = 20
    check(total_alloc == 20, f"Total Alloc = {total_alloc} (expected 20)")
    # Frees: 1(phase1)+1(munmap)+2(delete22-23)+3(custom19-21)+2(orphan) = 9
    check(total_free == 9, f"Total Free = {total_free} (expected 9)")

    # Verify all 23 symbols present
    seen = set()
    for line in txt.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                code = int(parts[-2])
                seen.add(code)
            except (ValueError, IndexError): pass

    # Parse TYPE_MAP from analyzer
    typemap = {}
    for line in open(os.path.join(td, '..', 'little_object_analyzer.py')):
        m2 = re.match(r"\s*(\d+):\s*['\"]([^'\"]+)['\"]", line)
        if m2: typemap[int(m2.group(1))] = m2.group(2)

    missing = [typemap.get(c, f"code {c}") for c in range(1, 24) if c not in seen]
    check(len(missing) == 0, f"All 23 symbols covered (missing: {missing})")

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