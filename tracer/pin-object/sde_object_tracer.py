#!/usr/bin/env python3
#
# sde_object_tracer.py — SDE Object Tracer wrapper
#
# Usage:
#   Live trace:  sde_object_tracer.py -- ./program [args...]
#   Replay:      sde_object_tracer.py --replay --pinball <basename>
#   Region dir:  sde_object_tracer.py --replay --pinball_dir <dir>
#

import os
import sys
import subprocess
import argparse
import glob


def get_sde():
    """Return (sde_binary, kit_path) tuple."""
    kit = os.environ.get("SDE_BUILD_KIT", "")
    if not kit:
        sys.exit("ERROR: SDE_BUILD_KIT environment variable not set")
    sde64 = os.path.join(kit, "sde64")
    if not os.path.isfile(sde64):
        sys.exit(f"ERROR: {sde64} not found")
    return sde64, kit


def find_pintool(kit):
    """Ensure object_tracer.so is installed in kit and return the tool name."""
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "obj-intel64", "object_tracer.so")
    kit_path = os.path.join(kit, "intel64", "object_tracer.so")
    if os.path.isfile(local):
        import shutil
        shutil.copy2(local, kit_path)
        print(f"[sde_object_tracer] Installed {local} -> {kit_path}")
    if not os.path.isfile(kit_path):
        sys.exit("ERROR: object_tracer.so not found. Build with 'make PIN_ROOT=$SDE_BUILD_KIT/pinkit'")
    return "object_tracer.so"  # SDE resolves tool name relative to kit/intel64/


def run_live(sde64, pintool, program_args, output="malloc.bin", arch="-skl"):
    """Run live trace with object_tracer.so."""
    cmd = [sde64, arch, "-t", pintool, "-m", output, "--"] + program_args
    print(f"[sde_object_tracer] Running: {' '.join(cmd)}")
    return subprocess.run(cmd).returncode


def replay_pinball(sde64, pintool, basename, output="malloc.bin", arch="-skl"):
    """Replay a single pinball with object_tracer.so. Returns True if output was generated."""
    kit = os.path.dirname(sde64)
    nullapp = os.path.join(kit, "intel64", "nullapp")
    if not os.path.isfile(nullapp):
        sys.exit(f"ERROR: {nullapp} not found")

    cmd = [
        sde64, arch,
        "-replay",
        "-t", pintool, "-m", output,
        "-replay:basename", basename,
        "-replay:strace",
        "-replay:playout", "0",
        "-replay:deadlock_timeout", "0",
        "-xyzzy",
        "--", nullapp
    ]
    print(f"[sde_object_tracer] Replaying: {basename}")
    subprocess.run(cmd)  # ignore return code (SDE may return non-zero due to NFE warnings)
    return os.path.isfile(output)


def compress_output(src, dst=None):
    """Compress src. If dst given, rename src to dst first, then xz -kf dst."""
    if dst:
        os.rename(src, dst)
        src = dst
    print(f"[sde_object_tracer] Compressing: {src} -> {src}.xz")
    return subprocess.run(["xz", "-kf", src]).returncode


def main():
    parser = argparse.ArgumentParser(
        description="SDE Object Tracer — capture malloc/free traces with object_tracer.so")
    parser.add_argument("--replay", action="store_true",
                        help="Replay a pinball (requires --pinball or --pinball_dir)")
    parser.add_argument("--pinball", type=str, default=None,
                        help="Pinball basename for single replay")
    parser.add_argument("--pinball_dir", type=str, default=None,
                        help="Directory containing *.address pinballs for batch replay")
    parser.add_argument("--output", "-m", type=str, default="malloc.bin",
                        help="Output file name (default: malloc.bin)")
    parser.add_argument("--arch", type=str, default="-skl",
                        help="SDE architecture flag (default: -skl)")
    parser.add_argument("--compress", action="store_true", default=True,
                        help="Compress output with xz (default: True)")
    parser.add_argument("--no-compress", dest="compress", action="store_false",
                        help="Do not compress output")
    parser.add_argument("program_args", nargs=argparse.REMAINDER,
                        help="Program and arguments (after --)")

    args = parser.parse_args()

    sde64, kit = get_sde()
    pintool = find_pintool(kit)

    ret = 0

    if args.replay:
        if args.pinball:
            basename = args.pinball
            ok = replay_pinball(sde64, pintool, basename, args.output, args.arch)
            if ok and args.compress:
                compress_output(args.output, basename + ".malloc.bin")
            elif not ok:
                sys.exit(1)
        elif args.pinball_dir:
            pattern = os.path.join(args.pinball_dir, "*.address")
            address_files = sorted(glob.glob(pattern))
            if not address_files:
                sys.exit(f"ERROR: No .address files found in {args.pinball_dir}")
            for addr_file in address_files:
                rpb_name = addr_file.replace(".address", "")
                out_name = rpb_name + ".malloc.bin"
                ok = replay_pinball(sde64, pintool, rpb_name, out_name, args.arch)
                if not ok:
                    print(f"WARNING: replay of {rpb_name} did not produce output", file=sys.stderr)
                elif args.compress:
                    compress_output(out_name)
        else:
            sys.exit("ERROR: --replay requires --pinball or --pinball_dir")
    else:
        if not args.program_args:
            sys.exit("ERROR: No program specified. Use '-- ./program [args...]'")
        ret = run_live(sde64, pintool, args.program_args, args.output, args.arch)
        if ret == 0 and args.compress:
            compress_output(args.output)

    sys.exit(ret)


if __name__ == "__main__":
    main()