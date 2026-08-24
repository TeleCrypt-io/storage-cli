#!/usr/bin/env python3
"""Run one release command with bounded output and process-group cleanup."""

from __future__ import annotations

import argparse
import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path


def kill_group(process: subprocess.Popen[bytes], sig: int) -> None:
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--stdout-limit", type=int, required=True)
    parser.add_argument("--stderr-limit", type=int, required=True)
    parser.add_argument("--stdout-path", type=Path, required=True)
    parser.add_argument("--stderr-path", type=Path, required=True)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if (args.stdout_limit <= 0 or args.stderr_limit <= 0 or args.timeout <= 0 or
            len(args.command) < 2 or args.command[0] != "--"):
        return 64
    streams = {
        "stdout": {"limit": args.stdout_limit, "path": args.stdout_path, "used": 0},
        "stderr": {"limit": args.stderr_limit, "path": args.stderr_path, "used": 0},
    }
    overflow = False
    timed_out = False
    process = subprocess.Popen(args.command[1:], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    selector = selectors.DefaultSelector()
    files = {}
    for name, stream in streams.items():
        pipe = process.stdout if name == "stdout" else process.stderr
        assert pipe is not None
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ, name)
        files[name] = stream["path"].open("wb")
    term_sent_at: float | None = None
    close_at: float | None = None

    def terminate_group() -> None:
        nonlocal term_sent_at
        if term_sent_at is None:
            term_sent_at = time.monotonic()
            kill_group(process, signal.SIGTERM)

    try:
        deadline = time.monotonic() + args.timeout
        while selector.get_map():
            now = time.monotonic()
            if term_sent_at is None and now >= deadline:
                timed_out = True
                terminate_group()
            if term_sent_at is not None and now - term_sent_at >= 5.0:
                kill_group(process, signal.SIGKILL)
                close_at = now
            wait_for = 0.1 if term_sent_at is None else 0.0 if close_at is not None else 0.1
            if term_sent_at is None:
                wait_for = min(wait_for, max(0.0, deadline - now))
            for key, _ in selector.select(wait_for):
                name = key.data
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                stream = streams[name]
                remaining = stream["limit"] - stream["used"]
                if remaining > 0:
                    take = min(len(chunk), remaining)
                    files[name].write(chunk[:take])
                    stream["used"] += take
                if len(chunk) > max(remaining, 0):
                    overflow = True
                    terminate_group()
            if process.poll() is not None and selector.get_map() and close_at is None:
                terminate_group()
                close_at = time.monotonic() + 5.0
            if close_at is not None and time.monotonic() >= close_at:
                for key in list(selector.get_map().values()):
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                break
        if process.poll() is None:
            kill_group(process, signal.SIGKILL)
        try:
            returncode = process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            kill_group(process, signal.SIGKILL)
            returncode = process.wait(timeout=1.0)
    finally:
        for file in files.values():
            file.close()
        selector.close()
        if process.poll() is None:
            kill_group(process, signal.SIGKILL)
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass
    if overflow:
        print("bounded command output exceeded its stream limit", file=sys.stderr)
        return 1
    if timed_out:
        print("bounded command timed out", file=sys.stderr)
        return 124
    return 128 - returncode if returncode < 0 else returncode


if __name__ == "__main__":
    raise SystemExit(main())
