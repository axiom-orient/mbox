#!/usr/bin/env python3
"""Optional real-PTY regression check; uses only the Python standard library.

Build mbox and the macOS sandbox probe with the native verifier first. This
check owns a separate controlling terminal and never uses the caller's tty.
"""

import argparse
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import pty
import re
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time


ROOT = Path(__file__).resolve().parents[2]
MAX_TRANSCRIPT_BYTES = 64 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def positive_integer(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def positive_timeout(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be finite and positive")
    return number


def process_identity(probe, pid):
    result = subprocess.run(
        [str(probe), "process-identity", str(pid)],
        capture_output=True, text=True, timeout=2,
    )
    value = result.stdout.strip()
    if result.returncode == 0:
        require(re.fullmatch(rf"{pid}\|[0-9]+\|[0-9]+", value),
                f"invalid identity for PID {pid}: {value!r}")
        return value
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    raise RuntimeError(f"cannot identify live PID {pid}: probe status {result.returncode}")


def signal_exact(probe, pid, expected, number, actions):
    try:
        observed = process_identity(probe, pid)
        if observed is None:
            return
        if not expected or observed != expected:
            actions.append({"pid": pid, "signal_refused": number,
                            "expected": expected, "observed": observed})
            return
        os.kill(pid, number)
        actions.append({"pid": pid, "identity": expected, "signal": number})
    except ProcessLookupError:
        pass
    except Exception as error:
        actions.append({"pid": pid, "signal_refused": number, "error": str(error)})


def wait_direct_child(pid, timeout):
    deadline = time.monotonic() + timeout
    while True:
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed == pid:
            return status
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.05)


def driver(mbox, workdir, mode):
    for number in (signal.SIGINT, signal.SIGQUIT, signal.SIGTERM,
                   signal.SIGTTIN, signal.SIGTTOU):
        signal.signal(number, signal.SIG_DFL)
    settings = termios.tcgetattr(0)
    settings[3] |= termios.ISIG | termios.ICANON
    settings[3] &= ~termios.ECHO
    settings[6][termios.VINTR] = b"\x03"
    termios.tcsetattr(0, termios.TCSANOW, settings)
    original = os.getpgrp()
    require(os.tcgetpgrp(0) == original, "driver does not own the foreground tty")
    print(f"DRIVER:{os.getpid()}:{original}:SIGINT={signal.getsignal(signal.SIGINT)}",
          flush=True)
    target = ('printf "TARGET:%s\\n" "$$"; IFS= read -r line; '
              'printf "GOT:%s\\n" "$line"; exit 37')
    process = subprocess.Popen(
        [str(mbox), "--cwd", str(workdir), "--allow-net", "example.com", "--",
         "/bin/sh", "-c", target], close_fds=True,
    )
    print(f"MBOX:{process.pid}", flush=True)
    code = process.wait()
    foreground = os.tcgetpgrp(0)
    print(f"RESULT:{code}:{foreground}:{original}", flush=True)
    require(code == (130 if mode == "interrupt" else 37), f"target status {code}")
    require(foreground == original, "foreground group was not restored")
    followup = os.read(0, 1024)
    require(followup == b"caller followup\n", f"followup input changed: {followup!r}")
    print("FOLLOWUP:OK", flush=True)


def read_pty(master):
    try:
        return os.read(master, 8192)
    except OSError as error:
        if error.errno == errno.EIO:
            return b""
        raise


def run_case(args, evidence, mode, index):
    start = time.monotonic()
    sys.stdout.flush()
    child, master = pty.fork()
    if child == 0:
        try:
            driver(args.mbox, evidence, mode)
        except BaseException as error:
            try:
                print(f"DRIVER-ERROR:{type(error).__name__}:{error}", flush=True)
            finally:
                os._exit(2)
        os._exit(0)

    known = {}
    transcript = b""
    mbox_pid = target_pid = wait_status = None
    sent = followup_sent = False
    actions = []
    observations = {}
    failure = None
    try:
        known[child] = process_identity(args.probe, child)
        require(known[child], "driver exited before identity capture")
        while time.monotonic() - start < args.timeout:
            if select.select([master], [], [], 0.05)[0]:
                transcript += read_pty(master)
            require(len(transcript) <= MAX_TRANSCRIPT_BYTES, "PTY transcript exceeded bound")
            text = transcript.decode(errors="replace")
            match = re.search(r"MBOX:([0-9]+)", text)
            if match and mbox_pid is None:
                mbox_pid = int(match[1])
                known[mbox_pid] = process_identity(args.probe, mbox_pid)
            match = re.search(r"TARGET:([0-9]+)", text)
            if match and target_pid is None:
                target_pid = int(match[1])
                known[target_pid] = process_identity(args.probe, target_pid)
            if target_pid and not sent:
                foreground = os.tcgetpgrp(master)
                group = os.getpgid(target_pid)
                observations.update({"target_pid": target_pid, "target_pgid": group,
                                     "tty_foreground": foreground,
                                     "target_identity": known[target_pid],
                                     "mbox_identity": known.get(mbox_pid)})
                if foreground == target_pid:
                    require(group == target_pid, "target is not its process-group leader")
                    require(known[target_pid] and mbox_pid and known.get(mbox_pid),
                            "target or supervisor identity was not captured")
                    value = b"\x03" if mode == "interrupt" else f"interactive value {index}\n".encode()
                    require(os.write(master, value) == len(value), "incomplete PTY input")
                    sent = True
            match = re.search(r"RESULT:(-?[0-9]+):([0-9]+):([0-9]+)", text)
            if match and not followup_sent:
                code, foreground, original = map(int, match.groups())
                observations.update({"result": code, "restored_foreground": foreground,
                                     "original_foreground": original})
                require(code == (130 if mode == "interrupt" else 37), f"target status {code}")
                require(foreground == original, "foreground group was not restored")
                if mode == "normal":
                    require(f"GOT:interactive value {index}\r\n" in text, "target input changed")
                value = b"caller followup\n"
                require(os.write(master, value) == len(value), "incomplete followup input")
                followup_sent = True
            wait_status = wait_direct_child(child, 0)
            if wait_status is not None:
                while select.select([master], [], [], 0)[0]:
                    tail = read_pty(master)
                    if not tail:
                        break
                    transcript += tail
                    require(len(transcript) <= MAX_TRANSCRIPT_BYTES, "PTY transcript exceeded bound")
                require(os.waitstatus_to_exitcode(wait_status) == 0,
                        f"driver status {os.waitstatus_to_exitcode(wait_status)}")
                require(sent and followup_sent and b"FOLLOWUP:OK" in transcript,
                        "PTY exchange did not complete")
                break
        else:
            raise TimeoutError(f"case exceeded {args.timeout}s")
    except BaseException as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        if failure is not None:
            if mbox_pid:
                signal_exact(args.probe, mbox_pid, known.get(mbox_pid), signal.SIGTERM, actions)
            if wait_status is None:
                wait_status = wait_direct_child(child, 6)
            for pid in (target_pid, mbox_pid, child if wait_status is None else None):
                if pid:
                    signal_exact(args.probe, pid, known.get(pid), signal.SIGKILL, actions)
            if wait_status is None:
                wait_status = wait_direct_child(child, 3)
        os.close(master)

    survivors = {}
    for pid, expected in known.items():
        try:
            observed = process_identity(args.probe, pid)
            if observed and observed == expected:
                survivors[str(pid)] = observed
        except Exception as error:
            survivors[str(pid)] = f"UNKNOWN: {error}"
    if survivors or wait_status is None:
        failure = failure or "owned process survived or driver could not be reaped"
    return {"mode": mode, "index": index, "pass": failure is None,
            "duration_seconds": round(time.monotonic() - start, 3),
            "observations": observations, "transcript": transcript.decode(errors="replace"),
            "failure": failure, "cleanup": actions, "survivors": survivors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mbox", type=Path, default=ROOT / "target/debug/mbox")
    parser.add_argument("--probe", type=Path, default=ROOT / "target/mbox-macos-sandbox-probe")
    parser.add_argument("--evidence-dir", type=Path,
                        help="parent directory for a new evidence directory; default: system temp")
    parser.add_argument("--normal", type=positive_integer, default=5)
    parser.add_argument("--interrupt", type=positive_integer, default=3)
    parser.add_argument("--timeout", type=positive_timeout, default=8)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.exit(69, "interactive PTY verification requires macOS\n")
    if sys.version_info < (3, 9):
        parser.exit(69, "interactive PTY verification requires Python 3.9+\n")
    for name in ("mbox", "probe"):
        path = getattr(args, name).resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.exit(69, f"{name} is not an executable file: {path}\n")
        setattr(args, name, path)
    parent = (args.evidence_dir or Path(tempfile.gettempdir())).resolve()
    if parent == ROOT or ROOT in parent.parents:
        parser.error("evidence directory must be outside the repository")
    parent.mkdir(parents=True, exist_ok=True)
    evidence = Path(tempfile.mkdtemp(prefix="mbox-pty-", dir=parent)).resolve()
    metadata = {"host": list(os.uname()), "mbox": str(args.mbox), "probe": str(args.probe),
                "mbox_sha256": hashlib.sha256(args.mbox.read_bytes()).hexdigest(),
                "probe_sha256": hashlib.sha256(args.probe.read_bytes()).hexdigest()}
    (evidence / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"PTY evidence: {evidence}", flush=True)
    results = []
    for mode, count in (("normal", args.normal), ("interrupt", args.interrupt)):
        for index in range(count):
            result = run_case(args, evidence, mode, index)
            results.append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
            (evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
            if not result["pass"]:
                return 1
    print(f"interactive PTY: PASS ({len(results)} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
