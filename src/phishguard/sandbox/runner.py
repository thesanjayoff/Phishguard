"""Thin, paranoid wrapper around `docker run`.

Design rules (the project's isolation contract):
  * Untrusted bytes (attachments, URLs) are given to the container over **stdin** - no bind
    mounts, so a compromised worker has no host path to touch.
  * Attachment analysis runs with `--network none`. There is NO host-side fallback: if Docker or the
    image is missing we raise SandboxUnavailable and the analysis for that item is skipped.
  * Containers are read-only, run as an unprivileged user, drop all capabilities, are
    PID/memory/CPU limited, and are killed on timeout. Output is size-capped and treated as untrusted.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass

log = logging.getLogger(__name__)


class SandboxUnavailable(RuntimeError):
    """Docker (or the required image) is not available. Callers must skip, never fall back to the host."""


@dataclass
class RunResult:
    stdout: bytes
    stderr: bytes
    returncode: int
    timed_out: bool = False
    truncated: bool = False


def hardening_args(*, network: str, memory: str = "512m", cpus: str = "1", pids: int = 128,
                   tmpfs_size: str = "128m", ipc_none: bool = True, shm: str | None = None) -> list[str]:
    args = [
        "--rm", "-i",
        "--network", network,
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(pids),
        "--memory", memory, "--memory-swap", memory,
        "--cpus", cpus,
        "--user", "65532:65532",
        "--tmpfs", f"/work:rw,noexec,nosuid,nodev,size={tmpfs_size}",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--label", "phishguard=1",
    ]
    if shm:
        args += ["--shm-size", shm]
    elif ipc_none:
        args += ["--ipc", "none"]
    return args


class DockerRunner:
    def __init__(self, docker_bin: str = "docker"):
        self.bin = docker_bin
        self._avail: tuple[float, bool, str] | None = None

    # ---- availability ------------------------------------------------------------
    def available(self) -> tuple[bool, str]:
        now = time.time()
        if self._avail and now - self._avail[0] < 60:
            return self._avail[1], self._avail[2]
        if shutil.which(self.bin) is None:
            res = (False, f"'{self.bin}' not found on PATH - install Docker (or Podman) to enable sandboxed analysis")
        else:
            try:
                p = subprocess.run([self.bin, "version", "--format", "{{.Server.Version}}"], capture_output=True,
                                   timeout=8, text=True)
                res = (p.returncode == 0, p.stdout.strip() or p.stderr.strip()[:200])
            except Exception as e:
                res = (False, f"docker not responding: {type(e).__name__}")
        self._avail = (now, res[0], res[1])
        return res

    def image_exists(self, image: str) -> bool:
        try:
            return subprocess.run([self.bin, "image", "inspect", image], capture_output=True, timeout=10).returncode == 0
        except Exception:
            return False

    def require(self, image: str) -> None:
        ok, why = self.available()
        if not ok:
            raise SandboxUnavailable(why)
        if not self.image_exists(image):
            raise SandboxUnavailable(f"image '{image}' not built - run: phishguard build-images")

    # ---- execution ------------------------------------------------------------------
    def run(self, image: str, cmd: list[str], stdin: bytes = b"", *, network: str = "none", timeout: int = 60,
            max_stdout: int = 6 * 1024 * 1024, memory: str = "512m", cpus: str = "1", pids: int = 128,
            tmpfs_size: str = "128m", shm: str | None = None, extra: list[str] | None = None) -> RunResult:
        self.require(image)
        name = "pg-" + uuid.uuid4().hex[:12]
        argv = [self.bin, "run", "--name", name,
                *hardening_args(network=network, memory=memory, cpus=cpus, pids=pids, tmpfs_size=tmpfs_size, shm=shm),
                *(extra or []), image, *cmd]
        log.debug("docker run %s image=%s", name, image)
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        state = {"timed_out": False, "truncated": False}

        def kill() -> None:
            state["timed_out"] = True
            subprocess.run([self.bin, "kill", name], capture_output=True)
            proc.kill()

        timer = threading.Timer(timeout, kill)
        timer.start()
        out_chunks: list[bytes] = []
        err_chunks: list[bytes] = []

        def feed() -> None:
            try:
                if proc.stdin:
                    proc.stdin.write(stdin)
                    proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass

        def drain_err() -> None:
            try:
                err_chunks.append(proc.stderr.read(64 * 1024) or b"")  # type: ignore[union-attr]
                proc.stderr.read()  # discard the rest  # type: ignore[union-attr]
            except Exception:
                pass

        threading.Thread(target=feed, daemon=True).start()
        te = threading.Thread(target=drain_err, daemon=True)
        te.start()
        try:
            total = 0
            while True:
                chunk = proc.stdout.read(65536)  # type: ignore[union-attr]
                if not chunk:
                    break
                total += len(chunk)
                if total > max_stdout:
                    state["truncated"] = True
                    subprocess.run([self.bin, "kill", name], capture_output=True)
                    proc.kill()
                    break
                out_chunks.append(chunk)
            proc.wait(timeout=10)
        finally:
            timer.cancel()
            te.join(timeout=2)
            subprocess.run([self.bin, "rm", "-f", name], capture_output=True)
        return RunResult(b"".join(out_chunks), b"".join(err_chunks), proc.returncode if proc.returncode is not None else -1,
                         state["timed_out"], state["truncated"])


def docker_runner(cfg) -> DockerRunner:
    return DockerRunner(cfg.sandbox.docker_bin)
