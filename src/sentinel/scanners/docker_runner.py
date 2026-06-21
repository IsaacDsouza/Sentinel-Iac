import subprocess
import sys
from pathlib import Path

DOCKER_MEMORY = "512m"
DOCKER_CPUS = "1"


def _docker_available() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def run_docker_container(
    image: str,
    command: list[str],
    target_path: Path,
    container_scan_dir: str = "/scan",
    read_only: bool = True,
    network_enabled: bool = False,
    extra_mounts: list[tuple[str, str]] | None = None,
) -> subprocess.CompletedProcess[str]:
    target_abs = target_path.resolve()
    if sys.platform == "win32":
        target_str = str(target_abs).replace("\\", "/")
        if target_str[1] == ":":
            target_str = "/" + target_str[0].lower() + target_str[2:]
    else:
        target_str = str(target_abs)

    cmd = [
        "docker",
        "run",
        "--rm",
    ]
    if not network_enabled:
        cmd.extend(["--network", "none"])
    if read_only:
        cmd.extend(["--read-only"])
    cmd.extend([
        "-v",
        f"{target_str}:{container_scan_dir}:ro",
        "--memory",
        DOCKER_MEMORY,
        "--cpus",
        DOCKER_CPUS,
    ])
    if extra_mounts:
        for host_path, container_path in extra_mounts:
            cmd.extend(["-v", f"{host_path}:{container_path}"])
    cmd.append(image)
    cmd.extend(c.replace("{SCAN_DIR}", container_scan_dir) for c in command)

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
    )


def run_local_command(
    binary: str,
    args: list[str],
    target_path: Path,
) -> subprocess.CompletedProcess[str]:
    cmd = [binary, *[a.replace("{SCAN_DIR}", str(target_path)) for a in args]]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _make_failed_result(error_msg: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[],
        returncode=-1,
        stdout="",
        stderr=error_msg,
    )


def best_effort_run(
    image: str,
    command: list[str],
    binary: str,
    local_args: list[str],
    target_path: Path,
    container_scan_dir: str = "/scan",
    read_only: bool = True,
    network_enabled: bool = False,
    extra_mounts: list[tuple[str, str]] | None = None,
) -> subprocess.CompletedProcess[str]:
    if _docker_available():
        try:
            return run_docker_container(
                image, command, target_path, container_scan_dir,
                read_only=read_only, network_enabled=network_enabled,
                extra_mounts=extra_mounts,
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
    try:
        return run_local_command(binary, local_args, target_path)
    except FileNotFoundError:
        return _make_failed_result(
            f"Binary '{binary}' not found on PATH. Install it or start Docker."
        )
    except OSError as e:
        return _make_failed_result(f"Failed to run '{binary}': {e}")
