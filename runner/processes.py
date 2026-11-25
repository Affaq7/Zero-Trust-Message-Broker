"""Start and stop the testbed processes for one repetition.

The mock services and every agent of a scenario run as separate uvicorn
processes on free local ports. Each gets a clean environment set by the
runner (MODE=direct, AGENT_*, LLM_*, LOG_DIR ...): inherited values for
these names are removed and every one is set explicitly, so nothing from
the runner's shell or a .env file leaks in. Testbed is a context manager:
all processes are stopped on normal exit, on an exception and on Ctrl+C.
"""

import atexit
import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from agents.telemetry import OFF as TELEMETRY_OFF

CONTROLLED_PREFIXES = ("MODE", "AGENT_", "LLM_", "LOG_DIR", "MOCKS_", "PLANNER_", "RESEARCH_", "MALICIOUS_")
STARTUP_TIMEOUT_S = 120.0
STOP_TIMEOUT_S = 10.0


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def port_is_free(port: int) -> bool:
    """True if a new server could listen on the port now.

    On Linux/macOS a port whose server just closed stays in TIME_WAIT for up to a
    minute; uvicorn binds with SO_REUSEADDR and would start fine, so the check does
    the same. Not on Windows, where SO_REUSEADDR would allow binding over a live server.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if os.name != "nt":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def clean_base_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(CONTROLLED_PREFIXES)}
    env.update(TELEMETRY_OFF)
    env["PYTHONUNBUFFERED"] = "1"
    return env


@dataclass
class Proc:
    name: str
    app: str
    port: int
    env: dict[str, str]
    popen: subprocess.Popen | None = None
    log_path: Path | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@dataclass
class TestbedConfig:
    __test__ = False   # not a pytest test class

    agents: list[dict]                       # [{"name", "impl", "role"}]
    run_dir: Path
    seed: int = 0
    llm_backend: str = "fake"                # "fake" or "ollama"
    fake_llm: dict[str, dict] = field(default_factory=dict)
    llm_base_url: str = "http://localhost:11434"
    python: str = sys.executable
    debug_prompts: bool = False              # PLANNER_DEBUG_PROMPTS=1 for the agents
    planner_prompt: str = ""                 # PLANNER_PROMPT; "" = the planner's default version
    mode: str = "direct"                     # MODE for every agent process (operator-set, never from a message)


class Testbed:
    __test__ = False   # not a pytest test class

    def __init__(self, config: TestbedConfig):
        self.config = config
        self.procs: dict[str, Proc] = {}
        self._registered = False
        self.leftover_ports: list[int] = []

    # --- setup -----------------------------------------------------------------

    def _plan(self) -> None:
        c = self.config
        logs = c.run_dir / "logs"
        base = clean_base_env()
        mocks = Proc("mocks", "mocks.main:app", free_port(), {
            **base, "MOCKS_RUNTIME_DIR": str(c.run_dir / "runtime"), "LOG_DIR": str(logs)})
        self.procs["mocks"] = mocks
        ports = {a["name"]: free_port() for a in c.agents}
        urls = ",".join(f"{n}=http://127.0.0.1:{p}" for n, p in ports.items())
        fake_dir = c.run_dir / "fake_llm"
        fake_dir.mkdir(parents=True, exist_ok=True)
        behaviour_dir = c.run_dir / "behaviour"
        behaviour_dir.mkdir(parents=True, exist_ok=True)
        for a in c.agents:
            script = fake_dir / f"{a['name']}.json"
            script.write_text(json.dumps(c.fake_llm.get(a["name"], {})), encoding="utf-8")
            # Compromised-responder deviation (data, like the fake-LLM script); empty file when honest.
            behaviour = a.get("behaviour")
            behaviour_file = behaviour_dir / f"{a['name']}.json"
            behaviour_file.write_text(json.dumps(behaviour) if behaviour else "", encoding="utf-8")
            self.procs[a["name"]] = Proc(a["name"], "wrapper.main:app", ports[a["name"]], {
                **base, "MODE": c.mode, "AGENT_NAME": a["name"],
                "AGENT_IMPL": a.get("impl") or "", "AGENT_ROLE": a.get("role") or "",
                "AGENT_URLS": urls, "MOCKS_URL": mocks.url, "LOG_DIR": str(logs),
                "LLM_BACKEND": c.llm_backend, "LLM_SEED": str(c.seed),
                "LLM_FAKE_SCRIPT": str(script) if c.llm_backend == "fake" else "",
                "MALICIOUS_BEHAVIOUR": str(behaviour_file) if behaviour else "",
                "LLM_BASE_URL": c.llm_base_url,
                "PLANNER_DEBUG_PROMPTS": "1" if c.debug_prompts else "",
                "RESEARCH_DEBUG_PROMPTS": "1" if c.debug_prompts else "",
                "PLANNER_PROMPT": c.planner_prompt,
            })

    def start(self) -> "Testbed":
        self._plan()
        if not self._registered:
            atexit.register(self.stop)
            self._registered = True
        proc_dir = self.config.run_dir / "processes"
        proc_dir.mkdir(parents=True, exist_ok=True)
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        try:
            for p in self.procs.values():
                p.log_path = proc_dir / f"{p.name}.log"
                with open(p.log_path, "w", encoding="utf-8") as out:
                    p.popen = subprocess.Popen(
                        [self.config.python, "-m", "uvicorn", p.app, "--host", "127.0.0.1",
                         "--port", str(p.port)],
                        env=p.env, stdout=out, stderr=subprocess.STDOUT, creationflags=flags)
            for p in self.procs.values():
                self._wait_healthy(p)
        except BaseException:
            self.stop()
            raise
        return self

    def _wait_healthy(self, p: Proc) -> None:
        deadline = time.monotonic() + STARTUP_TIMEOUT_S
        while time.monotonic() < deadline:
            if p.popen.poll() is not None:
                raise RuntimeError(f"{p.name} exited during startup; see {p.log_path}")
            try:
                if httpx.get(f"{p.url}/health", timeout=1.0).status_code == 200:
                    return
            except httpx.TransportError:
                pass
            time.sleep(0.3)
        raise RuntimeError(f"{p.name} not healthy after {STARTUP_TIMEOUT_S}s; see {p.log_path}")

    # --- teardown --------------------------------------------------------------

    def stop(self) -> None:
        for p in self.procs.values():
            if p.popen and p.popen.poll() is None:
                p.popen.terminate()
        for p in self.procs.values():
            if p.popen:
                try:
                    p.popen.wait(timeout=STOP_TIMEOUT_S)
                except subprocess.TimeoutExpired:
                    p.popen.kill()
                    p.popen.wait(timeout=STOP_TIMEOUT_S)
        # Windows releases a dead process's listening port a moment later.
        deadline = time.monotonic() + STOP_TIMEOUT_S
        busy = [p.port for p in self.procs.values() if p.popen]
        while busy and time.monotonic() < deadline:
            busy = [port for port in busy if not port_is_free(port)]
            if busy:
                time.sleep(0.2)
        self.leftover_ports = busy

    def __enter__(self) -> "Testbed":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def url(self, name: str) -> str:
        return self.procs[name].url
