"""
Generic Ollama client for RedStorm.
Pass any JSON + any prompt → get answer.
"""
import json
import requests
import pathlib
import subprocess
from typing import Any, Optional

_BIN   = pathlib.Path(__file__).parent.parent / "ollama" / "ollama"
_DATA  = pathlib.Path(__file__).parent.parent / "ollama" / "ollama-data"
_URL   = "http://127.0.0.1:11434"
_MODEL = "llama3.1:8b"
_TIMEOUT = 300


# ---------- public ----------
def query(data: Any, prompt: Optional[str] = None, temperature: float = 0.3) -> str:
    """
    Send any Python object (dict, list, str, int …) to Llama-3.1-8B and return raw text.
    If no prompt is supplied we use a generic red-team summary template.
    """
    if not _server_up():
        raise RuntimeError("Ollama server not running at " + _URL)

    _ensure_model()

    if prompt is None:
        prompt = f"""You are a senior red-team operator.
Summarise the following JSON in ≤15 lines.
Flag any secrets, emails, buckets, git exposures, backup files, tech versions.
Give a 0-10 risk score and one short remediation tip.
JSON:
{json.dumps(data, indent=2)}
"""

    return _ask(prompt, temperature)


def query_json(data: Any, system: str, temperature: float = 0.0) -> Any:
    """
    Same as `query` but **forces valid JSON** output (set temp=0).
    system = instructions like "Return only JSON with keys: risk, tip"
    """
    prompt = f"{system}\n\nInput:\n{json.dumps(data, indent=2)}\n\nOutput (valid JSON only):"
    raw = _ask(prompt, temperature)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # last-resort clean-up
        raw = raw[raw.find("{"):raw.rfind("}") + 1]
        return json.loads(raw)


# ---------- internal ----------
def _server_up() -> bool:
    try:
        return requests.head(_URL, timeout=2).status_code == 200
    except Exception:
        return False


def _ensure_model() -> None:
    lst = subprocess.run([str(_BIN), "list"], capture_output=True, text=True).stdout
    if _MODEL not in lst:
        subprocess.run([str(_BIN), "pull", _MODEL], check=True)


def _ask(prompt: str, temperature: float) -> str:
    resp = requests.post(
        f"{_URL}/api/generate",
        json={"model": _MODEL, "prompt": prompt, "stream": False, "options": {"temperature": temperature}},
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()["response"].strip()