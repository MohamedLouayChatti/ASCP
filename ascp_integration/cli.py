from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Sequence

import httpx


DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_CHAT_MODEL = "llama3.2"
DEFAULT_EMBED_MODEL = "hf.co/CompendiumLabs/bge-base-en-v1.5-gguf:latest"
DEFAULT_CHAT_TIMEOUT = 120.0
DEFAULT_EMBED_TIMEOUT = 60.0


@dataclass(frozen=True)
class SetupOptions:
    yes: bool
    ollama_url: str
    chat_model: str
    embed_model: str
    chat_timeout: float
    embed_timeout: float
    skip_install: bool
    skip_start: bool


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "setup-grounding":
        return setup_grounding(
            SetupOptions(
                yes=args.yes,
                ollama_url=args.ollama_url.rstrip("/"),
                chat_model=args.chat_model,
                embed_model=args.embed_model,
                chat_timeout=args.chat_timeout,
                embed_timeout=args.embed_timeout,
                skip_install=args.skip_install,
                skip_start=args.skip_start,
            )
        )

    parser.print_help()
    return 1


def setup_grounding(options: SetupOptions) -> int:
    print("ASCP Layer A grounding setup")
    print()
    print("This command prepares the optional Ollama-backed grounding backend.")
    print("It may install Ollama, start a local Ollama server, and pull local models.")
    print(f"Ollama endpoint: {options.ollama_url}")
    print(f"Claim extraction model: {options.chat_model}")
    print(f"Embedding model: {options.embed_model}")
    print()

    ollama_path = shutil.which("ollama")
    if ollama_path:
        print(f"Found Ollama CLI: {ollama_path}")
    elif options.skip_install:
        print("Ollama CLI was not found and --skip-install was provided.")
        print("Install Ollama manually, then rerun this command.")
        return 2
    elif _confirm("Install Ollama now?", default=True, assume_yes=options.yes):
        if not _install_ollama():
            print("Ollama installation did not complete.")
            print("Install Ollama manually from https://docs.ollama.com/windows and rerun this command.")
            return 2
        ollama_path = shutil.which("ollama")
        if not ollama_path:
            print("Ollama installed, but the CLI is not visible on PATH in this shell.")
            print("Open a new terminal and rerun: ascp setup-grounding")
            return 2
    else:
        print("Skipped Ollama installation.")
        return 2

    if _server_ready(options.ollama_url):
        print("Ollama server is reachable.")
    elif options.skip_start:
        print("Ollama server is not reachable and --skip-start was provided.")
        return 3
    elif _confirm("Start Ollama server in the background?", default=True, assume_yes=options.yes):
        _start_ollama_server()
        if not _wait_for_server(options.ollama_url, timeout_seconds=20):
            print("Ollama did not become reachable at the configured endpoint.")
            print("Start it manually with: ollama serve")
            return 3
        print("Ollama server is reachable.")
    else:
        print("Skipped starting Ollama.")
        return 3

    installed_models = _list_models(options.ollama_url)
    for model in (options.chat_model, options.embed_model):
        if _model_available(model, installed_models):
            print(f"Model already available: {model}")
            continue
        if _confirm(f"Pull model '{model}' now?", default=True, assume_yes=options.yes):
            if not _run(["ollama", "pull", model]):
                print(f"Failed to pull model: {model}")
                return 4
        else:
            print(f"Skipped model: {model}")

    print()
    print("Validating Ollama endpoints...")
    chat_ok = _validate_chat(options.ollama_url, options.chat_model, options.chat_timeout)
    embeddings_ok = _validate_embeddings(options.ollama_url, options.embed_model, options.embed_timeout)

    if not chat_ok or not embeddings_ok:
        print()
        print("Grounding setup is incomplete.")
        if not chat_ok:
            print("- Chat validation failed; claim extraction will fall back to regex.")
        if not embeddings_ok:
            print("- Embedding validation failed; semantic support scoring will be degraded.")
        return 5

    print()
    print("Layer A grounding backend is ready.")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ascp", description="ASCP SDK utilities.")
    subparsers = parser.add_subparsers(dest="command")

    setup = subparsers.add_parser(
        "setup-grounding",
        description="Install and validate the optional Ollama-backed Layer A grounding backend.",
    )
    setup.add_argument("-y", "--yes", action="store_true", help="Accept setup prompts.")
    setup.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL, help="Ollama endpoint.")
    setup.add_argument("--chat-model", default=DEFAULT_CHAT_MODEL, help="Claim extraction model.")
    setup.add_argument("--embed-model", default=DEFAULT_EMBED_MODEL, help="Embedding model.")
    setup.add_argument(
        "--chat-timeout",
        type=float,
        default=DEFAULT_CHAT_TIMEOUT,
        help="Seconds to wait for chat validation. First local model load can be slow.",
    )
    setup.add_argument(
        "--embed-timeout",
        type=float,
        default=DEFAULT_EMBED_TIMEOUT,
        help="Seconds to wait for embedding validation.",
    )
    setup.add_argument("--skip-install", action="store_true", help="Do not install Ollama.")
    setup.add_argument("--skip-start", action="store_true", help="Do not start Ollama.")
    return parser


def _confirm(prompt: str, *, default: bool, assume_yes: bool) -> bool:
    if assume_yes:
        print(f"{prompt} yes")
        return True

    suffix = "Y/n" if default else "y/N"
    while True:
        answer = input(f"{prompt} ({suffix}) ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please answer yes or no.")


def _install_ollama() -> bool:
    system = platform.system().lower()
    if system == "windows":
        if not shutil.which("winget"):
            print("winget was not found. Install Ollama from https://docs.ollama.com/windows")
            return False
        return _run(["winget", "install", "--id", "Ollama.Ollama", "--exact"])

    if system == "darwin":
        if shutil.which("brew"):
            return _run(["brew", "install", "ollama"])
        print("Homebrew was not found. Install Ollama from https://docs.ollama.com/")
        return False

    if system == "linux":
        print("Automatic Linux install is intentionally not run by ASCP.")
        print("Install Ollama from https://docs.ollama.com/linux, then rerun this command.")
        return False

    print(f"Unsupported platform for automatic install: {platform.system()}")
    return False


def _start_ollama_server() -> None:
    kwargs: dict[str, object] = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "stdin": subprocess.DEVNULL,
    }
    if platform.system().lower() == "windows":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(["ollama", "serve"], **kwargs)


def _server_ready(ollama_url: str) -> bool:
    try:
        response = httpx.get(f"{ollama_url}/api/tags", timeout=3.0)
        return response.status_code == 200
    except httpx.HTTPError:
        return False


def _wait_for_server(ollama_url: str, *, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _server_ready(ollama_url):
            return True
        time.sleep(0.5)
    return False


def _list_models(ollama_url: str) -> set[str]:
    try:
        response = httpx.get(f"{ollama_url}/api/tags", timeout=5.0)
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPError:
        return set()

    names: set[str] = set()
    for model in data.get("models", []):
        name = model.get("name")
        model_name = model.get("model")
        if isinstance(name, str):
            names.add(name)
        if isinstance(model_name, str):
            names.add(model_name)
    return names


def _model_available(model: str, installed_models: set[str]) -> bool:
    return model in installed_models or (
        ":" not in model and f"{model}:latest" in installed_models
    )


def _validate_chat(ollama_url: str, model: str, timeout: float = DEFAULT_CHAT_TIMEOUT) -> bool:
    payload = {
        "model": model,
        "stream": False,
        "keep_alive": "5m",
        "options": {"temperature": 0.0, "num_predict": 4},
        "messages": [{"role": "user", "content": "Reply with OK."}],
    }
    try:
        response = httpx.post(f"{ollama_url}/api/chat", json=payload, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        ok = bool(data.get("message", {}).get("content"))
    except httpx.HTTPError as exc:
        print(f"Chat endpoint failed: {exc}")
        return False
    print("Chat endpoint validated." if ok else "Chat endpoint returned an empty response.")
    return ok


def _validate_embeddings(
    ollama_url: str,
    model: str,
    timeout: float = DEFAULT_EMBED_TIMEOUT,
) -> bool:
    payload = {"model": model, "prompt": "ASCP grounding setup test."}
    try:
        response = httpx.post(f"{ollama_url}/api/embeddings", json=payload, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        embedding = data.get("embedding")
        ok = isinstance(embedding, list) and bool(embedding)
    except httpx.HTTPError as exc:
        print(f"Embedding endpoint failed: {exc}")
        return False
    print("Embedding endpoint validated." if ok else "Embedding endpoint returned no vector.")
    return ok


def _run(command: list[str]) -> bool:
    print(f"Running: {' '.join(command)}")
    try:
        completed = subprocess.run(command, check=False)
    except OSError as exc:
        print(f"Command failed to start: {exc}")
        return False
    return completed.returncode == 0


if __name__ == "__main__":
    raise SystemExit(main())
