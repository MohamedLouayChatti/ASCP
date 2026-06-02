# ASCP External User Demo

This branch is an isolated user-side demo of the ASCP SDK. It exists to show how a real application would consume ASCP as an installed dependency, without using the ASCP repo itself as the application runtime.

## Purpose

- Demonstrate ASCP protecting a LangChain-based agent from the outside.
- Exercise Layer A grounding checks, Layer B tool validation, and Layer C DLP handling from an external project.
- Keep the demo separate from the main ASCP codebase so the integration path is realistic.

## What the demo runs

The entry point is `external_user_demo.py`. It builds:

- a small LangChain retriever
- a deterministic chat model for repeatable output
- a `file_read` tool
- an `ASCPLangChainAdapter` connected to `ASCPOrchestrator`

The script runs two turns:

1. a normal RAG + tool invocation
2. a second turn that attempts to leak debug context

Telemetry is written to `logs/external_user_ascp_demo.jsonl`.

## Install and run

From this demo folder, install ASCP from the sibling repo with the LangChain extra.
Replace the example path with the local path to your own ASCP checkout:

```bash
pip install -e "C:/path/to/ASCP[ascp-langchain]"
```

After installing, set up grounding so the local Ollama server is running and the grounding models are available:

```bash
ascp setup-grounding
```

Then, if you want the live local dashboard that tracks logs and events, launch it on localhost port 8765:

```bash
ascp local-dashboard
```

Finally run the demo:

```bash
python external_user_demo.py
```

## Notes

- This branch is for integration testing and documentation of the external-user experience.
- The ASCP repo is the actual SDK implementation; this branch only shows how a consumer application would use it.
