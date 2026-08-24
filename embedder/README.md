# Semantic sidecar

Runs in its own pinned venv (python3.13 -- onnxruntime has no reliable cp314 wheel, and
system python 3.14 is PEP-668 externally-managed, so an in-process import is impossible).

    python3.13 -m venv ~/.agents/capabilities/embedder/.venv
    ~/.agents/capabilities/embedder/.venv/bin/pip install -r requirements.txt
    cp embed.py ~/.agents/capabilities/embedder/

Build the index (re-run after every `cap rebuild`; `check` reports staleness):

    FP=$(python3 -c "import json,pathlib;print(json.load(open(pathlib.Path.home()/'.agents/capabilities/manifest.json'))['fingerprint'])")
    ~/.agents/capabilities/embedder/.venv/bin/python ~/.agents/capabilities/embedder/embed.py \
        build --registry ~/.agents/capabilities/registry.jsonl --out ~/.agents/capabilities --fingerprint "$FP"

The router degrades to lexical-only if this is missing, stale, crashed, or hanging.
