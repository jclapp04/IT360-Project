"""Talks to the Ollama server through its API."""

import json

import requests


def ask_ollama(prompt, system=None):
    """Sends one prompt to the model and returns the full reply.

    Host, key and model come from config.py, which is not in git. It loads
    here and not at the top so everything else still runs without it.
    Only --ai needs it.
    """
    try:
        import config
    except ImportError:
        raise RuntimeError("config.py not found. Copy config_example.py to config.py and fill it in.")

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    resp = requests.post(
        f"{config.OLLAMA_HOST}/ollama/api/chat",
        headers={"Authorization": f"Bearer {config.OLLAMA_API_KEY}"},
        json={
            "model": config.OLLAMA_MODEL,
            "messages": messages,
            "stream": True,
            # temperature 0 so the same timeline gives nearly the same answer
            "options": {"temperature": 0},
        },
        stream=True,
        timeout=(10, 300),   # 10 sec to connect, 5 min to wait for a reply
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Ollama returned {resp.status_code}: {resp.text[:200]}")

    # the reply comes as one JSON object per line, so join the pieces
    reply = ""
    for line in resp.iter_lines():
        if not line:
            continue
        chunk = json.loads(line)
        reply += chunk.get("message", {}).get("content", "")
        if chunk.get("done"):
            break
    return reply
