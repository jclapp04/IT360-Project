import json
import requests
import config

def ask_ollama(prompt, system=None):
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
            "options": {"temperature": 0},
        },
        stream=True,
        timeout=(10, 300),
    )
    if resp.status_code != 200:
        raise RuntimeError(F"Ollama returned {resp.status_code}: {resp.text[:200]}")

    reply = ""
    for line in resp.iter_lines():
        if not line:
            continue
        chunk = json.loads(line)
        reply += chunk.get("message", {}).get("content", "")
        if chunk.get("done"):
            break
    return reply
