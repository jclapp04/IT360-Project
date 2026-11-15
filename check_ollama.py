"""Tests that the server, key and model in config.py work."""

from fte.ollama_client import ask_ollama

print(ask_ollama("Reply with the single word: ready"))
