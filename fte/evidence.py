"""Hashes each input file before it is read."""

import hashlib


def sha256_file(path):
    """Returns the SHA-256 of a file as a hex string.

    Reads 1 MB at a time so big logs don't fill memory. The hash goes in the
    report to show the file analyzed is the same file that was collected.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()
