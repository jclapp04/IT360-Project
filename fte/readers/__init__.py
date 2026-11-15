import json

from fte.readers.cloudtrail import read_cloudtrail
from fte.readers.gworkspace import read_gworkspace
from fte.readers.o365 import read_o365

def read_file(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)


    if isinstance(data, dict) and "Records" in data:
        return read_cloudtrail(path)
    if isinstance( data, dict) and "items" in data:
        return read_gworkspace(path)
    if isinstance(data, list):
        return read_o365(path)

    raise ValueError(f"unrecognized log format: {path}")
