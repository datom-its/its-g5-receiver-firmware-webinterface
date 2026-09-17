#!/usr/bin/env python3
"""Pre-compress a web asset so the firmware can serve it as Content-Encoding: gzip.
Called from CMake at build time; mtime=0 keeps the output byte-identical."""
import gzip
import sys

with open(sys.argv[1], "rb") as src:
    data = src.read()
with open(sys.argv[2], "wb") as dst:
    dst.write(gzip.compress(data, compresslevel=9, mtime=0))
