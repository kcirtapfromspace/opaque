"""Strict local download transport used only by packaged acceptance's real installer."""
import json
import os
from pathlib import Path
import shutil
import sys

args = sys.argv[1:]
if len(args) != 4 or args[0] not in ("-fSL", "-fsSL") or args[1] != "-o":
    sys.exit(22)
requested = args[3]
expected = os.environ["OPAQUE_PACKAGED_URL"]
sources = {expected: "OPAQUE_PACKAGED_ARCHIVE", expected + ".sha256": "OPAQUE_PACKAGED_CHECKSUM"}
if requested not in sources:
    sys.exit(22)
with Path(os.environ["OPAQUE_PACKAGED_REQUESTS"]).open("a") as log:
    log.write(json.dumps(requested) + "\n")
shutil.copyfile(os.environ[sources[requested]], args[2])
