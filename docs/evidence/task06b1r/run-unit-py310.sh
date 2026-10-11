#!/bin/bash
# Runs sandbox-worker unit tests with the image's Python 3.10, offline.
set -euo pipefail
python3 --version
pip install -q --no-index --find-links /wheels --target /tmp/pt pytest==8.3.4
cd /src
PYTHONPATH=/tmp/pt PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -v -p no:cacheprovider tests 2>&1 | tee /out/unit-tests-py310.txt
