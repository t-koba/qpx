#!/usr/bin/env python3
"""Protect request-driven CI triggers on the integration branch."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "ci.yml": '''  push:
    branches:
      - "**"
      - "!mizu"
    tags:
      - "v*"
  pull_request:
  workflow_dispatch:
  release:
    types: [published]
''',
    "structure.yml": '''  push:
    branches:
      - "**"
      - "!mizu"
    tags:
      - "**"
  pull_request:
  workflow_dispatch:
''',
    "security-qa.yml": '''  push:
    branches:
      - "**"
      - "!mizu"
    tags:
      - "**"
  pull_request:
  workflow_dispatch:
''',
}

for workflow, contract in EXPECTED.items():
    source = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
    if contract not in source:
        raise SystemExit(f"{workflow}: integration-branch CI trigger contract changed")
