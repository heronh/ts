#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"

echo
echo "Núcleo compilado. Exemplos:"
echo "  source .venv/bin/activate"
echo "  tslab                 # interface gráfica"
echo "  tslab scan arquivo.ts"
echo "  tslab remap in.ts out.ts --map 0x100=0x200"
