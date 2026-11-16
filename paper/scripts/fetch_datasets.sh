#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p paper/data

if [ -f paper/data/rjudge-violations.jsonl ]; then
  echo "  already present: paper/data/rjudge-violations.jsonl"
  exit 0
fi

echo "  R-Judge is not redistributed with this artifact."
echo "  Obtain it from the authors' release, place the trajectory"
echo "  file at paper/data/rjudge-violations.jsonl, then run:"
echo "      python paper/scripts/analysis/taxonomy_robustness.py"
echo
echo "  Every other number in the paper regenerates without it:"
echo "      python paper/scripts/verify_all.py"
