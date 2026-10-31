#!/usr/bin/env bash
# Fetch the three public sources used by the R1 benchmark at the exact commits
# used in the paper. Run from any directory; creates ./raw and source_commits.txt.
# The raw data are NOT redistributed with SENTINEL-QR: JPCERT/CC and Ebbu2017
# publish no explicit licence, and the phishing URLs are live attack URLs.
# Do not open or render any URL from these files.
set -euo pipefail
mkdir -p raw && cd raw

fetch () {  # repo  commit  paths...
  local repo=$1 commit=$2; shift 2
  local dir; dir=$(basename "$repo")
  git clone --filter=blob:none --no-checkout "https://github.com/$repo.git" "$dir"
  ( cd "$dir" && git checkout -q "$commit" -- "$@" )
}

# JPCERT/CC phishing URL list (confirmed phishing, with confirmation dates)
fetch JPCERTCC/phishurl-list e19b194b2d23f6c6ab532cf880c99b306992473e 2019 2020 2021 2022 2023 2024 2025 2026 README.md
# Chrome UX Report top-million origins (CC BY 4.0, via zakird/crux-top-lists)
fetch zakird/crux-top-lists 35ba243941defcd21882b134d9dd354824922482 \
      data/global/202301.csv.gz data/global/202401.csv.gz data/global/202609.csv.gz README.md
# Ebbu2017 legitimate URLs (Sahingoz et al., Expert Syst. Appl., 2019)
fetch ebubekirbbr/pdd 90b394d8f9fb5d5dc48400e8bf46b001ce42999f input/data_legitimate_36400.json

cd ..
cat > source_commits.txt <<EOF
phishurl-list e19b194b2d23f6c6ab532cf880c99b306992473e 2026-10-16T04:10:34+00:00
crux-top-lists 35ba243941defcd21882b134d9dd354824922482 2026-10-13T10:05:18+00:00
pdd 90b394d8f9fb5d5dc48400e8bf46b001ce42999f 2019-05-30T13:15:49+03:00
EOF
echo "Sources fetched. Next: python build_dataset.py raw r1"
