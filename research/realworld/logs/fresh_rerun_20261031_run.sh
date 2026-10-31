set -x
REL=/home/claude/github_release/SENTINEL-QR/research/realworld
PY=/home/claude/venv_proj/bin/python
cd /tmp/repro2 && rm -rf raw && bash $REL/fetch_sources.sh > fetch.log 2>&1; echo FETCH $? >> status.txt
cd $REL && $PY build_dataset.py /tmp/repro2/raw /tmp/repro2/r1 > /tmp/repro2/build.log 2>&1; echo BUILD $? >> /tmp/repro2/status.txt
sha256sum /tmp/repro2/r1/{train,val,test}.csv > /tmp/repro2/hashes.txt
for s in train val test; do cmp -s /tmp/repro2/r1/${s}_hashes.csv $REL/data_manifest/${s}_hashes.csv && echo "HASHCSV $s same" || echo "HASHCSV $s DIFF"; done >> /tmp/repro2/status.txt
mkdir -p /tmp/repro2/res
$PY run_experiments.py /tmp/repro2/r1 /tmp/repro2/res/r1_results.json > /tmp/repro2/exp.log 2>&1; echo EXP $? >> /tmp/repro2/status.txt
$PY subset_checks.py /tmp/repro2/r1/test.csv /tmp/repro2/res/r1_results_scores.npz /tmp/repro2/res/subset_checks.json > /tmp/repro2/sub.log 2>&1; echo SUB $? >> /tmp/repro2/status.txt
$PY crux_rank_check.py /tmp/repro2/r1/test.csv /tmp/repro2/res/r1_results_scores.npz /tmp/repro2/res/r1_results.json /tmp/repro2/res/crux_rank_check.json > /tmp/repro2/crux.log 2>&1; echo CRUX $? >> /tmp/repro2/status.txt
$PY url_type_breakdown.py /tmp/repro2/r1/test.csv /tmp/repro2/res/r1_results_scores.npz /tmp/repro2/res/r1_results.json /tmp/repro2/res/url_type_breakdown.json > /tmp/repro2/ut.log 2>&1; echo UT $? >> /tmp/repro2/status.txt
(cd $REL && $PY rule_trigger_rates.py /tmp/repro2/r1/test.csv /tmp/repro2/res/rule_trigger_rates.json > /tmp/repro2/rt.log 2>&1); echo RT $? >> /tmp/repro2/status.txt
$PY leakage_audit.py /tmp/repro2/r1 /tmp/repro2/res/leakage_audit.json > /tmp/repro2/la.log 2>&1; echo LA $? >> /tmp/repro2/status.txt
$PY cluster_bootstrap.py /tmp/repro2/r1/test.csv /tmp/repro2/res/r1_results_scores.npz /tmp/repro2/res/r1_results.json /tmp/repro2/res/cluster_bootstrap.json > /tmp/repro2/cb.log 2>&1; echo CB $? >> /tmp/repro2/status.txt
echo DONE >> /tmp/repro2/status.txt
