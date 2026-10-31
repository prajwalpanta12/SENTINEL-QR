set -x
export XDG_CACHE_HOME=/tmp/clean/cache   # isolated: no access to the cached live PSL
REL=/tmp/clean/SENTINEL-QR/research/realworld; PY=/tmp/clean/venv/bin/python; O=/tmp/clean/out; mkdir -p $O/res
cd $REL
$PY build_dataset.py /tmp/repro2/raw $O/r1 > $O/build.log 2>&1; echo BUILD $? >> $O/status.txt
$PY validate_reproducibility.py $O/r1 > $O/validate_splits.log 2>&1; echo VALIDATE $? >> $O/status.txt
$PY run_experiments.py $O/r1 $O/res/r1_results.json > $O/exp.log 2>&1; echo EXP $? >> $O/status.txt
$PY subset_checks.py $O/r1/test.csv $O/res/r1_results_scores.npz $O/res/subset_checks.json > $O/sub.log 2>&1; echo SUB $? >> $O/status.txt
$PY cluster_bootstrap.py $O/r1/test.csv $O/res/r1_results_scores.npz $O/res/r1_results.json $O/res/cluster_bootstrap.json > $O/cb.log 2>&1; echo CB $? >> $O/status.txt
$PY crux_rank_check.py $O/r1/test.csv $O/res/r1_results_scores.npz $O/res/r1_results.json $O/res/crux_rank_check.json > $O/crux.log 2>&1; echo CRUX $? >> $O/status.txt
$PY url_type_breakdown.py $O/r1/test.csv $O/res/r1_results_scores.npz $O/res/r1_results.json $O/res/url_type_breakdown.json > $O/ut.log 2>&1; echo UT $? >> $O/status.txt
$PY rule_trigger_rates.py $O/r1/test.csv $O/res/rule_trigger_rates.json > $O/rt.log 2>&1; echo RT $? >> $O/status.txt
cd /tmp/clean/SENTINEL-QR && $PY test_system.py > $O/tests.log 2>&1; echo TESTS $? >> $O/status.txt
$PY test_fixes.py > $O/fixes.log 2>&1; echo FIXES $? >> $O/status.txt
$PY research/audit_experiments.py > $O/synth.log 2>&1; echo SYNTH $? >> $O/status.txt
echo DONE >> $O/status.txt
