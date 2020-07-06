# Make one regular C/R cycle
set -e
source `dirname $0`/criu-lib.sh
prep
FAIL=0
./test/zdtm.py run --all -x ns_file_bindmount -x pidns_proc --keep-going --report report --parallel 4 || \
	FAIL=$?
./test/zdtm.py run --all --mounts-v2 --keep-going --report report --parallel 4 || FAIL=$?

if [ $FAIL -ne 0 ]; then
	fail
fi
