# Make one regular C/R cycle
set -e
source `dirname $0`/criu-lib.sh
prep
./test/zdtm.py run --all -x packet_sock_mmap --keep-going --report report --parallel 4 || fail
