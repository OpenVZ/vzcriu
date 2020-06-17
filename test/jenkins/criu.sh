#!/bin/bash

# Make one regular C/R cycle
set -e
source `dirname $0`/criu-lib.sh
prep
FAIL=0
./test/zdtm.py run --all --flavor h,ns,uns --keep-going --report report --parallel 4 || FAIL=$?
./test/zdtm.py run --all --flavor h,ns,uns --no-mntns-compat-mode --keep-going --report report --parallel 4 || FAIL=$?

if [ $FAIL -ne 0 ]; then
        fail
fi
