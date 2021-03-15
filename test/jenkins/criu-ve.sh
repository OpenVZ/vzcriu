#!/bin/bash

# Make one regular C/R cycle
set -e
source `dirname $0`/criu-lib.sh
prep
FAIL=0
./test/zdtm.py run --all --flavor ve --keep-going --report report || FAIL=$?

if [ $FAIL -ne 0 ]; then
	fail
fi
