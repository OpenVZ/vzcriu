#!/bin/bash

set -ex

if [ "$CRTOOLS_SCRIPT_ACTION" == "pre-resume" ]; then
	cgset -r ve.pseudosuper="0" 99874 || { echo "Failed to drop pseudosuper on 99874"; exit 1; }
fi

exit 0
