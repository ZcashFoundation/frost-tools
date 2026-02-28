#!/bin/sh

# Entrypoint for running frost-tools in Docker.
#
# ## Notes
#
# frost-tools builds 7 binaries.
# currently this script will run `frostd` by default.

set -eo pipefail

# Main Script Logic
#
# 1. Print environment variables and config for debugging
# 2. Tests if frostd runs, printing help.
# 3. Execs the CMD or custom command provided.

echo "INFO: Using the following environment variables:"
printenv

echo "Testing --version for all binaries :"
echo "frostd:"
./frostd --version
echo "zcash-sign:"
./zcash-sign --version
echo "The following binaries all return frost-client versions:"
./frost-client --version
./coordinator --version
./participant --version
./trusted-dealer --version
./dkg --version


echo "Now runnning exec $@ "
exec "$@"
