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

echo "Testing frostd to print version string:"
./frostd help

echo "Now runnning exec $@ "
exec "$@"
