#!/bin/sh

set -e

echo "Checking local docker image store to see if a frost-tools:latest image is present."
# Checks for empty string, discarding error messages.
if [ -z "$(docker images -q frost-tools:latest 2>/dev/null)" ]; then
  echo "There is no frost-tools:latest image listed by docker."
else
  echo "This is both a command line tool and a library which allow creating a Zcash transaction from a YWallet transaction plan, by using externally-generated signatures. It was built to use along with FROST but it is not restricted to it."
  echo "Running zcash-sign --help ..."
  docker run frost-tools:latest ./zcash-sign --help
fi
