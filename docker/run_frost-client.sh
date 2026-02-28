#!/bin/sh

set -e

echo "Checking local docker image store to see if a frost-tools:latest image is present."
# Checks for empty string, discarding error messages.
if [ -z "$(docker images -q frost-tools:latest 2>/dev/null)" ]; then
  echo "There is no frost-tools:latest image listed by docker."
else
  echo "Running frost-client ..."
  docker run frost-tools:latest ./frost-client --version
fi
