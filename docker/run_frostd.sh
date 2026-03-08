#!/bin/sh

set -e

echo "Checking local docker image store to see if a frost-tools:latest image is present."
# Checks for empty string, discarding error messages.
if [ -z "$(docker images -q frost-tools:latest 2>/dev/null)" ]; then
  echo "There is no frost-tools:latest image listed by docker."
else
  echo "frostd is a JSON-HTTPS server that allow FROST clients (Coordinator and Participants) to run FROST without needing to directly connect to one another."
  echo "documentation is available at https://frost.zfnd.org/zcash/server.html"
  echo "Running frostd --help ..."
  docker run frost-tools:latest ./frostd --help
fi
