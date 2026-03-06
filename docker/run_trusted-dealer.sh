#!/bin/sh

set -e

echo "Checking local docker image store to see if a frost-tools:latest image is present."
# Checks for empty string, discarding error messages.
if [ -z "$(docker images -q frost-tools:latest 2>/dev/null)" ]; then
  echo "There is no frost-tools:latest image listed by docker."
else
  echo "Running trusted-dealer demo ... defaults to use ed25519-sha512-v1 and threshold 2 with 3 participants, non-interactively, writing json key package files in the working directory..."
  docker run frost-tools:latest ./trusted-dealer
fi
