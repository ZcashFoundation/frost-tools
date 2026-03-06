#!/bin/sh

set -e

echo "Checking local docker image store to see if a frost-tools:latest image is present."
# Checks for empty string, discarding error messages.
if [ -z "$(docker images -q frost-tools:latest 2>/dev/null)" ]; then
  echo "There is no frost-tools:latest image listed by docker."
else
  echo "Running coordinator as interactive cli..."
  echo "When prompted for the message to be signed (hex encoded), this corresponds to the 'signing_share' from the key package output by the trusted dealer."
  echo "When prompted for 'JSON encoded commitments for participant' this is the 'SigningCommitments' produced with the participant command."
  docker run -it frost-tools:latest ./coordinator --cli
fi
