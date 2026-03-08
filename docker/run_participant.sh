#!/bin/sh

set -e

echo "Checking local docker image store to see if a frost-tools:latest image is present."
# Checks for empty string, discarding error messages.
if [ -z "$(docker images -q frost-tools:latest 2>/dev/null)" ]; then
  echo "There is no frost-tools:latest image listed by docker."
else
  echo "Participants interact with the coordinator."
  echo "Running paticipant --help :"
  docker run frost-tools:latest ./participant --help
  echo "The demonstration defined in this Makefile uses three participants, which should each be launched in their own terminals."
  echo "Participants must have key packages, which can be provided as files (with the option -k ) or copy-pasted."
  echo "For this demo, as each participant will be in its own container and in its own terminal,, we will use copy-pasting."
  echo "Now, running participant..."
  docker run -it frost-tools:latest ./participant --cli
fi
