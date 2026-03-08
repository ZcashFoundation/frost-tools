#!/bin/sh

set -e

echo "Checking local docker image store to see if a frost-tools:latest image is present."
# Checks for empty string, discarding error messages.
if [ -z "$(docker images -q frost-tools:latest 2>/dev/null)" ]; then
  echo "There is no frost-tools:latest image listed by docker."
else
  echo "frost-client is a command-line tool that allows running the FROST protocol using the FROST server to help with communication. It uses a config file to store things like secret shares, group information and contacts, but be advised that it stores secrets unencrypted in the config file."
  echo "For an usage example, check https://frost.zfnd.org/zcash/ywallet-demo.html"
  echo "Running frost-client --help ..."
  docker run frost-tools:latest ./frost-client --help
fi
