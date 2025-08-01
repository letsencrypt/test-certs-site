#!/usr/bin/env bash
#
# Usage: ./checklist.complete.sh
#
# This script will replace all instances of `gorepotemplate` in README.md with
# the new project name.
#
# It will also *delete*:
#   * CHECKLIST.md  - you finished it already, right!?
#   * hello.go      - this is example cruft
#   * hello_test.go - also example cruft
#
# Afterwards *you* will need to delete the `checklist.complete.sh` script.
#
set -e

# The NEW_PROJECT_NAME is assumed to be the name of the directory that
# `checklist.complete.sh` is being run from.
NEW_PROJECT_NAME="${PWD##*/}"

# If there is no CHECKLIST.md in the directory, fail
if [ ! -f CHECKLIST.md ]; then
  echo "CHECKLIST.md not found - have you already run this script?"
  exit 1
fi
rm CHECKLIST.md

# Replace the gorepotemplate name in the README
sed -i "s/gorepotemplate/$NEW_PROJECT_NAME/g" README.md

# Allow the removal of the Go files to fail. It doesn't really matter if they're
# already gone.
rm hello.go      2>/dev/null || true
rm hello_test.go 2>/dev/null || true

echo "All finished!"
echo "Please complete the new repo by removing this script:"
echo "  rm $0"
