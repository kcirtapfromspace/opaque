#!/bin/sh
# Synthetic native-command boundary. The sidecar is authored by this test suite;
# it is not provider data or user input. Keep executable bytes immutable.
set -eu
. "${0}.body"
