#!/bin/sh
# Synthetic bws command boundary. The disposable token selects private test
# data because the production client canonicalizes this immutable executable.
set -eu
case "${BWS_ACCESS_TOKEN-}" in
    disposable-fixture-token:/*) fixture=${BWS_ACCESS_TOKEN#disposable-fixture-token:} ;;
    *) exit 9 ;;
esac
printf '%s\n' "$@" >> "$fixture/args"
/bin/cat "$2" > "$fixture/config"
[ -z "${BWS_SERVER_URL-}" ] || exit 10
[ -z "${BWS_CONFIG_FILE-}" ] || exit 11
[ -z "${OPAQUE_BWS_PARENT_ONLY-}" ] || exit 12
# This sidecar contains authored test behavior, never provider/user input.
. "$fixture/behavior"
case "$9 ${10}" in
    'project list') /bin/cat "$fixture/projects.json" ;;
    'secret list') /bin/cat "$fixture/secrets.json" ;;
    'secret get') /bin/cat "$fixture/secret.json" ;;
    *) exit 13 ;;
esac
