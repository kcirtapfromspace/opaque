#!/bin/sh
# Synthetic bws command boundary; never contacts a real provider account.
set -eu
case "${BWS_ACCESS_TOKEN-}" in
    test-bw-token:/*) fixture=${BWS_ACCESS_TOKEN#test-bw-token:} ;;
    *) exit 9 ;;
esac
: > "$fixture/bws-fixture.invoked"
[ "$1" = '--config-file' ] && [ -f "$2" ] || exit 10
[ "$3 $4 $5 $6 $7 $8" = '--profile opaque --output json --color no' ] || exit 11
case "$9 ${10}" in
    'project list') printf '%s' '[{"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","name":"backend-secrets"}]' ;;
    'secret get')
        [ "${11}" = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' ] || exit 12
        printf '%s' '{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","key":"TUTORIAL_KEY","value":"tutorial-value-plaintext","note":"private fixture note"}' ;;
    *) exit 13 ;;
esac
