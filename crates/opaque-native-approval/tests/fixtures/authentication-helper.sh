#!/bin/sh
# Synthetic subprocess protocol only; this fixture never invokes polkit or claims human presence.
[ "$#" -eq 2 ] && [ "$1" = --reason ] || exit 2
printf '%s' "$2" > "$0.reason" || exit 2
printf '%s\n' $$ > "$0.pid" || exit 2
case "${0##*/}" in
    authentication-approved)
        printf '%s\n' '{"account":{"uid":1234,"username":"fixture-account"}}'
        exit 0
        ;;
    authentication-anonymous)
        printf '%s\n' 'malformed account output'
        exit 0
        ;;
    authentication-denied)
        printf '%s\n' '{"account":{"uid":1234,"username":"fixture-account"}}'
        exit 1
        ;;
    authentication-unavailable) exit 2 ;;
    authentication-signal) kill -TERM $$ ;;
    authentication-timeout) exec /bin/sleep 30 ;;
    *) exit 2 ;;
esac
