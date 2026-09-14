#!/bin/sh
# Controlled helper protocol boundary; this fixture never authenticates a person.
case "$1" in
  --review-only)
    [ "$2" = --reason-stdin ] || exit 2
    cat > "$0.review" || exit 2
    exit 1
    ;;
  --check-ui)
    cat "$0.report" || exit 2
    exit 0
    ;;
  *) exit 2 ;;
esac
