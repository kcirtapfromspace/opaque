#!/bin/sh
# Synthetic review protocol fixture. It never authenticates a native factor.
# Execute via a private per-test symlink; $0 locates that test's output files.
[ "$#" -eq 2 ] && [ "$1" = --review-only ] && [ "$2" = --reason-stdin ] || exit 2

case "${0##*/}" in
    review-helper-timeout)
        IFS= read -r review
        printf '%s' "$review" > "$0.review" || exit 2
        printf '%s\n' $$ > "$0.pid"
        printf '%s\n' 'opaque-review-stage: window-ordered'
        exec /bin/sleep 30
        ;;
    review-helper-unread)
        exec /bin/sleep 5
        ;;
    review-helper-approve)
        cat > "$0.review" || exit 2
        exit 0
        ;;
    review-helper-deny)
        cat > "$0.review" || exit 2
        printf '%s\n' 'opaque-review-stage: review-confirmed'
        exit 1
        ;;
    review-helper-unavailable)
        cat > "$0.review" || exit 2
        exit 2
        ;;
    *)
        exit 2
        ;;
esac
