#!/bin/sh
# Controlled command boundary. This script never displays or authenticates UI.
printf '%s\n' "$@" > "$0.arguments" || exit 2
if [ "$1" = --version ] && [ -f "$0.version" ]; then
    IFS= read -r result < "$0.version" || exit 2
else
    IFS= read -r result < "$0.result" || exit 2
fi
if [ "$1" = --text-info ]; then
    # /bin/cat is absolute because every test owns its complete private PATH.
    /bin/cat > "$0.review" || exit 2
fi
case "$result" in
  signal) kill -TERM "$$" ;;
  *) exit "$result" ;;
esac
