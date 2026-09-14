#!/bin/sh
# Synthetic 1Password command boundary; never accesses an actual vault.
# Execute via a private symlink so $0 selects that test's exact output bytes.
[ "$#" -eq 3 ] && [ "$1" = read ] && [ "$2" = op://vault/item/field ] && [ "$3" = --no-newline ] || exit 2
exec /bin/cat "$0.value"
