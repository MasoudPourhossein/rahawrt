#!/bin/sh
set -eu
export PYTHONPATH=/usr/lib/rahawrt
case "${1:-}" in
admin)
    [ "$#" = 2 ] || { echo 'Usage: router.sh admin NAME' >&2; exit 1; }
    python3 -m rahawrt.server --create-admin "$2"
    ;;
backup)
    [ "$#" = 2 ] || { echo 'Usage: router.sh backup NEW_ARCHIVE.zip' >&2; exit 1; }
    python3 -m rahawrt.backup backup "$2"
    ;;
restore)
    [ "$#" = 2 ] || { echo 'Usage: router.sh restore ARCHIVE.zip (stop service first)' >&2; exit 1; }
    python3 -m rahawrt.backup restore "$2"
    ;;
rollback)
    # Remove only RahaWRT-owned rules; existing PassWall2 nodes are retained.
    for config in firewall passwall2 rahawrt; do
        [ -z "$(uci changes "$config")" ] || { echo 'Save or revert pending UCI edits before policy rollback.' >&2; exit 1; }
    done
    /etc/init.d/rahawrt stop
    python3 -m rahawrt.boot_guard uninstall
    uci set rahawrt.main.enforce=0
    uci commit rahawrt
    if nft list table inet rahawrt >/dev/null 2>&1; then nft delete table inet rahawrt; fi
    if nft list table inet rahawrt_transition >/dev/null 2>&1; then nft delete table inet rahawrt_transition; fi
    uci -q show passwall2 | sed -n 's/^\(passwall2\.rw_[A-Za-z0-9_]*\)=acl_rule$/\1/p' | while IFS= read -r section; do
        [ "$(uci -q get "$section.rahawrt_owner")" = 1 ] || { echo "Refusing unowned section: $section" >&2; exit 1; }
        uci delete "$section"
    done
    uci commit passwall2
    /etc/init.d/passwall2 restart
    echo 'Managed restrictions removed. This restores ordinary PassWall2 behavior, including direct access where configured.'
    ;;
*) echo 'Usage: router.sh admin NAME | backup NEW_ARCHIVE.zip | restore ARCHIVE.zip | rollback' >&2; exit 1;;
esac
