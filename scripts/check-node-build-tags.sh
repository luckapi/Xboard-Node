#!/bin/sh
set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <binary> <required-tag> [required-tag...]" >&2
    exit 2
fi

binary="$1"
shift

if [ ! -f "$binary" ]; then
    echo "build tag check failed: binary not found: $binary" >&2
    exit 1
fi

metadata=$(go version -m "$binary" 2>/dev/null || true)
tags=$(printf '%s\n' "$metadata" | sed -n 's/^[[:space:]]*build[[:space:]]*-tags=//p' | head -n 1)

if [ -z "$tags" ]; then
    echo "build tag check failed: $binary has no recorded Go build tags" >&2
    echo "rebuild xboard-node with required tags, especially with_utls for sing-box Reality" >&2
    exit 1
fi

normalized_tags=$(printf '%s' "$tags" | tr ' ' ',')
missing=""

for required in "$@"; do
    case ",$normalized_tags," in
        *",$required,"*) ;;
        *) missing="${missing} ${required}" ;;
    esac
done

if [ -n "$missing" ]; then
    echo "build tag check failed: $binary is missing required tag(s):$missing" >&2
    echo "found tags: $tags" >&2
    exit 1
fi

echo "build tag check passed: $binary tags=$tags"
