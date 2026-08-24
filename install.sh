#!/bin/sh
# Install `lockkeeper` by symlinking the launcher into ~/.local/bin (or a prefix of
# your choice via PREFIX=...).
set -eu

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${PREFIX:-}" ] && [ -z "${HOME:-}" ]; then
    echo "error: HOME is not set; pass PREFIX=/some/bin-dir explicitly" >&2
    exit 1
fi
PREFIX="${PREFIX:-$HOME/.local/bin}"
mkdir -p "$PREFIX"
for name in cap capability-registry; do
    if [ -d "$PREFIX/$name" ]; then
        echo "error: $PREFIX/$name exists and is a directory; remove it first" >&2
        exit 1
    fi
done

ln -sfn "$REPO_ROOT/scripts/capability-registry" "$PREFIX/lockkeeper"
ln -sfn "$REPO_ROOT/scripts/capability-registry" "$PREFIX/cap"  # deprecated alias
ln -sfn "$REPO_ROOT/scripts/capability-registry" "$PREFIX/capability-registry"

# Auto-bind: detect every harness on this machine and write local bindings.
# Selective: ./install.sh --runtimes claude,codex   Skip: CAP_NO_INIT=1.
if [ "${CAP_NO_INIT:-}" != "1" ]; then
    echo
    echo "Detecting installed agent harnesses..."
    if [ -n "${CAP_RUNTIMES:-}" ]; then
        "$PREFIX/cap" init --runtimes "$CAP_RUNTIMES" || true
    else
        "$PREFIX/cap" init || true
    fi
fi

echo "Installed:"
echo "  $PREFIX/cap"
echo "  $PREFIX/capability-registry (alias)"
echo
echo "Next steps:"
echo "  lockkeeper snapshot-runtimes && lockkeeper rebuild && lockkeeper doctor"
