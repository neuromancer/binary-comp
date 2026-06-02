#!/usr/bin/env sh
set -eu

EXAMPLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=${REPO_ROOT:-$(CDPATH= cd -- "$EXAMPLE_DIR/../../.." && pwd)}
MSVC42_DIR=${MSVC42_DIR:-"$EXAMPLE_DIR/.tools/MSVC420"}
WIBO=${WIBO:-"$EXAMPLE_DIR/.tools/wibo/wibo"}

if [ ! -x "$WIBO" ]; then
    echo "wibo not found or not executable: $WIBO" >&2
    exit 1
fi

if [ ! -f "$MSVC42_DIR/bin/CL.EXE" ]; then
    echo "MSVC 4.x compiler not found: $MSVC42_DIR/bin/CL.EXE" >&2
    exit 1
fi

compile_one() {
    name=$1
    source=$2
    out_dir="artifacts/$name"

    mkdir -p "$EXAMPLE_DIR/$out_dir"
    INCLUDE="$MSVC42_DIR/include;$MSVC42_DIR/mfc/include" \
    LIB="$MSVC42_DIR/lib;$MSVC42_DIR/mfc/lib" \
    PATH="$MSVC42_DIR/bin:$PATH" \
        "$WIBO" -C "$EXAMPLE_DIR" "$MSVC42_DIR/bin/CL.EXE" \
        /nologo /GX /Od /MT "$source" \
        /Fo"$out_dir/$name.obj" \
        /Fa"$out_dir/$name.asm" \
        /Fe"$out_dir/$name.exe" \
        /link /MAP:"$out_dir/$name.map"
}

rm -rf "$EXAMPLE_DIR/artifacts" "$EXAMPLE_DIR/code"

compile_one original src/original/original.cpp
compile_one rebuilt src/rebuilt/rebuilt.cpp
