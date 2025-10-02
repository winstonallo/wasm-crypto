#!/usr/bin/env bash

BASE_OUTPUT_DIRECTORY="./pkg"

TARGETS=("web" "nodejs")

for TARGET in "${TARGETS[@]}"; do
    echo "Building for target: $TARGET"

    OUTPUT_DIRECTORY="$BASE_OUTPUT_DIRECTORY/$TARGET"

    RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --release --target $TARGET --out-dir $OUTPUT_DIRECTORY

    rm -f $OUTPUT_DIRECTORY/.gitignore

    echo "Built for $TARGET at $OUTPUT_DIRECTORY"
done

echo "All builds completed"
