#!/bin/bash

echo "Linux x86_64 için derleniyor..."
cargo build --target x86_64-unknown-linux-gnu --target-dir  ./target

echo "Android x86_64 için derleniyor..."
cargo ndk build -t x86_64 --target-dir  --platform 24 ./target

echo "Android ARM64 için derleniyor..."
cargo ndk build -t arm64-v8a --target-dir --platform 24   ./target

echo "Linux'ta çalıştırılıyor..."
adb push ./target/aarch64-linux-android/debug/bedrock-nethernet /tmp
#./target/x86_64-unknown-linux-gnu/debug/bedrock-nethernet