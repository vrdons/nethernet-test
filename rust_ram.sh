#!/bin/bash

# RAM diskin boyutu (2G genelde yeterli)
SIZE="2G"
RAM_DIR="/tmp/cargo-target"

# RAM disk oluştur (zaten varsa atla)
if ! mountpoint -q "$RAM_DIR"; then
    echo "[*] RAM diski oluşturuluyor: $RAM_DIR ($SIZE)"
    mkdir -p "$RAM_DIR"
    sudo mount -t tmpfs -o size=$SIZE tmpfs "$RAM_DIR"
else
    echo "[*] RAM diski zaten bağlı."
fi

# Ortam değişkeni ayarla ve VSCode'u başlat
echo "[*] VSCode Rust RAM modda başlatılıyor..."
echo "$@"
CARGO_TARGET_DIR="$RAM_DIR" code "$@"
