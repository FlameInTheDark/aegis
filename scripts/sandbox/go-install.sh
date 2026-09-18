#!/usr/bin/env bash
# Reinstall the Go toolchain after a sandbox reset (idempotent).
set -euo pipefail
if /home/z/go-sdk/go/bin/go version >/dev/null 2>&1; then
  echo "go already installed: $(/home/z/go-sdk/go/bin/go version)"
  exit 0
fi
if [ ! -f /tmp/go1.24.1.linux-amd64.tar.gz ]; then
  curl -sL -o /tmp/go1.24.1.linux-amd64.tar.gz https://go.dev/dl/go1.24.1.linux-amd64.tar.gz
fi
mkdir -p /home/z/go-sdk
tar -xzf /tmp/go1.24.1.linux-amd64.tar.gz -C /home/z/go-sdk
/home/z/go-sdk/go/bin/go version
