#!/usr/bin/env bash
# Setup script for Solana Signing Applet
# Run once after cloning: bash setup.sh
set -euo pipefail

JCED25519_DIR="lib/jced25519"

if [ -d "$JCED25519_DIR" ]; then
    echo "JCEd25519 already present at $JCED25519_DIR — skipping clone."
else
    echo "Cloning JCEd25519..."
    mkdir -p lib
    git clone https://github.com/dufkan/JCEd25519.git "$JCED25519_DIR"
    echo "JCEd25519 cloned to $JCED25519_DIR"
fi

echo ""
echo "Setup complete. You can now build with: ant"
