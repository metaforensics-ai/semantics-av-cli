#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PREFIX="${INSTALL_PREFIX:-$HOME/.local}"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  SemanticsAV User Setup"
echo "═══════════════════════════════════════════════════════════"
echo ""

echo "[1/4] Creating user directories..."
mkdir -p "$HOME/.config/semantics-av"
mkdir -p "$HOME/.local/share/semantics-av"
mkdir -p "$HOME/.local/share/semantics-av/models"
mkdir -p "$HOME/.local/state/semantics-av"
mkdir -p "$HOME/.cache/semantics-av"
echo "      ✓ Directories created"

echo ""
echo "[2/4] Setting permissions..."
chmod 700 "$HOME/.config/semantics-av"
chmod 755 "$HOME/.local/share/semantics-av"
echo "      ✓ Permissions set"

echo ""
echo "[3/4] Checking PATH..."
if [[ ":$PATH:" == *":$INSTALL_PREFIX/bin:"* ]]; then
    echo "      ✓ $INSTALL_PREFIX/bin is in PATH"
else
    echo "      ⚠ $INSTALL_PREFIX/bin is NOT in PATH"
    echo ""
    echo "      Add this to your shell profile (~/.bashrc or ~/.zshrc):"
    echo "      export PATH=\"$INSTALL_PREFIX/bin:\$PATH\""
fi

echo ""
echo "[4/4] Reloading user systemd..."
if command -v systemctl &>/dev/null; then
    systemctl --user daemon-reload
    echo "      ✓ User systemd reloaded"
else
    echo "      ⚠ systemctl not found, skipping"
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Setup Complete!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. Configure: semantics-av config init"
echo "  2. Enable service: systemctl --user enable semantics-av"
echo "  3. Start service: systemctl --user start semantics-av"
echo "  4. Check status: systemctl --user status semantics-av"
echo ""