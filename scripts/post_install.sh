#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  SemanticsAV System Setup"
echo "═══════════════════════════════════════════════════════════"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    echo "Please run: sudo $0"
    exit 1
fi

echo "[1/3] Creating system user 'semantics-av-daemon'..."
if ! id "semantics-av-daemon" &>/dev/null; then
    useradd --system --shell /bin/false --home /nonexistent semantics-av-daemon
    echo "      ✓ User created"
else
    echo "      ✓ User already exists"
fi

echo ""
echo "[2/3] Reloading systemd..."
if command -v systemctl &>/dev/null; then
    systemctl daemon-reload
    echo "      ✓ Systemd reloaded"
    
    systemctl enable semantics-av.service
    echo "      ✓ Service enabled"
else
    echo "      ⚠ systemctl not found, skipping"
fi

echo ""
echo "[3/3] Verifying installation..."
if id "semantics-av-daemon" &>/dev/null; then
    echo "      ✓ User verified: semantics-av-daemon"
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Setup Complete!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. Configure (requires sudo):"
echo "     sudo semantics-av config init"
echo ""
echo "  2. Start daemon:"
echo "     sudo systemctl start semantics-av"
echo ""
echo "  3. Use CLI tools (no sudo needed when daemon is running):"
echo "     semantics-av scan /path/to/file"
echo "     semantics-av analyze /path/to/file"
echo "     semantics-av update"
echo ""
echo "  Check daemon status:"
echo "     systemctl status semantics-av"
echo ""
echo "Note: systemd manages directories automatically."
echo "      Config changes require sudo (system-wide settings)."
echo ""