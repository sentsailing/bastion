#!/bin/bash
set -euo pipefail

BASTION_DIR="/usr/lib/bastion"
DATA_DIR="/var/lib/bastion"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RELEASE_DIR="$PROJECT_DIR/target/release"

# Configurable parameters
PUZZLE_COUNT="${PUZZLE_COUNT:-100}"
T_BITS="${T_BITS:-24}"  # ~1 minute on modern CPU

echo "=== Bastion Installer ==="
echo ""
echo "Parameters:"
echo "  Puzzles:    $PUZZLE_COUNT"
echo "  Difficulty: T=2^$T_BITS ($(python3 -c "print(f'~{2**$T_BITS/30_000_000:.0f}s')" 2>/dev/null || echo "unknown") solve time)"
echo ""

# Check we're root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)."
    exit 1
fi

# Check binaries exist
for bin in bastion bastion-timelock bastion-cerberus bastion-chronos; do
    if [ ! -f "$RELEASE_DIR/$bin" ]; then
        echo "ERROR: $RELEASE_DIR/$bin not found. Run 'cargo build --release' first."
        exit 1
    fi
done

echo "[1/7] Creating directories..."
mkdir -p "$BASTION_DIR"
mkdir -p "$DATA_DIR/puzzles"

echo "[2/7] Installing binaries..."
cp "$RELEASE_DIR/bastion" "$BASTION_DIR/"
cp "$RELEASE_DIR/bastion-timelock" "$BASTION_DIR/"
cp "$RELEASE_DIR/bastion-cerberus" "$BASTION_DIR/"
cp "$RELEASE_DIR/bastion-chronos" "$BASTION_DIR/"
chmod 755 "$BASTION_DIR"/*

# Also install bastion CLI to /usr/local/bin for convenience
ln -sf "$BASTION_DIR/bastion" /usr/local/bin/bastion

echo "[3/7] Initializing (generating keys, puzzles)..."
"$BASTION_DIR/bastion" init --puzzle-count "$PUZZLE_COUNT" --t-bits "$T_BITS"

echo "[4/7] Installing systemd services..."
cp "$SCRIPT_DIR/bastion-alpha.service" /etc/systemd/system/
cp "$SCRIPT_DIR/bastion-beta.service" /etc/systemd/system/
cp "$SCRIPT_DIR/bastion-gamma.service" /etc/systemd/system/
cp "$SCRIPT_DIR/bastion-chronos.service" /etc/systemd/system/
systemctl daemon-reload

echo "[5/7] Enabling services..."
systemctl enable bastion-alpha bastion-beta bastion-gamma bastion-chronos
systemctl start bastion-alpha bastion-beta bastion-gamma bastion-chronos

echo "[6/7] Verifying services..."
sleep 2
bastion status

echo "[7/7] Applying hardening..."
bash "$SCRIPT_DIR/harden.sh"

echo ""
echo "=== Bastion Installation Complete ==="
echo ""
echo "Usage:"
echo "  bastion status                          # Check system status"
echo "  bastion unlock --rule 'allow site.com'  # Solve puzzle to allow a site"
echo "  bastion block --domain 'site.com'       # Block a site (no puzzle needed)"
echo ""
echo "To uninstall, you must solve a puzzle first (by design)."
