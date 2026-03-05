#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Bastion Hardening ==="
echo ""

# Check we're root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)."
    exit 1
fi

# --- Layer 0: Protect ld.so.preload (keep current contents) ---
echo "[1/12] Locking ld.so.preload..."
if [ -f /etc/ld.so.preload ]; then
    chattr -i /etc/ld.so.preload 2>/dev/null || true
    chattr +i /etc/ld.so.preload
    echo "  ld.so.preload locked (contents unchanged)."
else
    echo "  SKIP /etc/ld.so.preload (not found)"
fi

# --- Layer 1: Set immutable flags ---
echo "[2/12] Setting immutable flags (chattr +i)..."

BASTION_FILES=(
    /usr/lib/bastion/bastion-cerberus
    /usr/lib/bastion/bastion-chronos
    /usr/lib/bastion/bastion-timelock
    /usr/lib/bastion/bastion
    /usr/lib/bastion/uninstall
)

PLUCKY_FILES=(
    /usr/lib/x86_64-linux-gnu/pluckeye.so
    /usr/lib32/pluckeye.so
    /opt/pluck/v/1.17.35/bin/boss
    /opt/pluck/v/1.17.35/bin/tock
    /opt/pluck/v/1.17.35/bin/pluck
    /opt/pluck/v/1.17.35/bin/pump
    /opt/pluck/v/1.17.35/bin/spawn
    /opt/pluck/v/1.17.35/bin/hatch
    /opt/pluck/v/1.17.35/bin/verify
    /opt/pluck/v/1.17.35/bin/true
    /opt/pluck/v/1.17.35/bin/pludo
    /opt/pluck/v/1.17.35/bin/plusu
    /opt/pluck/v/1.17.35/lib/libssl.so.1.1
    /opt/pluck/v/1.17.35/lib/libcrypto.so.1.1
    /opt/pluck/v/1.17.35/lib/libcurl.so.4
    /opt/pluck/v/1.17.35/lib/pluckeye.so
    /opt/pluck/v/1.17.35/lib/x
    /opt/pluck/v/1.17.35/lib/x86/pluckeye.so
    /etc/opt/chrome/native-messaging-hosts/net.pluckeye.pump.json
    /etc/chromium/native-messaging-hosts/net.pluckeye.pump.json
    /etc/opt/edge/native-messaging-hosts/net.pluckeye.pump.json
    /etc/opt/chrome/policies/managed/plug.json
    /etc/chromium/policies/managed/plug.json
    /etc/brave/policies/managed/plug.json
    /etc/opt/edge/policies/managed/plug.json
)

OTHER_FILES=(
    /usr/bin/pkexec
    /usr/bin/chattr
    /usr/sbin/debugfs
    /usr/bin/snap
    /usr/lib/snapd/snapd
)

for f in "${BASTION_FILES[@]}" "${PLUCKY_FILES[@]}" "${OTHER_FILES[@]}"; do
    if [ -f "$f" ]; then
        chattr -i "$f" 2>/dev/null || true
        chattr +i "$f"
        echo "  +i $f"
    else
        echo "  SKIP $f (not found)"
    fi
done

# --- Layer 2: Fix browser policies ---
echo "[3/12] Fixing browser policies..."

# Fix Brave policy — update URL to canonical form
BRAVE_POLICY="/etc/brave/policies/managed/plug.json"
if [ -f "$BRAVE_POLICY" ]; then
    chattr -i "$BRAVE_POLICY" 2>/dev/null || true
    # Update the update_url to the canonical URL
    sed -i 's|"update_url":"https://up.pluckeye.net/pluck/linux/[^"]*"|"update_url":"https://up.pluckeye.net/cluxo.xml"|' "$BRAVE_POLICY"
    echo "  Fixed Brave policy update URL"
fi

# Fix Edge policy — set plucky extension with correct update URL
EDGE_POLICY="/etc/opt/edge/policies/managed/plug.json"
if [ -f "$EDGE_POLICY" ]; then
    chattr -i "$EDGE_POLICY" 2>/dev/null || true
    # Replace Edge store URL with plucky update URL
    sed -i 's|"update_url":"https://edge.microsoft.com/extensionwebstorebase/v1/crx"|"update_url":"https://up.pluckeye.net/cluxo.xml"|' "$EDGE_POLICY"
    echo "  Fixed Edge policy update URL"
fi

# --- Layer 2b: Remove dyw from docker and sudo groups ---
echo "[4/12] Removing dyw from docker and sudo groups..."
if id -nG dyw 2>/dev/null | grep -qw docker; then
    gpasswd -d dyw docker
    echo "  Removed dyw from docker group (takes effect on next login)"
else
    echo "  SKIP dyw not in docker group"
fi
if id -nG dyw 2>/dev/null | grep -qw sudo; then
    gpasswd -d dyw sudo
    echo "  Removed dyw from sudo group (allow-list in bastion-protect only)"
else
    echo "  SKIP dyw not in sudo group"
fi

# --- Layer 2c: Disable snapd (bypasses ld.so.preload) ---
echo "[5/12] Disabling snapd..."
# Remove any snap-installed browsers
for pkg in chromium firefox chromium-browser; do
    if snap list "$pkg" &>/dev/null; then
        snap remove --purge "$pkg"
        echo "  Removed snap: $pkg"
    fi
done
# Stop and disable snapd
systemctl stop snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true
systemctl disable snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true
systemctl mask snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true
echo "  snapd stopped, disabled, and masked"

# --- Layer 2d: Disable unprivileged user namespaces ---
echo "[6/12] Disabling unprivileged user namespaces..."
USERNS_CONF="/etc/sysctl.d/99-no-userns.conf"
chattr -i "$USERNS_CONF" 2>/dev/null || true
echo "kernel.unprivileged_userns_clone=0" > "$USERNS_CONF"
chattr +i "$USERNS_CONF"
sysctl -w kernel.unprivileged_userns_clone=0 >/dev/null 2>&1 || true
echo "  Unprivileged user namespaces disabled"

# --- Layer 2d: Install immutable uninstall script ---
echo "[7/12] Installing puzzle-gated uninstaller..."
chattr -i /usr/lib/bastion/uninstall 2>/dev/null || true
mkdir -p /usr/lib/bastion
cp "$SCRIPT_DIR/uninstall.sh" /usr/lib/bastion/uninstall
chmod 755 /usr/lib/bastion/uninstall
chown root:root /usr/lib/bastion/uninstall
chattr +i /usr/lib/bastion/uninstall
echo "  Installed and locked /usr/lib/bastion/uninstall"

# --- Layer 3: Install sudoers deny rules ---
echo "[8/12] Installing sudoers deny rules..."
# Remove immutable flag if re-running hardening
chattr -i /etc/sudoers.d/bastion-protect 2>/dev/null || true
cp "$SCRIPT_DIR/bastion-protect.sudoers" /etc/sudoers.d/bastion-protect
chmod 440 /etc/sudoers.d/bastion-protect
chown root:root /etc/sudoers.d/bastion-protect

# Validate sudoers syntax
if ! visudo -c -f /etc/sudoers.d/bastion-protect >/dev/null 2>&1; then
    echo "ERROR: Sudoers file has syntax errors! Removing to prevent lockout."
    rm -f /etc/sudoers.d/bastion-protect
    exit 1
fi

# Make the sudoers file itself immutable
chattr +i /etc/sudoers.d/bastion-protect
echo "  Installed and locked /etc/sudoers.d/bastion-protect"

# Also lock the cronguard sudoers if it exists
if [ -f /etc/sudoers.d/zzz-cronguard ]; then
    chattr +i /etc/sudoers.d/zzz-cronguard
    echo "  Locked /etc/sudoers.d/zzz-cronguard"
fi

# --- Layer 4: Update systemd services with RefuseManualStop ---
echo "[9/12] Updating systemd service files..."
for svc in bastion-alpha bastion-beta bastion-gamma bastion-chronos; do
    UNIT_FILE="/etc/systemd/system/${svc}.service"
    if [ -f "$UNIT_FILE" ]; then
        # Copy fresh version from deploy dir (already has RefuseManualStop=yes)
        cp "$SCRIPT_DIR/${svc}.service" "$UNIT_FILE"
        chattr +i "$UNIT_FILE"
        echo "  Updated and locked $UNIT_FILE"
    else
        echo "  SKIP $UNIT_FILE (not found)"
    fi
done
systemctl daemon-reload

# --- Layer 5: Generate SHA-256 integrity manifest ---
echo "[10/12] Generating integrity manifest..."
MANIFEST="/var/lib/bastion/integrity.manifest"
chattr -i "$MANIFEST" 2>/dev/null || true
: > "$MANIFEST"

for f in "${BASTION_FILES[@]}" "${PLUCKY_FILES[@]}" "${OTHER_FILES[@]}"; do
    if [ -f "$f" ]; then
        sha256sum "$f" >> "$MANIFEST"
    fi
done

# Also include the puzzle hashes file itself
if [ -f /var/lib/bastion/puzzle_hashes.json ]; then
    sha256sum /var/lib/bastion/puzzle_hashes.json >> "$MANIFEST"
fi

# Include polkit deny rule
if [ -f /etc/polkit-1/rules.d/50-bastion-deny.rules ]; then
    sha256sum /etc/polkit-1/rules.d/50-bastion-deny.rules >> "$MANIFEST"
fi

chattr +i "$MANIFEST"
echo "  Wrote and locked $MANIFEST ($(wc -l < "$MANIFEST") entries)"

# --- Verify ---
echo "[11/12] Verifying hardening..."
echo ""

FAILURES=0

# Test immutable flags
for f in "${BASTION_FILES[@]}" "${PLUCKY_FILES[@]}" "${OTHER_FILES[@]}"; do
    if [ -f "$f" ]; then
        if lsattr "$f" 2>/dev/null | grep -q '.*i.*'; then
            echo "  OK  chattr +i on $f"
        else
            echo "  FAIL  missing +i on $f"
            FAILURES=$((FAILURES + 1))
        fi
    fi
done

# Test sudoers file
if [ -f /etc/sudoers.d/bastion-protect ]; then
    echo "  OK  sudoers deny rules installed"
else
    echo "  FAIL  sudoers deny rules missing"
    FAILURES=$((FAILURES + 1))
fi

# Test docker group
if id -nG dyw 2>/dev/null | grep -qw docker; then
    echo "  FAIL  dyw still in docker group"
    FAILURES=$((FAILURES + 1))
else
    echo "  OK  dyw not in docker group"
fi

# Test sudo group
if id -nG dyw 2>/dev/null | grep -qw sudo; then
    echo "  FAIL  dyw still in sudo group (allow-list bypass possible)"
    FAILURES=$((FAILURES + 1))
else
    echo "  OK  dyw not in sudo group (allow-list enforced)"
fi

# Test userns sysctl
USERNS_VAL=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "unknown")
if [ "$USERNS_VAL" = "0" ]; then
    echo "  OK  unprivileged user namespaces disabled"
else
    echo "  WARN unprivileged_userns_clone=$USERNS_VAL (expected 0)"
fi

# Test snapd disabled
if systemctl is-active --quiet snapd 2>/dev/null; then
    echo "  FAIL  snapd is still running"
    FAILURES=$((FAILURES + 1))
else
    echo "  OK  snapd is disabled"
fi

# Test services running
for svc in bastion-alpha bastion-beta bastion-gamma bastion-chronos; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "  OK  $svc is running"
    else
        echo "  WARN $svc is not running"
    fi
done

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "=== Bastion Hardening Complete ==="
    echo ""
    echo "Protection summary:"
    echo "  - Critical files are immutable (chattr +i)"
    echo "  - Browser policies fixed and locked"
    echo "  - Sudoers deny rules block removal/bypass commands"
    echo "  - Services refuse manual stop"
    echo "  - Plucky LD_PRELOAD hook is active"
    echo "  - Docker group membership removed"
    echo "  - Unprivileged user namespaces disabled"
    echo "  - snapd disabled and masked"
    echo "  - SHA-256 integrity manifest generated and locked"
    echo ""
    echo "To undo hardening (requires root, e.g. via uninstall.sh after puzzle):"
    echo "  chattr -i on all protected files, then remove sudoers rules."
else
    echo "=== Hardening completed with $FAILURES failure(s) ==="
    exit 1
fi
