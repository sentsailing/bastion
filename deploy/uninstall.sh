#!/bin/bash
set -euo pipefail

echo "=== Bastion Uninstaller ==="
echo ""
echo "WARNING: This will remove Bastion and all its protections."
echo "You must solve a time-lock puzzle to proceed."
echo ""

# Must run as root (puzzle files are root-owned)
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)."
    exit 1
fi

# --- Step 1: Verify integrity manifest ---
# If files were tampered with (e.g., bastion binary replaced), abort early.
MANIFEST="/var/lib/bastion/integrity.manifest"
if [ -f "$MANIFEST" ]; then
    echo "Verifying file integrity..."
    TAMPERED=0
    while IFS= read -r line; do
        expected_hash=$(echo "$line" | awk '{print $1}')
        filepath=$(echo "$line" | awk '{print $2}')
        if [ -f "$filepath" ]; then
            actual_hash=$(sha256sum "$filepath" | awk '{print $1}')
            if [ "$expected_hash" != "$actual_hash" ]; then
                echo "  TAMPERED: $filepath"
                TAMPERED=$((TAMPERED + 1))
            fi
        fi
    done < "$MANIFEST"
    if [ "$TAMPERED" -gt 0 ]; then
        echo "ERROR: $TAMPERED file(s) have been tampered with. Uninstall aborted."
        echo "This may indicate an attack. Investigate before proceeding."
        exit 1
    fi
    echo "  All files match integrity manifest."
else
    echo "WARNING: No integrity manifest found. Proceeding without file integrity check."
fi

# --- Step 2: Solve puzzle and capture cryptographic token ---
echo ""
echo "Solving time-lock puzzle..."
UNLOCK_OUTPUT=$(bastion unlock --rule "uninstall-authorized") || {
    echo "ERROR: Puzzle not solved. Uninstall denied."
    exit 1
}

# Extract the cryptographic token from bastion output
TOKEN=$(echo "$UNLOCK_OUTPUT" | grep '^BASTION_UNINSTALL_TOKEN=' | head -1 | cut -d= -f2)
if [ -z "$TOKEN" ]; then
    echo "ERROR: No uninstall token received from bastion. Binary may be compromised."
    exit 1
fi

# --- Step 3: Verify token hash against pre-stored puzzle hashes ---
PUZZLE_HASHES="/var/lib/bastion/puzzle_hashes.json"
if [ -f "$PUZZLE_HASHES" ]; then
    # Hash the token (which is the hex-encoded secret) — convert hex back to binary first
    TOKEN_HASH=$(echo -n "$TOKEN" | xxd -r -p | sha256sum | awk '{print $1}')
    # Check if this hash exists as a value in puzzle_hashes.json
    if grep -q "\"$TOKEN_HASH\"" "$PUZZLE_HASHES"; then
        echo "  Cryptographic token verified."
    else
        echo "ERROR: Token hash does not match any known puzzle secret."
        echo "This means the bastion binary produced an invalid token."
        echo "Uninstall aborted."
        exit 1
    fi
else
    echo "WARNING: No puzzle hashes file found. Proceeding without token verification."
fi

echo ""
echo "Authorization confirmed. Proceeding with uninstall..."
echo ""
echo "Removing immutable flags..."
# Remove immutable flags from all protected files
for f in \
    /usr/lib/bastion/bastion-cerberus \
    /usr/lib/bastion/bastion-chronos \
    /usr/lib/bastion/bastion-timelock \
    /usr/lib/bastion/bastion \
    /usr/lib/bastion/uninstall \
    /usr/lib/x86_64-linux-gnu/pluckeye.so \
    /usr/lib32/pluckeye.so \
    /opt/pluck/v/1.17.35/bin/boss \
    /opt/pluck/v/1.17.35/bin/tock \
    /opt/pluck/v/1.17.35/bin/pluck \
    /opt/pluck/v/1.17.35/bin/pump \
    /opt/pluck/v/1.17.35/bin/spawn \
    /opt/pluck/v/1.17.35/bin/hatch \
    /opt/pluck/v/1.17.35/bin/verify \
    /opt/pluck/v/1.17.35/bin/true \
    /opt/pluck/v/1.17.35/bin/pludo \
    /opt/pluck/v/1.17.35/bin/plusu \
    /opt/pluck/v/1.17.35/lib/libssl.so.1.1 \
    /opt/pluck/v/1.17.35/lib/libcrypto.so.1.1 \
    /opt/pluck/v/1.17.35/lib/libcurl.so.4 \
    /opt/pluck/v/1.17.35/lib/pluckeye.so \
    /opt/pluck/v/1.17.35/lib/x \
    /opt/pluck/v/1.17.35/lib/x86/pluckeye.so \
    /etc/opt/chrome/native-messaging-hosts/net.pluckeye.pump.json \
    /etc/chromium/native-messaging-hosts/net.pluckeye.pump.json \
    /etc/opt/edge/native-messaging-hosts/net.pluckeye.pump.json \
    /etc/opt/chrome/policies/managed/plug.json \
    /etc/chromium/policies/managed/plug.json \
    /etc/brave/policies/managed/plug.json \
    /etc/opt/edge/policies/managed/plug.json \
    /etc/sysctl.d/99-no-userns.conf \
    /etc/ld.so.preload \
    /etc/sudoers.d/bastion-protect \
    /etc/sudoers.d/zzz-cronguard \
    /etc/systemd/system/bastion-alpha.service \
    /etc/systemd/system/bastion-beta.service \
    /etc/systemd/system/bastion-gamma.service \
    /etc/systemd/system/bastion-chronos.service; do
    if [ -f "$f" ]; then
        chattr -i "$f" 2>/dev/null || true
        echo "  -i $f"
    fi
done

echo "Removing sudoers deny rules..."
rm -f /etc/sudoers.d/bastion-protect

echo "Stopping services..."
# Services have RefuseManualStop, but we already removed immutable flags on unit files
# Replace unit files without RefuseManualStop to allow stopping
for svc in bastion-alpha bastion-beta bastion-gamma bastion-chronos; do
    UNIT_FILE="/etc/systemd/system/${svc}.service"
    if [ -f "$UNIT_FILE" ]; then
        # Remove RefuseManualStop line
        sed -i '/^RefuseManualStop=yes$/d' "$UNIT_FILE"
    fi
done
systemctl daemon-reload
systemctl stop bastion-alpha bastion-beta bastion-gamma bastion-chronos 2>/dev/null || true
systemctl disable bastion-alpha bastion-beta bastion-gamma bastion-chronos 2>/dev/null || true

echo "Removing systemd units..."
rm -f /etc/systemd/system/bastion-alpha.service
rm -f /etc/systemd/system/bastion-beta.service
rm -f /etc/systemd/system/bastion-gamma.service
rm -f /etc/systemd/system/bastion-chronos.service
systemctl daemon-reload

echo "Removing lockdown rules..."
rm -f /etc/nftables-bastion-lockdown.conf
nft delete table inet bastion_lockdown 2>/dev/null || true

echo "Removing binaries..."
rm -rf /usr/lib/bastion
rm -f /usr/local/bin/bastion

echo "Removing data..."
chattr -i /var/lib/bastion/integrity.manifest 2>/dev/null || true
rm -rf /var/lib/bastion
rm -rf /run/bastion

echo ""
echo "=== Bastion Uninstalled ==="
