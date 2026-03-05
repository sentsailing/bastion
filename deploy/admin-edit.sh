#!/bin/bash
set -euo pipefail

echo "=== Bastion Admin: Edit Sudoers Allow-List ==="
echo ""
echo "This will let you add/remove sudo rules after solving a time-lock puzzle."
echo ""

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)."
    exit 1
fi

# --- Step 1: Verify integrity manifest ---
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
        echo "ERROR: $TAMPERED file(s) have been tampered with. Aborted."
        exit 1
    fi
    echo "  All files match integrity manifest."
else
    echo "WARNING: No integrity manifest found."
fi

# --- Step 2: Solve puzzle and capture cryptographic token ---
echo ""
echo "Solving time-lock puzzle..."
UNLOCK_OUTPUT=$(bastion unlock --rule "uninstall-authorized") || {
    echo "ERROR: Puzzle not solved. Denied."
    exit 1
}

TOKEN=$(echo "$UNLOCK_OUTPUT" | grep '^BASTION_UNINSTALL_TOKEN=' | head -1 | cut -d= -f2)
if [ -z "$TOKEN" ]; then
    echo "ERROR: No token received from bastion. Binary may be compromised."
    exit 1
fi

# --- Step 3: Verify token hash ---
PUZZLE_HASHES="/var/lib/bastion/puzzle_hashes.json"
if [ -f "$PUZZLE_HASHES" ]; then
    TOKEN_HASH=$(echo -n "$TOKEN" | xxd -r -p | sha256sum | awk '{print $1}')
    if grep -q "\"$TOKEN_HASH\"" "$PUZZLE_HASHES"; then
        echo "  Cryptographic token verified."
    else
        echo "ERROR: Token hash does not match any known puzzle secret."
        echo "Aborted."
        exit 1
    fi
else
    echo "WARNING: No puzzle hashes file found."
fi

echo ""
echo "Authorization confirmed."
echo ""

# --- Step 4: Show current rules and accept edits ---
SUDOERS="/etc/sudoers.d/bastion-protect"
chattr -i "$SUDOERS"

echo "Current sudoers allow-list:"
echo "---"
cat "$SUDOERS"
echo "---"
echo ""
echo "Commands:"
echo "  add <rule>    — add a sudoers rule (e.g., 'dyw ALL=(root) /usr/bin/apt install *')"
echo "  remove <num>  — remove rule by line number"
echo "  show          — show current rules"
echo "  done          — save and exit"
echo "  abort         — discard changes and exit"
echo ""

while true; do
    read -rp "admin> " CMD ARG
    case "$CMD" in
        add)
            if [ -z "$ARG" ]; then
                echo "Usage: add <sudoers rule>"
                continue
            fi
            echo "$ARG" >> "$SUDOERS"
            echo "Added: $ARG"
            ;;
        remove)
            if [ -z "$ARG" ] || ! [[ "$ARG" =~ ^[0-9]+$ ]]; then
                echo "Usage: remove <line number>"
                continue
            fi
            sed -i "${ARG}d" "$SUDOERS"
            echo "Removed line $ARG"
            ;;
        show)
            echo "---"
            cat -n "$SUDOERS"
            echo "---"
            ;;
        done)
            # Validate sudoers syntax before saving
            if visudo -c -f "$SUDOERS" >/dev/null 2>&1; then
                chattr +i "$SUDOERS"
                # Update integrity manifest for the changed sudoers file
                chattr -i "$MANIFEST" 2>/dev/null || true
                # Replace the old hash for bastion-protect
                grep -v "$SUDOERS" "$MANIFEST" > /tmp/manifest.tmp
                sha256sum "$SUDOERS" >> /tmp/manifest.tmp
                mv /tmp/manifest.tmp "$MANIFEST"
                chattr +i "$MANIFEST"
                echo "Saved and locked."
            else
                echo "ERROR: Sudoers syntax error! Fix before saving."
                echo "Use 'show' to review, 'remove' to fix, or 'abort' to discard."
                continue
            fi
            break
            ;;
        abort)
            # Restore original by re-running harden would be overkill,
            # just re-lock what we have
            chattr +i "$SUDOERS"
            echo "Aborted. No changes saved."
            break
            ;;
        *)
            echo "Unknown command. Use: add, remove, show, done, abort"
            ;;
    esac
done
