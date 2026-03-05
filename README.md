# Bastion Deployment Guide

Complete guide to deploying Bastion's tamper-resistant content filter hardening on a new machine.

## Overview

Bastion wraps Plucky (a content filter using LD_PRELOAD) with multiple layers of tamper resistance:

- **Immutable flags** (chattr +i) on all critical binaries and configs
- **Sudoers allow-list** — user removed from sudo group; only specific commands permitted
- **Polkit deny rule** blocking pkexec escalation
- **Snapd removal** (snap apps bypass LD_PRELOAD)
- **Cryptographic puzzle-gated uninstaller** requiring ~1-2 hours of sequential computation
- **SHA-256 integrity manifest** detecting file tampering
- **Curfew cron job** shutting down the machine during restricted hours

### Security model

The sudoers approach is an **allow-list**, not a deny-list. The user is removed from the `sudo` group entirely, so no commands are allowed by default. Only explicitly listed commands work:

- `sudo /usr/lib/bastion/uninstall` — puzzle-gated (~1.7 hrs at t_bits=31)
- `sudo /usr/bin/cat *` — read-only file access (cat has no shell escape)
- `sudo /bin/systemctl poweroff` — shutdown

This eliminates all GTFOBins bypasses (vim, less, find, awk, man, git, etc.) because those commands simply aren't allowed.

### Root escalation paths after hardening

1. `sudo /usr/lib/bastion/uninstall` — solves a time-lock puzzle, verifies crypto token, checks integrity manifest, then removes everything
2. Recovery mode (hold Shift at GRUB) — physical access
3. Live USB — physical access

## Prerequisites

- Ubuntu/Debian Linux (tested on Ubuntu 24.04)
- Plucky content filter installed and working
- Rust toolchain (for building bastion)
- Root access (you will be locking yourself out)

## Step-by-Step Deployment

All steps from 2 onward must be run from a root shell. Get one before you start hardening — after step 9 you won't be able to get another one.

### 1. Build Bastion

```bash
cd ~/Programs/bastion
cargo build --release
```

Binaries are produced at `target/release/bastion`, `target/release/bastion-cerberus`, etc.

### 2. Install binaries

From a root shell:

```bash
mkdir -p /usr/lib/bastion
cp target/release/bastion /usr/lib/bastion/bastion
cp target/release/bastion-cerberus /usr/lib/bastion/bastion-cerberus
ln -sf /usr/lib/bastion/bastion /usr/local/bin/bastion
```

### 3. Initialize puzzles

Choose your t_bits value based on CPU speed. Test with a low value first to measure your squarings/sec rate, then scale up.

| t_bits | Squarings | ~Time at 340K sq/s |
|--------|-----------|--------------------|
| 25 | 33M | ~1.5 min |
| 28 | 268M | ~13 min |
| 30 | 1.07B | ~52 min |
| 31 | 2.15B | ~1.7 hrs |
| 32 | 4.29B | ~3.5 hrs |

```bash
./target/release/bastion init --t-bits 31
```

This generates:
- 100 time-lock puzzles in `/var/lib/bastion/puzzles/`
- Ed25519 signing keypair (private key destroyed after use)
- RSA-2048 modulus for puzzle construction
- `puzzle_hashes.json` — SHA-256 hashes of puzzle secrets for crypto verification
- Signed config at `/var/lib/bastion/config.signed`

**Important**: The `puzzle_hashes.json` file is critical. It enables the uninstall script to verify that the bastion binary actually solved a real puzzle (not a fake binary printing a fake token).

### 4. Nuke snapd

Snap applications run in isolated mount namespaces and bypass LD_PRELOAD entirely. Remove snapd before hardening.

```bash
# Remove all snap packages
snap list | awk 'NR>1{print $1}' | xargs -I{} snap remove --purge {}
# Stop and disable snapd
systemctl stop snapd.service snapd.socket snapd.seeded.service
systemctl disable snapd.service snapd.socket snapd.seeded.service
systemctl mask snapd.service snapd.socket snapd.seeded.service
# Remove all snap data and systemd units
rm -rf /var/lib/snapd /var/cache/snapd /snap /var/snap
rm -f /etc/systemd/system/snap-*.mount /etc/systemd/system/snap.*.service
rm -f /etc/systemd/system/snapd.*.service /etc/systemd/system/snapd.*.socket
rm -f /etc/systemd/system/snapd.*.timer /etc/systemd/system/snapd.*.target
rm -rf /etc/systemd/system/snapd.mounts.target.wants
rm -rf /etc/systemd/system/snapd.mounts-pre.target.wants
systemctl daemon-reload
# Optionally remove snap binary entirely
rm -f /usr/bin/snap /usr/lib/snapd/snapd
```

### 5. Set up polkit deny rule

Block pkexec escalation:

```bash
cat > /etc/polkit-1/rules.d/50-bastion-deny.rules << 'EOF'
polkit.addRule(function(action, subject) {
    if (action.id === "org.freedesktop.policykit.exec" &&
        subject.user === "YOUR_USERNAME") {
        return polkit.Result.NO;
    }
});
EOF
chattr +i /etc/polkit-1/rules.d/50-bastion-deny.rules
systemctl restart polkit
```

Replace `YOUR_USERNAME` with your actual username.

### 6. Set up curfew (optional)

Create the shutdown script:

```bash
cat > /usr/lib/bastion/curfew.sh << 'EOF'
#!/bin/bash
/usr/sbin/shutdown -h now "Bastion curfew: system shutting down"
EOF
chmod 755 /usr/lib/bastion/curfew.sh
chown root:root /usr/lib/bastion/curfew.sh
chattr +i /usr/lib/bastion/curfew.sh
```

Create the cron job (adjust hours as needed):

```bash
cat > /etc/cron.d/bastion-curfew << 'EOF'
# Bastion curfew: shutdown every 2 mins during restricted hours
30,32,34,36,38,40,42,44,46,48,50,52,54,56,58 21 * * * root /usr/lib/bastion/curfew.sh
*/2 22-23 * * * root /usr/lib/bastion/curfew.sh
*/2 0-3 * * * root /usr/lib/bastion/curfew.sh
EOF
chmod 644 /etc/cron.d/bastion-curfew
chown root:root /etc/cron.d/bastion-curfew
chattr +i /etc/cron.d/bastion-curfew
```

### 7. Run hardening

```bash
cd ~/Programs/bastion
./deploy/harden.sh
```

This will:
1. Lock `ld.so.preload` (immutable)
2. Set immutable flags on all bastion/plucky/system binaries (including pkexec, chattr, debugfs)
3. Fix browser extension policies
4. Remove user from docker and sudo groups
5. Disable snapd
6. Disable unprivileged user namespaces
7. Install puzzle-gated uninstaller at `/usr/lib/bastion/uninstall`
8. Install sudoers allow-list (only uninstall, cat, poweroff)
9. Lock systemd service files (with RefuseManualStop)
10. Generate SHA-256 integrity manifest
11. Verify everything

**Critical**: harden.sh removes the user from the `sudo` group. This takes effect on next login/reboot.

### 8. Make plucky rules writable

Plucky needs to manage its own rules file for normal operation (delay-gated rule changes via `pluck` CLI or web interface):

```bash
chattr -i /var/opt/pluck/rules
chattr -i /var/opt/pluck
```

### 9. Verify, exit, and reboot

Run the final check:

```bash
bash /tmp/bastion-final-check.sh
```

Expected output:
- All immutable files: OK
- bastion-alpha/beta/gamma: active
- cron: active
- snapd: inactive
- plucky rules writable: yes, immutable: no
- puzzle_hashes.json: exists
- dyw in sudo group (/etc/group): no
- All integrity manifest files match

**Exit the root shell:**

```bash
exit
```

**Reboot** to ensure the sudo group removal takes effect:

```bash
sudo /bin/systemctl poweroff
```

After reboot, the user's session will no longer have the `sudo` group, and the allow-list is fully enforced.

### 10. Post-reboot verification

After logging back in:

```bash
# Should work:
sudo cat /etc/sudoers.d/bastion-protect

# Should be denied:
sudo bash
sudo whoami
sudo find / -exec /bin/bash \;
sudo vim

# Should show no 'sudo' group:
groups
```

## Modifying Sudo Rules (Without Full Uninstall)

To add or remove sudo rules without uninstalling everything:

```bash
sudo /usr/lib/bastion/admin-edit
```

This will:
1. Verify the integrity manifest (abort if files tampered)
2. Solve a time-lock puzzle (~1.7 hours at t_bits=31)
3. Verify the cryptographic token
4. Drop into an interactive editor for the sudoers allow-list

Interactive commands:
- `add <rule>` — add a sudoers rule (e.g., `add dyw ALL=(root) /usr/bin/apt install *`)
- `remove <num>` — remove a rule by line number
- `show` — display current rules with line numbers
- `done` — validate syntax, save, re-lock, and update integrity manifest
- `abort` — discard all changes and re-lock

The script validates sudoers syntax before saving — if there's a syntax error, it won't let you save (which would lock you out of sudo entirely).

**Safety notes**:
- Don't add rules that allow shell-spawning binaries (vim, less, find, man, git, etc.)
- Safe commands to allow: `cat`, `apt install`, `systemctl status`, `ls`, `df`, `du`, `lsattr`
- Unsafe commands (GTFOBins): `vim`, `less`, `more`, `man`, `find`, `awk`, `git`, `tar`, `zip`, `ssh`, `ftp`, `script`, `expect`, `nice`, `nmap`

## Uninstalling

### Method 1: Puzzle-gated uninstaller (normal path)

```bash
sudo /usr/lib/bastion/uninstall
```

This will:
1. Verify integrity manifest (abort if files tampered)
2. Solve a time-lock puzzle (~1.7 hours at t_bits=31)
3. Output a cryptographic token
4. Verify the token hash against `puzzle_hashes.json`
5. Remove all immutable flags
6. Remove sudoers rules
7. Stop and disable bastion services
8. Remove systemd units
9. Remove lockdown rules
10. Remove bastion binaries and data

**After uninstall**: You'll need to add yourself back to the sudo group to regain full access:

```bash
# From recovery mode or the uninstall script's context:
usermod -aG sudo YOUR_USERNAME
```

### Method 2: Recovery mode (emergency)

1. Reboot, hold Shift at GRUB menu
2. Select "Advanced options" > "Recovery mode"
3. Select "root — Drop to root shell prompt"
4. Run:

```bash
# Re-add user to sudo group
usermod -aG sudo YOUR_USERNAME

# Remove sudoers allow-list
chattr -i /etc/sudoers.d/bastion-protect
rm -f /etc/sudoers.d/bastion-protect

# Remove polkit deny
chattr -i /etc/polkit-1/rules.d/50-bastion-deny.rules
rm -f /etc/polkit-1/rules.d/50-bastion-deny.rules

# Remove curfew
chattr -i /etc/cron.d/bastion-curfew
rm -f /etc/cron.d/bastion-curfew
chattr -i /usr/lib/bastion/curfew.sh

# Remove immutable flags on all bastion files
chattr -i /usr/lib/bastion/*
chattr -i /var/lib/bastion/integrity.manifest

# Remove immutable from system binaries
chattr -i /usr/bin/pkexec
chattr -i /usr/bin/chattr
chattr -i /usr/sbin/debugfs

# Remove immutable from ld.so.preload
chattr -i /etc/ld.so.preload

# Remove immutable from systemd units
chattr -i /etc/systemd/system/bastion-*.service

# Stop services
sed -i '/^RefuseManualStop=yes$/d' /etc/systemd/system/bastion-*.service
systemctl daemon-reload
systemctl stop bastion-alpha bastion-beta bastion-gamma bastion-chronos
systemctl disable bastion-alpha bastion-beta bastion-gamma bastion-chronos

# Remove everything
rm -rf /usr/lib/bastion
rm -rf /var/lib/bastion
rm -f /usr/local/bin/bastion

# Restart polkit
systemctl restart polkit

# Reboot
reboot
```

### Method 3: Live USB (if recovery mode is inaccessible)

1. Boot from a Linux live USB
2. Mount the root partition: `mount /dev/sdaX /mnt`
3. Remove the sudoers file: `rm /mnt/etc/sudoers.d/bastion-protect`
4. Remove polkit rule: `rm /mnt/etc/polkit-1/rules.d/50-bastion-deny.rules`
5. Remove curfew: `rm /mnt/etc/cron.d/bastion-curfew`
6. Re-add user to sudo group: edit `/mnt/etc/group`, find the `sudo:x:27:` line and add your username
7. Unmount and reboot: `umount /mnt && reboot`
8. After reboot, use `sudo` normally to remove remaining hardening

## Architecture

### Cryptographic verification flow (uninstall)

```
uninstall.sh
  |
  ├─ Step 1: Read /var/lib/bastion/integrity.manifest
  │          SHA-256 check every protected file
  │          ABORT if any file was tampered with
  │
  ├─ Step 2: Run `bastion unlock --rule "uninstall-authorized"`
  │          Solve time-lock puzzle (sequential squarings)
  │          Capture BASTION_UNINSTALL_TOKEN=<hex> from stdout
  │          ABORT if no token output (fake binary)
  │
  └─ Step 3: Hash the token with SHA-256
             Check hash exists in /var/lib/bastion/puzzle_hashes.json
             ABORT if hash doesn't match (fake token)
             PROCEED with uninstall
```

### Attack this defeats

**Before crypto hardening**: attacker copies chattr to /tmp, removes immutable flag on bastion binary, replaces with fake `exit 0` script, runs uninstall, fake exits 0, uninstall proceeds.

**After crypto hardening**:
1. Integrity manifest detects the binary was replaced -> **abort**
2. Even if manifest is bypassed, fake binary can't produce a token whose SHA-256 matches any puzzle secret hash -> **abort**

### Why allow-list, not deny-list

The original approach used sudoers deny rules (`!command`) to block specific dangerous binaries. This is fundamentally broken because:

- Linux has hundreds of binaries that can spawn shells (GTFOBins)
- `sudo vim` → `:!bash` = root shell
- `sudo find / -exec /bin/bash \;` = root shell
- `sudo less` → `!bash` = root shell
- `sudo awk 'BEGIN {system("/bin/bash")}'` = root shell
- `sudo man man` → `!bash` = root shell
- `sudo git -p help` → `!bash` = root shell
- `sudo tar ... --checkpoint-action=exec=/bin/bash` = root shell

The allow-list approach removes the user from the `sudo` group entirely. With no blanket `ALL` grant, only explicitly listed commands work. There's nothing to bypass.

### Key files

| Path | Purpose |
|------|---------|
| `/usr/lib/bastion/bastion` | CLI binary (unlock, init, status) |
| `/usr/lib/bastion/uninstall` | Puzzle-gated uninstall script |
| `/usr/lib/bastion/admin-edit` | Puzzle-gated sudoers editor |
| `/usr/lib/bastion/curfew.sh` | Curfew shutdown script |
| `/var/lib/bastion/puzzles/` | Pre-generated time-lock puzzles |
| `/var/lib/bastion/puzzle_hashes.json` | SHA-256(secret) for each puzzle |
| `/var/lib/bastion/integrity.manifest` | SHA-256 hashes of all protected files |
| `/var/lib/bastion/config.signed` | Signed bastion config (t_bits, PSK, etc.) |
| `/etc/sudoers.d/bastion-protect` | Sudoers allow-list |
| `/etc/sudoers.d/poweroff-dyw` | Poweroff permission |
| `/etc/sudoers.d/zzz-cronguard` | Cronguard permissions |
| `/etc/polkit-1/rules.d/50-bastion-deny.rules` | Polkit deny for pkexec |
| `/etc/cron.d/bastion-curfew` | Curfew cron schedule |
| `/etc/ld.so.preload` | Plucky LD_PRELOAD hook |

### Sudoers allow-list

After hardening, the user can only run via sudo:

| Command | Purpose | Password |
|---------|---------|----------|
| `sudo /usr/lib/bastion/uninstall` | Puzzle-gated full uninstall | yes |
| `sudo /usr/lib/bastion/admin-edit` | Puzzle-gated sudoers editor | yes |
| `sudo /usr/bin/cat *` | Read any file as root | no |
| `sudo /bin/systemctl poweroff` | Shutdown | no |
| `sudo -u cronguard chattr *` | Cronguard operations | — |
| `sudo -u cronguard crontab *` | Cronguard operations | — |

Everything else is denied by default (user is not in sudo group).

## Troubleshooting

### "sudo: sorry, you are not allowed to execute..."

This is expected behavior after hardening. Only the commands listed in the allow-list work. If you need to do admin tasks, use the puzzle-gated uninstaller or recovery mode.

### sudo still allows everything after hardening

The user must **log out and log back in** (or reboot) after `gpasswd -d USERNAME sudo`. The sudo group removal only takes effect when the session refreshes group membership. Check:

```bash
# Persistent group membership (should NOT show sudo):
grep sudo /etc/group

# Current session groups (will still show sudo until relogin):
groups
```

### Plucky rules not applying

Check that `/var/opt/pluck/rules` and `/var/opt/pluck` are NOT immutable:

```bash
lsattr /var/opt/pluck/rules
```

If immutable, you need root to fix — use the uninstaller or recovery mode.

### "uninstall-authorized" appearing in plucky rules

Fixed in current code — `cmd_unlock` skips applying "uninstall-authorized" to plucky. If it happens, the rules file needs manual cleanup from a root shell.

### Puzzle time estimate is wrong

The CLI assumes ~30M squarings/sec. Actual rate varies by CPU. The real time is shown by the progress bar during solve.

### bastion-chronos not running

This is a known WARN — chronos may not be deployed on all setups. It doesn't affect the core hardening.

### Re-hardening after changes

If you need to make changes and re-harden, you must remove immutable flags on files that harden.sh needs to write. From a root shell:

```bash
chattr -i /usr/lib/bastion/uninstall
chattr -i /etc/sudoers.d/bastion-protect
chattr -i /var/lib/bastion/integrity.manifest
chattr -i /etc/systemd/system/bastion-alpha.service
chattr -i /etc/systemd/system/bastion-beta.service
chattr -i /etc/systemd/system/bastion-gamma.service
chattr -i /etc/systemd/system/bastion-chronos.service
cd ~/Programs/bastion && ./deploy/harden.sh
```
