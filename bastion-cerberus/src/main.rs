use anyhow::{Context, Result};
use bastion_common::crypto;
use bastion_common::paths;
use bastion_common::protocol::WatchdogMessage;
use bastion_common::WatchdogRole;
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
use std::collections::HashMap;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const PEER_TIMEOUT: Duration = Duration::from_secs(15);
const CHALLENGE_INTERVAL: Duration = Duration::from_secs(30);
const SOCKET_DIR: &str = "/run/bastion";

fn socket_path(role: WatchdogRole) -> String {
    format!("{}/{}.sock", SOCKET_DIR, role)
}

fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let role = determine_role(&args).context("could not determine watchdog role")?;

    println!("Bastion Cerberus starting as {} watchdog", role);

    let config = load_config()?;
    let psk = hex::decode(&config.watchdog_psk).context("invalid PSK hex")?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc_handler(r);

    run_watchdog(role, &psk, &config.watched_paths, running)
}

fn determine_role(args: &[String]) -> Option<WatchdogRole> {
    if let Some(name) = args[0].rsplit('/').next() {
        if let Some(role) = WatchdogRole::from_arg(
            name.strip_prefix("bastion-cerberus-").unwrap_or(""),
        ) {
            return Some(role);
        }
    }
    if args.len() > 1 {
        return WatchdogRole::from_arg(&args[1]);
    }
    None
}

fn load_config() -> Result<bastion_common::BastionConfig> {
    let data = std::fs::read_to_string(paths::config_path())
        .context("failed to read bastion config — is bastion initialized?")?;
    let val: serde_json::Value = serde_json::from_str(&data).context("failed to parse config JSON")?;
    if let Some(inner) = val.get("config") {
        serde_json::from_value(inner.clone()).context("failed to parse config from envelope")
    } else {
        serde_json::from_value(val).context("failed to parse config")
    }
}

fn ctrlc_handler(running: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            if !running.load(Ordering::Relaxed) {
                break;
            }
        }
    });
}

fn run_watchdog(
    role: WatchdogRole,
    psk: &[u8],
    watched_paths: &[String],
    running: Arc<AtomicBool>,
) -> Result<()> {
    // Create socket directory
    std::fs::create_dir_all(SOCKET_DIR).ok();

    // Remove stale socket file
    let sock_path = socket_path(role);
    let _ = std::fs::remove_file(&sock_path);

    let sock = UnixDatagram::bind(&sock_path)
        .with_context(|| format!("failed to bind socket at {}", sock_path))?;
    sock.set_read_timeout(Some(Duration::from_secs(1)))?;

    let inotify = setup_inotify(watched_paths)?;
    let mut peer_last_seen: HashMap<WatchdogRole, Instant> = HashMap::new();
    let mut last_heartbeat = Instant::now();
    let mut last_challenge = Instant::now();

    println!("{}: Watchdog running. Monitoring {} paths.", role, watched_paths.len());

    while running.load(Ordering::Relaxed) {
        if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
            let msg = WatchdogMessage::Heartbeat {
                from: role,
                timestamp_secs: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };
            broadcast_to_peers(role, &msg);
            last_heartbeat = Instant::now();
        }

        if last_challenge.elapsed() >= CHALLENGE_INTERVAL {
            let mut nonce = [0u8; 32];
            getrandom::getrandom(&mut nonce).unwrap();
            let msg = WatchdogMessage::Challenge {
                from: role,
                nonce: nonce.to_vec(),
            };
            broadcast_to_peers(role, &msg);
            last_challenge = Instant::now();
        }

        let mut buf = [0u8; 4096];
        match sock.recv(&mut buf) {
            Ok(n) => {
                if let Ok(msg) = serde_json::from_slice::<WatchdogMessage>(&buf[..n]) {
                    handle_message(role, psk, &msg, &mut peer_last_seen);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => log::warn!("{}: socket recv error: {}", role, e),
        }

        for peer in role.peers() {
            if let Some(last) = peer_last_seen.get(&peer) {
                if last.elapsed() > PEER_TIMEOUT {
                    log::warn!("{}: peer {} appears dead, attempting respawn", role, peer);
                    respawn_peer(peer);
                    peer_last_seen.remove(&peer);
                }
            }
        }

        check_inotify(&inotify, role);
    }

    // Cleanup socket on exit
    let _ = std::fs::remove_file(&sock_path);
    println!("{}: Shutting down.", role);
    Ok(())
}

fn handle_message(
    role: WatchdogRole,
    psk: &[u8],
    msg: &WatchdogMessage,
    peer_last_seen: &mut HashMap<WatchdogRole, Instant>,
) {
    match msg {
        WatchdogMessage::Heartbeat { from, timestamp_secs } => {
            peer_last_seen.insert(*from, Instant::now());
            log::debug!("{}: heartbeat from {} at t={}", role, from, timestamp_secs);
        }
        WatchdogMessage::Challenge { from, nonce } => {
            peer_last_seen.insert(*from, Instant::now());
            let mac = crypto::hmac_challenge(psk, nonce);
            let response = WatchdogMessage::ChallengeResponse {
                from: role,
                mac,
            };
            send_to_peer(*from, &response);
        }
        WatchdogMessage::ChallengeResponse { from, mac: _ } => {
            peer_last_seen.insert(*from, Instant::now());
            log::debug!("{}: challenge response from {}", role, from);
        }
        WatchdogMessage::TamperAlert { from, path, detail } => {
            log::error!(
                "{}: TAMPER ALERT from {} — path={}, detail={}",
                role, from, path, detail
            );
            trigger_lockdown(role, &format!("tamper alert from {}: {}", from, detail));
        }
        WatchdogMessage::RespawnRequest { from, target } => {
            log::warn!("{}: respawn request from {} for {}", role, from, target);
            respawn_peer(*target);
        }
    }
}

fn broadcast_to_peers(role: WatchdogRole, msg: &WatchdogMessage) {
    for peer in role.peers() {
        send_to_peer(peer, msg);
    }
}

fn send_to_peer(peer: WatchdogRole, msg: &WatchdogMessage) {
    let path = socket_path(peer);
    if !Path::new(&path).exists() {
        return;
    }
    if let Ok(data) = serde_json::to_vec(msg) {
        if let Ok(s) = UnixDatagram::unbound() {
            let _ = s.send_to(&data, &path);
        }
    }
}

fn setup_inotify(watched_paths: &[String]) -> Result<Inotify> {
    let inotify = Inotify::init(InitFlags::IN_NONBLOCK)?;
    for path in watched_paths {
        if Path::new(path).exists() {
            let flags = AddWatchFlags::IN_MODIFY
                | AddWatchFlags::IN_DELETE_SELF
                | AddWatchFlags::IN_MOVE_SELF
                | AddWatchFlags::IN_ATTRIB;
            match inotify.add_watch(Path::new(path), flags) {
                Ok(_) => log::info!("watching: {}", path),
                Err(e) => log::warn!("failed to watch {}: {}", path, e),
            }
        } else {
            log::warn!("watched path does not exist: {}", path);
        }
    }
    Ok(inotify)
}

fn check_inotify(inotify: &Inotify, role: WatchdogRole) {
    match inotify.read_events() {
        Ok(events) => {
            for event in events {
                let detail = format!("inotify event: mask={:?}", event.mask);
                log::error!("{}: file integrity violation — {}", role, detail);
                trigger_lockdown(role, &detail);
            }
        }
        Err(_) => {}
    }
}

fn respawn_peer(peer: WatchdogRole) {
    let binary = format!("{}/bastion-cerberus", paths::bastion_dir());
    if Path::new(&binary).exists() {
        match Command::new(&binary).arg(peer.to_string()).spawn() {
            Ok(child) => log::info!("respawned {} (pid {})", peer, child.id()),
            Err(e) => log::error!("failed to respawn {}: {}", peer, e),
        }
    } else {
        log::error!(
            "cannot respawn {}: binary missing at {}. LOCKDOWN.",
            peer, binary
        );
        trigger_lockdown(peer, "binary missing");
    }
}

fn trigger_lockdown(role: WatchdogRole, reason: &str) {
    log::error!("{}: LOCKDOWN triggered — {}", role, reason);

    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths::audit_log())
    {
        use std::io::Write;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let _ = writeln!(f, "{} [{}] LOCKDOWN: {}", ts, role, reason);
    }

    let nft_rules = r#"
#!/usr/sbin/nft -f
flush ruleset
table inet bastion_lockdown {
    chain output {
        type filter hook output priority 0; policy drop;
        oif lo accept
        counter drop
    }
}
"#;
    if let Ok(()) = std::fs::write(paths::NFTABLES_LOCKDOWN, nft_rules) {
        let _ = Command::new("nft").arg("-f").arg(paths::NFTABLES_LOCKDOWN).status();
    }
}

mod hex {
    use anyhow::{Context, Result};

    pub fn decode(s: &str) -> Result<Vec<u8>> {
        if s.len() % 2 != 0 {
            anyhow::bail!("odd hex string length");
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("invalid hex"))
            .collect()
    }
}
