mod bootloader;
mod cpio;
mod net_params;
use bootloader::{probe_bootloader, register_boot_entry, remove_boot_entry};
use cpio::{CpioReader, CpioWriter};
use net_params::KernelIpConfig;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use log::{debug, error, info, warn};
use mimic_shared::DeploymentConfig;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

// Alpine Linux 3.21.0 Virt Artifacts
const ALPINE_KERNEL_URL: &str =
    "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/netboot/vmlinuz-virt";
const ALPINE_INITRD_URL: &str =
    "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/netboot/initramfs-virt";
const ALPINE_MODLOOP_URL: &str =
    "https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/netboot/modloop-virt";

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Clean up/uninstall the Mimic Alpine Rescue System
    Clean,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    info!("--- Mimic Boot Manager");

    let args = Args::parse();

    // Handle subcommands
    if let Some(Commands::Clean) = args.command {
        return perform_cleanup();
    }

    let config_path = "deployment.json";
    if !Path::new(config_path).exists() {
        warn!(
            "No deployment configuration found at {}. Please run kgen (run.sh) first.",
            config_path
        );
        return Ok(());
    }

    let content = fs::read_to_string(config_path).context("Failed to read deployment config")?;
    let config: DeploymentConfig =
        serde_json::from_str(&content).context("Failed to parse deployment config")?;

    info!("Starting installation...");

    match run_installation_flow(&config) {
        Ok(_) => {
            info!("Success! Boot entry installed.");
            info!("Run 'reboot' to start the Mimic Alpine Rescue System.");
            Ok(())
        }
        Err(e) => {
            error!("Installation failed: {:#}", e);
            warn!("Rolling back changes due to installation failure...");

            if let Err(cleanup_err) = perform_cleanup() {
                error!("CRITICAL: Failed to rollback changes: {:#}", cleanup_err);
            } else {
                info!("Rollback successful. System restored to clean state.");
            }

            Err(e)
        }
    }
}

fn run_installation_flow(config: &DeploymentConfig) -> Result<()> {
    // 1. Setup /boot directory structure
    let boot_root = Path::new("/boot/mimic");
    setup_directories(boot_root)?;

    // 2. Download/Install Alpine Base
    let (alp_kernel, alp_initrd) = install_alpine(boot_root)?;

    // 3. Generate Alpine Overlay (Network + Auth + Setup Script)
    let alp_overlay = generate_alpine_overlay(boot_root, config)?;

    // 4. Probe Host Bootloader
    let loader = probe_bootloader();
    info!("Detected Bootloader: {:?}", loader);

    // Build Kernel Command Line
    let cmdline = build_kernel_cmdline(config)?;
    info!("Generated Kernel Command Line:\n  {}", cmdline);

    // 5. Register Boot Entry
    register_boot_entry(
        &loader,
        "Mimic Alpine Rescue System",
        &alp_kernel,
        &alp_initrd,
        &alp_overlay,
        &cmdline,
    )?;

    Ok(())
}

fn perform_cleanup() -> Result<()> {
    info!("Starting cleanup/uninstall process...");

    // 1. Probe bootloader to know what to clean
    let loader = probe_bootloader();
    info!("Detected Bootloader: {:?}", loader);

    // 2. Remove Boot Entry
    // We match the label used in register_boot_entry
    remove_boot_entry(&loader, "Mimic Alpine Rescue System")?;

    // 3. Remove /boot/mimic directory
    let boot_root = Path::new("/boot/mimic");
    if boot_root.exists() {
        info!("Removing files at {}...", boot_root.display());
        fs::remove_dir_all(boot_root).context("Failed to remove /boot/mimic directory")?;
    } else {
        info!("{} does not exist, nothing to delete.", boot_root.display());
    }

    info!("Cleanup complete. Mimic Alpine Rescue System has been removed.");
    Ok(())
}

fn build_kernel_cmdline(config: &DeploymentConfig) -> Result<String> {
    let mut parts: Vec<String> = Vec::new();

    // Base modules and console settings - IMPORTANT: pkgs=linux-virt is needed for proper module support
    parts.push("modules=loop,squashfs,sd-mod,usb-storage".to_string());
    parts.push("quiet".to_string());
    parts.push("console=tty0".to_string());
    parts.push("pkgs=openssh".to_string()); // Install kernel modules and sshd
                                            // Reduced memory usage - modloop is loaded from disk/ram, handled by alpine init

    // Point to the overlay file we packed inside the initrd
    parts.push("apkovl=/kexec.apkovl.tar.gz".to_string());

    // Enable networking for apk add
    parts.push("alpine_repo=http://dl-cdn.alpinelinux.org/alpine/v3.21/main".to_string());

    // Network Config (ip=...)
    // Syntax: ip=client-ip:server-ip:gw-ip:netmask:hostname:device:autoconf:dns0-ip:dns1-ip

    // Find the first interface with a valid IPv4 address
    let ipv4_iface = config.network.interfaces.iter().find(|iface| {
        iface
            .addresses
            .iter()
            .any(|a| a.contains('.') && !a.starts_with("127."))
    });

    if let Some(iface) = ipv4_iface {
        // Use IPv4
        let addr = iface.addresses.iter().find(|a| a.contains('.')).unwrap(); // confirmed exists
        let parts_addr: Vec<&str> = addr.split('/').collect();
        let ip = parts_addr[0].to_string();
        let prefix = parts_addr
            .get(1)
            .unwrap_or(&"24")
            .parse::<u32>()
            .unwrap_or(24);
        let netmask = cidr_to_netmask(prefix)?;

        let gw = iface.gateway.clone();
        let device = iface.name.clone();
        let dns1 = config.network.dns.get(0).cloned();
        let dns2 = config.network.dns.get(1).cloned();

        let ip_config = KernelIpConfig {
            client_ip: Some(ip),
            gw_ip: gw,
            netmask: Some(netmask),
            hostname: Some("alpine-rescue".to_string()),
            device: Some(device),
            autoconf: Some("off".to_string()),
            dns0: dns1,
            dns1: dns2,
            ..Default::default()
        };

        parts.push(ip_config.to_string());
    } else {
        // Fallback: Check for IPv6
        let ipv6_iface = config.network.interfaces.iter().find(|iface| {
            iface
                .addresses
                .iter()
                .any(|a| a.contains(':') && !a.starts_with("::1"))
        });

        if let Some(iface) = ipv6_iface {
            // Use IPv6
            let addr = iface.addresses.iter().find(|a| a.contains(':')).unwrap();

            // addr format is "ip/prefix" from mimic-gen
            let addr_parts: Vec<&str> = addr.split('/').collect();
            let ip_part = addr_parts[0];
            let prefix_part = addr_parts.get(1).unwrap_or(&""); // e.g. "64"

            let gw = iface.gateway6.as_deref().unwrap_or("");
            let gw_str = if gw.is_empty() {
                None
            } else {
                Some(gw.to_string())
            };

            let device = iface.name.clone();
            let dns1 = config.network.dns.get(0).cloned();
            let dns2 = config.network.dns.get(1).cloned();

            // Format for IPv6 Client IP: [addr]
            // We pass raw IP in brackets. We pass prefix in 'netmask' field?
            // Or we pass [ip/prefix] in client_ip and leave netmask empty?
            // To be safe and "parse" it as requested, we handle them.
            // Many init scripts accept [ip/prefix] as client_ip.
            // But let's try to keep fields clean: client_ip=[ip], netmask=prefix.
            let client_ip = ip_part.to_string();
            let netmask_str = if prefix_part.is_empty() {
                None
            } else {
                Some(prefix_part.to_string())
            };

            let ip_config = KernelIpConfig {
                client_ip: Some(client_ip),
                gw_ip: gw_str,
                netmask: netmask_str,
                hostname: Some("alpine-rescue".to_string()),
                device: Some(device),
                autoconf: Some("off".to_string()),
                dns0: dns1,
                dns1: dns2,
                ..Default::default()
            };

            parts.push(ip_config.to_string());
        } else {
            // Fallback to DHCP if no suitable static config found
            parts.push(KernelIpConfig::dhcp().to_string());
        }
    }

    Ok(parts.join(" "))
}

fn cidr_to_netmask(prefix: u32) -> Result<String> {
    if prefix > 32 {
        anyhow::bail!("Invalid CIDR prefix: {}", prefix);
    }
    if prefix == 0 {
        return Ok("0.0.0.0".to_string());
    }
    let mask = !0u32 << (32 - prefix);
    let octets = mask.to_be_bytes();
    Ok(format!(
        "{}.{}.{}.{}",
        octets[0], octets[1], octets[2], octets[3]
    ))
}

fn setup_directories(root: &Path) -> Result<()> {
    fs::create_dir_all(root.join("alpine"))?;
    Ok(())
}

fn download_file(url: &str, path: &Path) -> Result<()> {
    info!("Downloading {} -> {} ...", url, path.display());
    let resp = ureq::get(url)
        .call()
        .context("Failed to make HTTP request")?;
    let mut reader = resp.into_body().into_reader();
    let mut file = File::create(path)?;
    io::copy(&mut reader, &mut file)?;
    Ok(())
}

fn install_alpine(root: &Path) -> Result<(PathBuf, PathBuf)> {
    let alpine_dir = root.join("alpine");
    let kernel_dest = alpine_dir.join("vmlinuz");
    let initrd_dest = alpine_dir.join("initramfs");
    let modloop_dest = alpine_dir.join("modloop-virt");
    let repo_marker = alpine_dir.join(".boot_repository");

    if !kernel_dest.exists() {
        download_file(ALPINE_KERNEL_URL, &kernel_dest)?;
    }

    if !initrd_dest.exists() {
        download_file(ALPINE_INITRD_URL, &initrd_dest)?;
        // Patch the just-downloaded initrd
        patch_alpine_init(&initrd_dest)?;
    } else {
        info!("Initrd exists. Applying patch to ensure robustness...");
        patch_alpine_init(&initrd_dest)?;
    }

    if !modloop_dest.exists() {
        download_file(ALPINE_MODLOOP_URL, &modloop_dest)?;
    }

    if !repo_marker.exists() {
        fs::write(&repo_marker, "")?;
    }

    Ok((kernel_dest, initrd_dest))
}

fn patch_alpine_init(initrd_path: &Path) -> Result<()> {
    info!("Patching Mimic Alpine init script (Streaming)...");

    // We will do a streaming patch: Read -> Decompress -> Parse CPIO -> Modify 'init' -> Write CPIO -> Compress -> Write

    let input_file = File::open(initrd_path)?;
    let decoder = GzDecoder::new(input_file);
    let mut reader = CpioReader::new(io::BufReader::new(decoder));

    // Temp output
    let temp_path = initrd_path.with_extension("tmp");
    let output_file = File::create(&temp_path)?;
    let encoder = GzEncoder::new(output_file, Compression::default());
    let mut writer = CpioWriter::new(encoder);

    while let Some(entry) = reader.next_entry()? {
        if entry.name == "init" {
            let content_str = std::str::from_utf8(&entry.content).unwrap_or("");
            // Patch 1: Change IFS to comma to allow IPv6 addresses
            let mut patched = content_str.replace("local IFS=':'", "local IFS=','");

            // Patch 2: Conditional IP assignment & Disable IPv6 Autoconf
            // We disable RA/Autoconf on the specific interface to prevent SLAAC pollution.
            // Then we use `ifconfig` for IPv4 and `ip addr` for IPv6.
            let ip_assign_logic = "
                if [ -w /proc/sys/net/ipv6/conf/\"$iface\"/accept_ra ]; then
                    echo 0 > /proc/sys/net/ipv6/conf/\"$iface\"/accept_ra
                    echo 0 > /proc/sys/net/ipv6/conf/\"$iface\"/autoconf
                fi
                
                if echo \"$netmask\" | grep -q \"\\.\"; then
                    ifconfig \"$iface\" \"$client_ip\" netmask \"$netmask\"
                else
                    ip addr add \"$client_ip/$netmask\" dev \"$iface\"
                fi";

            patched = patched.replace(
                "ifconfig \"$iface\" \"$client_ip\" netmask \"$netmask\"",
                ip_assign_logic,
            );

            // Patch 3: IPv6-aware routing with onlink fallback
            // We verify if gw_ip is IPv6 (contains :)
            let route_logic = "if [ -n \"$gw_ip\" ]; then
                if echo \"$gw_ip\" | grep -q \":\"; then
                    ip -6 route add default via \"$gw_ip\" dev \"$iface\" || ip -6 route add default via \"$gw_ip\" dev \"$iface\" onlink
                else
                    ip route add default via \"$gw_ip\" dev \"$iface\"
                fi
            fi";

            // The original script line for routing:
            // [ -z "$gw_ip" ] || ip route add 0.0.0.0/0 via "$gw_ip" dev "$iface"
            patched = patched.replace(
                "[ -z \"$gw_ip\" ] || ip route add 0.0.0.0/0 via \"$gw_ip\" dev \"$iface\"",
                route_logic,
            );

            if content_str == patched {
                // If direct match failed, it might be due to our previous incomplete patch or whitespace.
                // However, since we are patching the *original* downloaded file every time (if we don't cache it patched),
                // or if we restart the process.
                // NOTE: The previous tool execution might have left the code in a state where we are looking at the *source code* of the tool,
                // but at runtime `install_alpine` downloads a fresh initrd if it doesn't exist.
                // If it exists, we patch it. If it was ALREADY patched by a previous run, these replace calls might fail if they don't match.
                // But `install_alpine` calls `patch_alpine_init` on the file.
                // To be safe, we should warn but NOT fail if we can't patch, unless we are sure it's the raw file.
                // Because of the 'replace' method, we can't easily detect "already patched" unless we check for the new string.
                if patched.contains("IFS=','") && patched.contains("ip -6 route") {
                    info!("Init script appears to be already patched.");
                    writer.write_entry(&entry.name, patched.as_bytes(), entry.mode)?;
                } else {
                    warn!("Could not find strict match for patching 'init'. It might have changed source or be already patched in an unrecognized way.");
                    // We write the original content if we couldn't patch strict matches,
                    // BUT we already performed the replacements on `patched`.
                    // If `replace` didn't find the string, `patched` == `content_str`.
                    writer.write_entry(&entry.name, patched.as_bytes(), entry.mode)?;
                }
            } else {
                info!("Patched 'init' network logic successfully (v2 - IPv4/v6 Hybrid).");
                writer.write_entry(&entry.name, patched.as_bytes(), entry.mode)?;
            }
        } else {
            writer.write_entry(&entry.name, &entry.content, entry.mode)?;
        }
    }

    // Finish
    let encoder = writer.finish()?;
    encoder.finish()?;

    // Replace original
    fs::rename(&temp_path, initrd_path)?;
    Ok(())
}

fn generate_alpine_overlay(root: &Path, config: &DeploymentConfig) -> Result<PathBuf> {
    info!("Generating Mimic Alpine Overlay (Network/Auth/Config) [Native]...");

    // Create directory structure in memory/temp for tar
    // But tar::Builder likes filesystem or explicit calls.
    // We will build the directory structure on disk to leverage `append_dir_all` easily,
    // or we can manually add entries to tar builder.
    // Building on disk is safer for complex nested structures and permissions.

    let temp_dir = root.join("temp_apkovl_src");
    if temp_dir.exists() {
        fs::remove_dir_all(&temp_dir)?;
    }
    debug!("Temp dir cleared");

    let etc = temp_dir.join("etc");
    fs::create_dir_all(etc.join("network"))?;
    fs::create_dir_all(etc.join("local.d"))?;
    fs::create_dir_all(etc.join("runlevels/default"))?;
    debug!("Etc structure created");

    let root_home = temp_dir.join("root");
    let ssh_dir = root_home.join(".ssh");
    fs::create_dir_all(&ssh_dir)?;
    debug!("SSH dir created");

    // Set strict permissions
    // Note: tar crate usually preserves FS permissions if added from FS.
    // We set them on FS first.
    let set_perm = |p: &Path, mode: u32| -> Result<()> {
        let mut perms = fs::metadata(p)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(p, perms)?;
        Ok(())
    };

    set_perm(&ssh_dir, 0o700)?;

    // 1. Network
    let mut iface_content = String::from("auto lo\niface lo inet loopback\n");
    for iface in &config.network.interfaces {
        iface_content.push_str(&format!("\nauto {}\n", iface.name));

        // Separate IPv4 and IPv6 addresses
        let mut ipv4_addrs = Vec::new();
        let mut ipv6_addrs = Vec::new();

        for addr in &iface.addresses {
            if addr.contains(':') {
                ipv6_addrs.push(addr);
            } else {
                ipv4_addrs.push(addr);
            }
        }

        // Configure IPv4
        if !ipv4_addrs.is_empty() {
            iface_content.push_str(&format!("iface {} inet static\n", iface.name));
            for addr in ipv4_addrs {
                iface_content.push_str(&format!("\taddress {}\n", addr));
            }
            if let Some(gw) = &iface.gateway {
                iface_content.push_str(&format!("\tgateway {}\n", gw));
            }
        }

        // Configure IPv6
        if !ipv6_addrs.is_empty() {
            iface_content.push_str(&format!("iface {} inet6 static\n", iface.name));
            for addr in ipv6_addrs {
                iface_content.push_str(&format!("\taddress {}\n", addr));
            }
            if let Some(gw6) = &iface.gateway6 {
                iface_content.push_str(&format!("\tgateway {}\n", gw6));
            }
        }
    }
    if !config.network.dns.is_empty() {
        let mut resolv = String::new();
        for dns in &config.network.dns {
            resolv.push_str(&format!("nameserver {}\n", dns));
        }
        fs::write(etc.join("resolv.conf"), resolv)?;
    }
    fs::write(etc.join("network/interfaces"), iface_content)?;
    debug!("Network config written");

    // 2. Auth
    if !config.auth.ssh_authorized_keys.is_empty() {
        let keys = config.auth.ssh_authorized_keys.join("\n");
        let authorized_keys_path = ssh_dir.join("authorized_keys");
        fs::write(&authorized_keys_path, keys)?;
        set_perm(&authorized_keys_path, 0o600)?;

        let _ = std::os::unix::fs::symlink("/etc/init.d/sshd", etc.join("runlevels/default/sshd"));
    }

    if let Some(hash) = &config.auth.root_password_hash {
        fs::write(etc.join("root_password_hash"), hash)?;
        if config.auth.ssh_authorized_keys.is_empty() {
            let _ =
                std::os::unix::fs::symlink("/etc/init.d/sshd", etc.join("runlevels/default/sshd"));
        }
    }
    debug!("Auth config written");

    // 3. Setup Script
    let script_path = etc.join("local.d/setup.start");
    // Use the template file included at compile time
    let script = include_str!("../templates/setup.start");

    fs::write(&script_path, script)?;
    set_perm(&script_path, 0o755)?;
    debug!("Setup script written");

    // Symlink local service
    if let Err(e) =
        std::os::unix::fs::symlink("/etc/init.d/local", etc.join("runlevels/default/local"))
    {
        warn!("Failed to symlink local service: {}", e);
    } else {
        debug!("Symlinked local service");
    }

    // Prepare kexec.apkovl.tar.gz in memory (or temp file)
    let tar_gz_path = root.join("temp_kexec.apkovl.tar.gz");
    {
        info!("Creating tar.gz at {}", tar_gz_path.display());
        let tar_file = File::create(&tar_gz_path).context("Failed to create tar.gz file")?;
        let enc = GzEncoder::new(tar_file, Compression::default());
        let mut tar = tar::Builder::new(enc);
        tar.follow_symlinks(false);

        debug!("Appending dir all from {}", temp_dir.display());

        // Debug: List contents
        if let Ok(entries) = fs::read_dir(&temp_dir) {
            for entry in entries.flatten() {
                debug!(" - {:?}", entry.path());
                if let Ok(sub) = fs::read_dir(entry.path()) {
                    for sub_entry in sub.flatten() {
                        debug!("   - {:?}", sub_entry.path());
                    }
                }
            }
        }

        // Add content FROM temp_dir, but we want the content to be relative to root
        match tar.append_dir_all(".", &temp_dir) {
            Ok(_) => debug!("Appended dir all successfully"),
            Err(e) => {
                error!("Error appending dir: {:?}", e);
                return Err(e.into());
            }
        }
        tar.finish().context("Failed to finish tar")?;
    }
    debug!("Tar.gz created and closed");

    fs::remove_dir_all(&temp_dir)?;
    debug!("Temp dir removed");

    // Now wrap this single file into a new CPIO (gzipped)
    let overlay_path = root.join("alpine/alpine-overlay.cpio.gz");
    info!("Creating overlay CPIO at {}", overlay_path.display());
    let overlay_file = File::create(&overlay_path).context("Failed to create overlay CPIO file")?;
    let enc = GzEncoder::new(overlay_file, Compression::default());
    let mut writer = CpioWriter::new(enc);

    // Read the tar content
    debug!("Reading tar content from {}", tar_gz_path.display());
    let tar_content = fs::read(&tar_gz_path).context("Failed to read tar.gz file")?;

    debug!("Removing tar.gz file");
    fs::remove_file(&tar_gz_path)?;

    // We only put ONE file in the CPIO: "kexec.apkovl.tar.gz"
    // IMPORTANT: It must be at the root of the CPIO.
    debug!("Writing entry to CPIO");
    writer.write_entry("kexec.apkovl.tar.gz", &tar_content, 0o100644)?;

    let encoder = writer.finish()?; // Finish CPIO
    encoder.finish()?; // Finish Gzip
    info!("Overlay CPIO created at {}", overlay_path.display());

    Ok(overlay_path)
}
