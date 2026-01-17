use anyhow::{Context, Result};
use clap::Parser;
use inquire::{Confirm, Password, Text};
use log::{info, warn};
use mimic_shared::{AuthConfig, DeploymentConfig, InterfaceConfig, NetworkConfig};
use pwhash::sha512_crypt;
use std::fs;
use std::process::Command;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "deployment.json")]
    output: String,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    info!("========================================");
    info!("Mimic Alpine Deployment Generator");
    info!("========================================");

    if fs::metadata(&cli.output).is_ok() {
        let overwrite = Confirm::new(&format!("{} already exists. Overwrite?", cli.output))
            .with_default(false)
            .prompt()?;
        if !overwrite {
            info!("Skipping generation.");
            return Ok(());
        }
    }

    // 1. Configure Host Network
    let network_config = generate_network_config()?;

    // 2. Configure Auth
    let auth_config = generate_auth_config()?;

    let config = DeploymentConfig {
        network: network_config,
        auth: auth_config,
    };

    let json = serde_json::to_string_pretty(&config)?;
    fs::write(&cli.output, json)?;

    info!("Configuration written to {}", cli.output);
    info!("Next step: Run 'run.sh' to deploy/boot.");
    Ok(())
}

fn generate_network_config() -> Result<NetworkConfig> {
    info!("\nScanning network interfaces...");

    // We keep the ip command usage. Ensure the host has 'ip' command.
    let output = Command::new("ip")
        .args(["-j", "link", "show"])
        .output()
        .context("Failed to execute ip link")?;

    let links: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;

    let output = Command::new("ip")
        .args(["-j", "addr", "show"])
        .output()
        .context("Failed to execute ip addr")?;

    let addrs: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;

    let output = Command::new("ip")
        .args(["-j", "route", "show", "default"])
        .output()
        .context("Failed to execute ip route")?;
    let ipv4_routes: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).unwrap_or_default();

    let output = Command::new("ip")
        .args(["-j", "-6", "route", "show", "default"])
        .output()
        .context("Failed to execute ip -6 route")?;
    let ipv6_routes: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).unwrap_or_default();

    let mut interfaces = Vec::new();

    for link in links {
        let ifname = link["ifname"].as_str().unwrap_or_default();
        let mac = link["address"].as_str().unwrap_or_default();

        if ifname == "lo" || mac == "00:00:00:00:00:00" || mac.is_empty() {
            continue;
        }

        info!("Found interface: {} ({})", ifname, mac);

        let mut iface_config = InterfaceConfig {
            name: ifname.to_string(),
            mac: mac.to_string(),
            addresses: Vec::new(),
            gateway: None,
            gateway6: None,
        };

        if let Some(addr_entry) = addrs.iter().find(|a| a["ifname"].as_str() == Some(ifname)) {
            if let Some(addr_infos) = addr_entry["addr_info"].as_array() {
                for info in addr_infos {
                    let scope = info["scope"].as_str().unwrap_or("");
                    if scope == "global" {
                        let local = info["local"].as_str().unwrap_or("");
                        let prefix = info["prefixlen"].as_u64().unwrap_or(0);
                        if !local.is_empty() {
                            iface_config.addresses.push(format!("{}/{}", local, prefix));
                        }
                    }
                }
            }
        }

        if let Some(route) = ipv4_routes
            .iter()
            .find(|r| r["dev"].as_str() == Some(ifname))
        {
            if let Some(gw) = route["gateway"].as_str() {
                iface_config.gateway = Some(gw.to_string());
            }
        }

        if let Some(route) = ipv6_routes
            .iter()
            .find(|r| r["dev"].as_str() == Some(ifname))
        {
            if let Some(gw) = route["gateway"].as_str() {
                iface_config.gateway6 = Some(gw.to_string());
            }
        }

        if !iface_config.addresses.is_empty() {
            interfaces.push(iface_config);
        }
    }

    let resolv = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let dns: Vec<String> = resolv
        .lines()
        .filter(|l| l.starts_with("nameserver"))
        .map(|l| l.split_whitespace().nth(1).unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Ok(NetworkConfig { interfaces, dns })
}

fn generate_auth_config() -> Result<AuthConfig> {
    info!("\nConfiguring Authentication...");
    let mut auth = AuthConfig::default();

    let use_password = Confirm::new("Use password login?")
        .with_default(true)
        .prompt()?;

    if use_password {
        let password = Password::new("Enter root password (leave empty for random):")
            .with_display_mode(inquire::PasswordDisplayMode::Masked)
            .without_confirmation()
            .prompt();

        let password = password.unwrap_or_default();

        let final_pass = if password.is_empty() {
            use rand::distr::{Alphanumeric, SampleString};
            let s = Alphanumeric.sample_string(&mut rand::rng(), 12);
            info!("Generated random password: {}", s);
            s
        } else {
            password
        };

        // Use pwhash to generate SHA512-crypt hash (compatible with Linux shadow)
        if !final_pass.is_empty() {
            let hash = sha512_crypt::hash(&final_pass)?;
            auth.root_password_hash = Some(hash);
        }
    }

    let use_local_keys = Confirm::new("Use local SSH keys (~/.ssh/authorized_keys)?")
        .with_default(true)
        .prompt()?;

    if use_local_keys {
        let home = std::env::var("HOME").unwrap_or_default();
        let path = format!("{}/.ssh/authorized_keys", home);
        if let Ok(content) = fs::read_to_string(&path) {
            auth.ssh_authorized_keys = content.lines().map(String::from).collect();
            info!(
                "Loaded {} keys from {}",
                auth.ssh_authorized_keys.len(),
                path
            );
        } else {
            warn!("Could not read {}", path);
        }
    } else {
        let key = Text::new("Enter SSH public key (optional):").prompt()?;
        if !key.trim().is_empty() {
            auth.ssh_authorized_keys.push(key);
        }
    }

    Ok(auth)
}
