use anyhow::{Context, Result};
use log::{info, warn};
use mimic_shared::BootloaderType;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, PartialEq)]
pub enum FileSystem {
    Btrfs,
    Ext4,
    Xfs,
    Zfs,
    Fat,
    Unknown(String),
}

pub struct FsResolver;

impl FsResolver {
    /// Detects the filesystem type for a given path
    pub fn detect(path: &Path) -> FileSystem {
        if let Ok(output) = Command::new("stat")
            .args(["-f", "-c", "%T"])
            .arg(path)
            .output()
        {
            let type_str = String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_lowercase();
            return match type_str.as_str() {
                "btrfs" => FileSystem::Btrfs,
                "ext2/ext3" | "ext2" | "ext3" | "ext4" => FileSystem::Ext4,
                "xfs" => FileSystem::Xfs,
                "zfs" => FileSystem::Zfs,
                "msdos" | "vfat" => FileSystem::Fat,
                s => FileSystem::Unknown(s.to_string()),
            };
        }
        FileSystem::Unknown("detection_failed".to_string())
    }

    /// Returns a list of candidate paths for GRUB/Bootloaders
    pub fn resolve_candidates(path: &Path) -> Vec<String> {
        let fs_type = Self::detect(path);
        let mut candidates = Vec::new();
        let abs_path = path.display().to_string();

        // 1. Always rely on grub-probe if available as primary source of truth
        if let Ok(output) = Command::new("grub-probe")
            .arg("--target=path")
            .arg(path)
            .output()
        {
            if output.status.success() {
                let probed = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !probed.is_empty() {
                    candidates.push(probed);
                }
            }
        }

        // 2. Add absolute path as fallback
        candidates.push(abs_path.clone());

        // 3. Dispatch specialized logic based on FS
        match fs_type {
            FileSystem::Btrfs => {
                // Strategy A: If /boot is a separate partition
                if let Ok(stripped) = path.strip_prefix("/boot") {
                    candidates.push(Path::new("/").join(stripped).display().to_string());
                }

                // Strategy B: Common Subvolume layouts
                candidates.push(format!("/root{}", abs_path));
                candidates.push(format!("/@{}", abs_path));

                if abs_path.starts_with("/boot") {
                    candidates.push(format!("/@{}", abs_path));
                    candidates.push(format!("/root{}", abs_path));
                }
            }
            FileSystem::Zfs => {
                if let Ok(stripped) = path.strip_prefix("/boot") {
                    candidates.push(Path::new("/").join(stripped).display().to_string());
                }
            }
            _ => {
                if let Ok(stripped) = path.strip_prefix("/boot") {
                    candidates.push(Path::new("/").join(stripped).display().to_string());
                }
            }
        }

        candidates.sort();
        candidates.dedup();
        candidates
    }
}

pub fn probe_bootloader() -> BootloaderType {
    if Path::new("/sys/firmware/efi").exists() {
        if Path::new("/boot/loader/loader.conf").exists() {
            return BootloaderType::SystemdBoot;
        }
        if Path::new("/boot/grub/grub.cfg").exists() || Path::new("/boot/grub2/grub.cfg").exists() {
            return BootloaderType::Grub;
        }
        return BootloaderType::Efi;
    }
    if Path::new("/boot/grub/grub.cfg").exists() || Path::new("/boot/grub2/grub.cfg").exists() {
        return BootloaderType::Grub;
    }
    BootloaderType::Unknown
}

pub fn register_boot_entry(
    loader: &BootloaderType,
    label: &str,
    kernel: &Path,
    initrd: &Path,
    overlay: &Path,
    cmdline: &str,
) -> Result<()> {
    let i_name = initrd.file_name().unwrap().to_string_lossy();
    let o_name = overlay.file_name().unwrap().to_string_lossy();

    match loader {
        BootloaderType::Grub => {
            let grub_dir = if Path::new("/boot/grub").exists() {
                Path::new("/boot/grub")
            } else {
                Path::new("/boot/grub2")
            };
            let custom_cfg = grub_dir.join("custom.cfg");
            let grub_cfg = grub_dir.join("grub.cfg");

            let candidates = FsResolver::resolve_candidates(kernel);
            info!("Generated specific search paths: {:?}", candidates);

            let mut search_block = String::new();
            search_block.push_str("    # Search for the Mimic Alpine kernel in candidate paths\n");

            for (i, full_k) in candidates.iter().enumerate() {
                let k_path_obj = Path::new(full_k);
                let parent = k_path_obj.parent().unwrap_or(Path::new("/"));
                let full_i = parent.join(i_name.as_ref()).to_string_lossy().to_string();
                let full_o = parent.join(o_name.as_ref()).to_string_lossy().to_string();

                let check = if i == 0 { "if" } else { "elif" };
                search_block.push_str(&format!(
                    r#"    {} search --no-floppy --file --set=root {}; then
        set kern="{}"
        set init="{}"
        set ovl="{}"
"#,
                    check, full_k, full_k, full_i, full_o
                ));
            }

            search_block.push_str(
                r#"    else
        echo "Error: Mimic Alpine kernel not found in known paths."
        echo "Tried:"
"#,
            );
            for full_k in &candidates {
                search_block.push_str(&format!("        echo \"  {}\"\n", full_k));
            }
            search_block.push_str(
                r#"        sleep 10
        halt
    fi
"#,
            );

            let entry_script = format!(
                r#"
{search_logic}
    echo "Loading Mimic Alpine..."
    echo "Kernel: $kern"
    linux $kern {cmdline}
    initrd $init $ovl
"#,
                search_logic = search_block,
                cmdline = cmdline
            );

            let entry = format!(
                r#"
menuentry "{}" {{
{}
}}
"#,
                label, entry_script
            );

            fs::write(&custom_cfg, entry)?;
            info!("Updated GRUB custom.cfg");

            if grub_cfg.exists() {
                let content = fs::read_to_string(&grub_cfg)?;
                if !content.contains("custom.cfg") {
                    info!("Appending source custom.cfg to grub.cfg");
                    let mut file = fs::OpenOptions::new().append(true).open(&grub_cfg)?;
                    writeln!(file, "\n# Added by alpine")?;
                    writeln!(file, "source $prefix/custom.cfg")?;
                    writeln!(file, "source $config_directory/custom.cfg")?;
                }
            }

            let status = Command::new("grub-reboot").arg(label).status();
            match status {
                Ok(s) if s.success() => info!("Next boot set to '{}' (grub-reboot)", label),
                _ => {
                    let status2 = Command::new("grub2-reboot").arg(label).status();
                    match status2 {
                        Ok(s) if s.success() => {
                            info!("Next boot set to '{}' (grub2-reboot)", label)
                        }
                        _ => warn!("Failed to set next boot entry automatically."),
                    }
                }
            }
        }
        BootloaderType::SystemdBoot => {
            let conf_path = Path::new("/boot/loader/entries/mimic-alpine.conf");
            let k_path = if let Ok(stripped) = kernel.strip_prefix("/boot") {
                stripped
            } else {
                kernel
            };
            let i_path = if let Ok(stripped) = initrd.strip_prefix("/boot") {
                stripped
            } else {
                initrd
            };
            let o_path = if let Ok(stripped) = overlay.strip_prefix("/boot") {
                stripped
            } else {
                overlay
            };

            let content = format!(
                "title {}\nlinux {}\ninitrd {}\ninitrd {}\noptions {}\n",
                label,
                k_path.display(),
                i_path.display(),
                o_path.display(),
                cmdline
            );
            fs::write(conf_path, content)?;
            info!("Created systemd-boot entry: {:?}", conf_path);
            let _ = Command::new("bootctl")
                .args(["set-oneshot", "mimic-alpine.conf"])
                .status();
        }
        BootloaderType::Efi => {
            info!("Detected Generic EFI. Registering via efibootmgr...");

            if let Ok(output) = Command::new("efibootmgr").output() {
                let out = String::from_utf8_lossy(&output.stdout);
                for line in out.lines() {
                    if line.contains(label) {
                        if let Some(start) = line.find("Boot") {
                            let id_part = &line[start + 4..];
                            if id_part.len() >= 4 {
                                let id = &id_part[0..4];
                                info!("Removing old EFI entry Boot{}", id);
                                let _ = Command::new("efibootmgr").args(["-b", id, "-B"]).status();
                            }
                        }
                    }
                }
            }

            let output = Command::new("findmnt")
                .args(["-n", "-o", "SOURCE", "--target"])
                .arg(kernel)
                .output()
                .context("Failed to find mountpoint source")?;
            let part_dev = String::from_utf8_lossy(&output.stdout).trim().to_string();

            let output = Command::new("lsblk")
                .args(["-no", "PKNAME,PARTN"])
                .arg(&part_dev)
                .output()
                .context("Failed to get disk info")?;
            let out_str = String::from_utf8_lossy(&output.stdout);
            let tokens: Vec<&str> = out_str.split_whitespace().collect();
            if tokens.len() < 2 {
                anyhow::bail!("Could not parse partition info for {}", part_dev);
            }
            let disk_dev = format!("/dev/{}", tokens[0]);
            let part_num = tokens[1];

            let output = Command::new("findmnt")
                .args(["-n", "-o", "TARGET", "--target"])
                .arg(kernel)
                .output()?;
            let mountpoint = String::from_utf8_lossy(&output.stdout).trim().to_string();

            let to_efi_path = |p: &Path| -> String {
                let s = p.strip_prefix(&mountpoint).unwrap_or(p).to_string_lossy();
                let s = s.replace("/", "\\");
                if !s.starts_with('\\') {
                    format!("\\{}", s)
                } else {
                    s
                }
            };

            let k_efi = to_efi_path(kernel);
            let i_efi = to_efi_path(initrd);
            let o_efi = to_efi_path(overlay);

            let output = Command::new("efibootmgr").output()?;
            let out = String::from_utf8_lossy(&output.stdout);
            let old_order = out.lines().find(|l| l.starts_with("BootOrder:")).map(|l| {
                l.split_once(':')
                    .map(|(_, v)| v.trim().to_string())
                    .unwrap_or_default()
            });

            let args = format!("initrd={} initrd={} {}", i_efi, o_efi, cmdline);

            info!("Creating EFI entry on {} partition {}", disk_dev, part_num);
            let status = Command::new("efibootmgr")
                .arg("-c")
                .arg("-d")
                .arg(&disk_dev)
                .arg("-p")
                .arg(part_num)
                .arg("-L")
                .arg(label)
                .arg("-l")
                .arg(&k_efi)
                .arg("-u")
                .arg(&args)
                .status()?;

            if !status.success() {
                anyhow::bail!("efibootmgr failed to create entry");
            }

            let output = Command::new("efibootmgr").output()?;
            let out = String::from_utf8_lossy(&output.stdout);
            let new_order_line = out
                .lines()
                .find(|l| l.starts_with("BootOrder:"))
                .context("No BootOrder found")?;
            let new_ids: Vec<&str> = new_order_line
                .split_once(':')
                .map(|(_, v)| v.trim())
                .unwrap_or("")
                .split(',')
                .collect();
            let new_id = new_ids.first().context("Empty boot order")?;

            if let Some(order) = old_order {
                if !order.is_empty() {
                    info!("Restoring BootOrder to: {}", order);
                    let _ = Command::new("efibootmgr").arg("-o").arg(&order).status();
                }
            }

            info!("Setting BootNext to {}", new_id);
            let _ = Command::new("efibootmgr").arg("-n").arg(new_id).status();
        }
        _ => {
            warn!("Unknown bootloader. Please configure manually.");
        }
    }
    Ok(())
}

pub fn remove_boot_entry(loader: &BootloaderType, label: &str) -> Result<()> {
    info!("Removing boot entry for '{}'...", label);

    match loader {
        BootloaderType::Grub => {
            let grub_dir = if Path::new("/boot/grub").exists() {
                Path::new("/boot/grub")
            } else {
                Path::new("/boot/grub2")
            };
            let custom_cfg = grub_dir.join("custom.cfg");
            let grub_cfg = grub_dir.join("grub.cfg");

            if custom_cfg.exists() {
                info!("Removing GRUB custom config: {:?}", custom_cfg);
                fs::remove_file(&custom_cfg).context("Failed to remove custom.cfg")?;
            }

            // Optional: Try to clean up grub.cfg if we modified it
            if grub_cfg.exists() {
                let content = fs::read_to_string(&grub_cfg)?;
                if content.contains("# Added by alpine") {
                    info!("Cleaning up grub.cfg...");
                    let new_lines: Vec<&str> = content
                        .lines()
                        .filter(|line| {
                            !line.trim().contains("# Added by alpine")
                                && !line.trim().contains("source $prefix/custom.cfg")
                                && !line.trim().contains("source $config_directory/custom.cfg")
                        })
                        .collect();
                    // Join with newlines
                    let new_content = new_lines.join("\n") + "\n";
                    fs::write(&grub_cfg, new_content)?;
                }
            }
        }
        BootloaderType::SystemdBoot => {
            let conf_path = Path::new("/boot/loader/entries/mimic-alpine.conf");
            if conf_path.exists() {
                info!("Removing systemd-boot entry: {:?}", conf_path);
                fs::remove_file(conf_path).context("Failed to remove systemd-boot entry")?;
            }
        }
        BootloaderType::Efi => {
            info!("Cleaning up EFI entries via efibootmgr...");
            let output = Command::new("efibootmgr").output();
            if let Ok(output) = output {
                let out = String::from_utf8_lossy(&output.stdout);
                for line in out.lines() {
                    if line.contains(label) {
                        if let Some(start) = line.find("Boot") {
                            let id_part = &line[start + 4..];
                            if id_part.len() >= 4 {
                                let id = &id_part[0..4];
                                info!("Removing EFI entry Boot{}...", id);
                                let status =
                                    Command::new("efibootmgr").args(["-b", id, "-B"]).status();
                                match status {
                                    Ok(s) if s.success() => {
                                        info!("Recursively removed entry {}", id)
                                    }
                                    _ => warn!("Failed to remove entry {}", id),
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {
            warn!("Unknown bootloader type, cannot perform automatic cleanup.");
        }
    }

    Ok(())
}
