# Mimic Project Roadmap

This document outlines the potential future directions and planned improvements for the Mimic project.

## 1. Robustness & Reliability

### Configurable Alpine Version
*   **Current Status**: The Alpine Linux version and download URLs (v3.21.0) are hardcoded in `mimic-apply`.
*   **Goal**: Allow users to specify the Alpine version or custom mirror URLs in `deployment.json` or via CLI arguments. This ensures the tool remains usable even if the default version becomes obsolete or the URL changes.

### Secure Downloads
*   **Current Status**: Files are downloaded via HTTP/HTTPS without checksum verification.
*   **Goal**: Implement SHA256 checksum verification for all downloaded artifacts (`vmlinuz`, `initramfs`, `modloop`) to prevent corrupted or malicious downloads.

### Improved Initramfs Patching
*   **Current Status**: `mimic-apply` patches the Alpine `init` script using string replacement. This is brittle and may break if Alpine changes the script content.
*   **Goal**:
    *   Implement a more robust patching mechanism, possibly by verifying the hash of the `init` script before patching.
    *   Alternatively, explore injecting a custom hook or script that runs independently of the main `init` script modifications.

## 2. Advanced Networking Support

### VLAN Support
*   **Current Status**: `mimic-gen` detects interfaces but may not correctly capture or recreate VLAN configurations (e.g., `eth0.100`).
*   **Goal**: Detect VLAN interfaces on the host and generate the appropriate configuration (loading `8021q` module, creating VLAN devices) in the rescue system.

### Bonding & LACP
*   **Current Status**: Bonded interfaces are treated as standard interfaces. The rescue system might fail to bring up the network if the switch expects LACP.
*   **Goal**: Detect bonding configurations (`/proc/net/bonding` or `ip -d link`) and configure the rescue system to assemble the bond before bringing up the IP.

### Bridge Support
*   **Current Status**: Similar to bonding, bridge interfaces are not explicitly handled.
*   **Goal**: Support recreating bridge interfaces to maintain connectivity in complex virtualization setups.

## 3. Testing & Quality Assurance

### Unit Tests
*   **Current Status**: No unit tests are currently present.
*   **Goal**: Add unit tests for `mimic-gen`, specifically for the network parsing logic. Mocking `ip` command output will allow testing edge cases without changing the host network.

### Integration Tests
*   **Current Status**: A Docker environment exists, but no automated integration tests are defined.
*   **Goal**: Create a test suite that runs in the Docker environment to verify:
    *   Configuration generation (`mimic-gen`).
    *   Artifact downloading and patching (`mimic-apply`).
    *   Simulated boot verification (if possible via QEMU inside Docker or similar).

## 4. Bootloader Support

### Expanded Compatibility
*   **Current Status**: Supports GRUB and Systemd-boot.
*   **Goal**: Add support for other bootloaders such as:
    *   **Syslinux/Extlinux**
    *   **Refind**
    *   **EFI Stub** (direct loading from UEFI)

## 5. User Experience

### Interactive CLI Improvements
*   **Current Status**: Basic interactive prompts.
*   **Goal**: Provide a more rich TUI (Terminal User Interface) for selecting interfaces, editing configurations before generation, and viewing logs.

### Cleanup Robustness
*   **Current Status**: `clean.sh` relies on `mimic-apply` to remove files.
*   **Goal**: Ensure cleanup handles edge cases (e.g., if the config file is missing but the files remain in `/boot`).
