use std::fmt;

/// Reference: https://www.kernel.org/doc/html/latest/admin-guide/nfs/nfsroot.html
///
/// ip=<client-ip>:<server-ip>:<gw-ip>:<netmask>:<hostname>:<device>:<autoconf>:<dns0-ip>:<dns1-ip>:<ntp0-ip>
///
/// This parameter tells the kernel how to configure IP addresses of devices and also how to set up the IP routing table.
/// It was originally called nfsaddrs, but now the boot-time IP configuration works independently of NFS, so it was renamed to ip
/// and the old name remained as an alias for compatibility reasons.
///
/// If this parameter is missing from the kernel command line, all fields are assumed to be empty, and the defaults mentioned below apply.
/// In general this means that the kernel tries to configure everything using autoconfiguration.
///
/// The <autoconf> parameter can appear alone as the value to the ip parameter (without all the ‘:’ characters before).
/// If the value is “ip=off” or “ip=none”, no autoconfiguration will take place, otherwise autoconfiguration will take place.
/// The most common way to use this is “ip=dhcp”.
#[derive(Debug, Default, Clone)]
pub struct KernelIpConfig {
    /// <client-ip> IP address of the client.
    /// Default: Determined using autoconfiguration.
    pub client_ip: Option<String>,

    /// <server-ip> IP address of the NFS server.
    /// Default: Determined using autoconfiguration.
    pub server_ip: Option<String>,

    /// <gw-ip> IP address of a gateway if the server is on a different subnet.
    /// Default: Determined using autoconfiguration.
    pub gw_ip: Option<String>,

    /// <netmask> Netmask for local network interface.
    /// Default: Determined using autoconfiguration.
    pub netmask: Option<String>,

    /// <hostname> Name of the client.
    /// Default: Client IP address is used in ASCII notation.
    pub hostname: Option<String>,

    /// <device> Name of network device to use.
    /// Default: If the host only has one device, it is used.
    pub device: Option<String>,

    /// <autoconf> Method to use for autoconfiguration.
    /// off or none: don't use autoconfiguration (do static IP assignment instead)
    /// on or any: use any protocol available in the kernel (default)
    /// dhcp, bootp, rarp, both
    pub autoconf: Option<String>,

    /// <dns0-ip> IP address of primary nameserver.
    pub dns0: Option<String>,

    /// <dns1-ip> IP address of secondary nameserver.
    pub dns1: Option<String>,

    /// <ntp0-ip> IP address of a Network Time Protocol (NTP) server.
    pub ntp0: Option<String>,
}

impl KernelIpConfig {
    pub fn dhcp() -> Self {
        Self {
            autoconf: Some("dhcp".to_string()),
            ..Default::default()
        }
    }
}

impl fmt::Display for KernelIpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // If only autoconf is set and it is a simple keyword like "dhcp" or "bootp" (and no other fields are set),
        // we can output just `ip=dhcp`.
        // However, the docs say: "The <autoconf> parameter can appear alone... without all the ':' characters".
        // We need to check if we can essentially compact it.
        // For safety, if we have specific static IP details, we use the long format.

        // Helper to get string or empty
        fn s(opt: &Option<String>) -> &str {
            opt.as_deref().unwrap_or("")
        }

        let is_simple_autoconf = self.client_ip.is_none()
            && self.server_ip.is_none()
            && self.gw_ip.is_none()
            && self.netmask.is_none()
            // hostname might be None
            // device might be None
            && self.dns0.is_none()
            && self.dns1.is_none() // docs say ntp0 is ignored usually but part of spec
            && self.ntp0.is_none();

        if is_simple_autoconf && self.autoconf.is_some() {
            // Check if autoconf value is one that supports standalone
            let val = self.autoconf.as_ref().unwrap();
            if val == "dhcp"
                || val == "on"
                || val == "any"
                || val == "bootp"
                || val == "rarp"
                || val == "both"
                || val == "off"
                || val == "none"
            {
                return write!(f, "ip={}", val);
            }
        }

        // Long format
        // ip=<client-ip>:<server-ip>:<gw-ip>:<netmask>:<hostname>:<device>:<autoconf>:<dns0-ip>:<dns1-ip>:<ntp0-ip>
        write!(
            f,
            "ip={},{},{},{},{},{},{},{},{},{}",
            s(&self.client_ip),
            s(&self.server_ip),
            s(&self.gw_ip),
            s(&self.netmask),
            s(&self.hostname),
            s(&self.device),
            s(&self.autoconf),
            s(&self.dns0), // dns0-ip
            s(&self.dns1), // dns1-ip
            s(&self.ntp0)  // ntp0-ip
        )
    }
}
