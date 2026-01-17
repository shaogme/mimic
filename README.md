# Mimic (拟态)

**Mimic** 是一个智能的 Rescue System（救援系统）部署工具。它能在你的 Linux 宿主机上快速部署一个基于 Alpine Linux 的内存救援系统，并**自动“拟态”（复刻）**宿主机原本的网络配置和 SSH 访问权限。

当你的主系统因为内核崩溃、配置错误或文件系统损坏而无法启动时，你可以通过 Bootloader 进入 Mimic 救援系统。由于它继承了你熟悉的网络 IP 和 SSH Key，你无需连接物理控制台（VNC/IPMI），直接通过 SSH 连入即可开始修复工作。

## 核心特性

*   **极速部署**: 一键运行，自动下载 Alpine Netboot 镜像并配置引导。
*   **拟态网络 (Network Mimicry)**: 自动扫描宿主机的 IPv4/IPv6、网关、DNS 配置，并将其注入到救援系统中。
*   **拟态认证 (Auth Mimicry)**: 自动提取宿主机的 SSH `authorized_keys` 和 Root 密码哈希，无需手动设置密码。
*   **广泛兼容**:
    *   支持 **GRUB** 和 **Systemd-boot** 引导加载器。
    *   支持自动修补 Alpine `initramfs` 以适应复杂的网络环境。
*   **纯内存运行**: 系统加载到 RAM 中运行 (`modloop` 可选)，不占用磁盘锁，方便对根磁盘进行 `fsck` 或挂载修复。

## 快速开始

### 前置要求
*   Linux 操作系统 (x86_64)
*   Root 权限
*   Rust 工具链 (用于从源码编译)
*   互联网连接 (用于下载 Alpine 镜像)

### 安装与运行

1.  **克隆仓库**
    ```bash
    git clone https://github.com/your-repo/mimic.git
    cd mimic
    ```

2.  **一键部署**
    使用提供的 `run.sh` 脚本进行编译和部署：
    ```bash
    sudo ./run.sh
    ```
    
    该脚本会依次执行：
    1.  **Mimic-Gen**: 扫描系统并生成 `deployment.json` 配置文件。
    2.  **Mimic-Apply**: 下载内核，生成配置 Overlay，并安装 Boot 条目。

3.  **重启进入救援系统**
    部署成功后，脚本会提示你：
    ```bash
    Run 'reboot' to start the Mimic Alpine Rescue System.
    ```
    如果是 GRUB 用户，工具会自动设置 `grub-reboot`，下一次重启将自动进入救援系统（一次性）。

### 卸载与清理

如果你不再需要 Mimic 救援系统，可以使用 `clean.sh` 脚本进行一键清理：
```bash
sudo ./clean.sh
```
该命令会调用 `mimic-apply` 的清理功能，自动移除 Bootloader 启动项并删除相关文件。

## 项目结构

本项目由三个 Rust Crates 组成：

### 1. `mimic-gen` (Generator)
负责“感知”。它运行在宿主机上，通过 `ip` 命令和文件系统扫描收集以下信息：
*   所有物理网卡的 IP 地址、子网掩码和 MAC 地址。
*   默认网关（IPv4/IPv6）。
*   DNS 服务器 (`/etc/resolv.conf`)。
*   SSH 公钥 (`~/.ssh/authorized_keys`)。
*   用户密码（可选交互式输入或随机生成）。

生成结果保存为 `deployment.json`。

### 2. `mimic-apply` (Applier)
负责“构造”。它读取配置文件并执行实际部署：
*   **下载**: 从 Alpine 官方源下载 `vmlinuz-virt`, `initramfs-virt`, `modloop-virt`。
*   **Patch**: 在内存中解压并修改 `initramfs` 的 init 脚本，注入增强的网络启动逻辑。
*   **Overlay**: 将网络配置 (`/etc/network/interfaces`) 和认证文件打包成 `apkovl.tar.gz`，并再次封装为 CPIO 归档，作为额外的 initrd 加载。
*   **Bootloader**: 自动识别 GRUB 或 Systemd-boot，并写入相应的启动项配置。

### 3. `mimic-shared`
包含两个组件共享的数据结构定义和配置模型。

## 常见问题

**Q: 救援系统的用户名和密码是什么？**
*   **用户名**: `root`
*   **密码**:
    *   如果你在运行脚本时输入了密码，则使用该密码。
    *   如果你选择了随机密码，脚本结束时会显示在屏幕上。
    *   **推荐**: 直接使用 SSH Key 登录，无需密码。

**Q: 是否支持静态 IP？**
A: 是的，`mimic-gen` 会优先探测并配置静态 IP。如果失败，救援系统会回退到 DHCP。

**Q: 它会修改我的磁盘文件吗？**
A: 它只会向 `/boot` 目录写入几个文件（内核、initrd、overlay），并添加一个引导配置文件（如 `custom.cfg`）。它**不会**修改你的根文件系统内容，非常安全。

## 许可证

MIT License
