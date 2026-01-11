# boku_no_key (我的密钥)

> **⚠️ 免责声明：这是一个非官方的第三方开源工具，与 PicoKey 商业项目或原作者无任何关联。**

[![Build Status](https://img.shields.io/github/actions/workflow/status/Lumingtianze/boku_no_key/.github/workflows/build.yaml?branch=main)](https://github.com/Lumingtianze/boku_no_key/actions)
[![Latest Release](https://img.shields.io/github/v/release/Lumingtianze/boku_no_key)](https://github.com/Lumingtianze/boku_no_key/releases)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

## 简介

**boku_no_key** 是一个适用于 Pico FIDO 安全密钥固件的**非官方 TUI 配置工具**，使用 Rust 编写。

## 主要功能

*   **交互式配置 (TUI)**：通过简单的菜单界面修改 USB VID/PID、产品名称、LED 亮度与驱动模式等。
*   **设备信息读取**：查看固件版本、序列号、硬件平台及已启用的功能模块（FIDO2 / OpenPGP / OATH 等）。
*   **恢复出厂设置**：支持对 FIDO 数据进行重置。

## 使用方法

在 [Release](https://github.com/Lumingtianze/boku_no_key/releases) 中下载二进制。

```bash
# 1. 列出当前连接的设备
./boku_no_key list

# 2. 查看设备详细信息
./boku_no_key info

# 3. 进入交互式配置菜单
./boku_no_key config

# 4. 恢复出厂设置 (慎用，会清除所有密钥)
./boku_no_key reset
```

## 编译

假设你已经安装了 Rust 工具链。Linux 下编译需要安装依赖。

```bash
sudo apt update
sudo apt install -y pkgconf libpcsclite-dev
```

```bash
git clone https://github.com/lumingtianze/boku_no_key
cd boku_no_key
cargo build --release
```

## 许可证

本项目采用 [**GNU Affero General Public License v3.0 (AGPLv3)**](LICENSE) 许可证。
