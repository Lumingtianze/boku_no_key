use anyhow::{anyhow, Context, Result};
use byteorder::{BigEndian, ByteOrder};
use clap::{Parser, Subcommand};
use colored::*;
use inquire::{Confirm, CustomType, MultiSelect, Select, Text, validator::Validation};
use pcsc::{Card, Context as PcscContext, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};

// --- 常量定义 ---

const AID_FIDO_MAN: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
const AID_PICO_RESCUE: &[u8] = &[0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21, 0x00];

// Management Tags
const MAN_TAG_SERIAL: u8 = 0x02;
const MAN_TAG_FORM_FACTOR: u8 = 0x04;
const MAN_TAG_VERSION: u8 = 0x05;
const MAN_TAG_USB_SUPPORTED: u8 = 0x01;
const MAN_TAG_USB_ENABLED: u8 = 0x03;

// PHY Data Tags
const TAG_VIDPID: u8 = 0x00;
const TAG_LED_GPIO: u8 = 0x04;
const TAG_LED_BRIGHTNESS: u8 = 0x05;
const TAG_OPTS: u8 = 0x06;
const TAG_PRESENCE_TIMEOUT: u8 = 0x08;
const TAG_PRODUCT_NAME: u8 = 0x09;
const TAG_ENABLED_CURVES: u8 = 0x0A;
const TAG_LED_DRIVER: u8 = 0x0C;

// Instructions
const INS_MGMT_READ: u8 = 0x1D;
const INS_RESCUE_WRITE_PHY: u8 = 0x1C;
const INS_RESCUE_READ_INFO: u8 = 0x1E;

// Bitmasks
const CAP_OTP: u16 = 0x0001;     // bit 0
const CAP_U2F: u16 = 0x0002;     // bit 1
const CAP_OPENPGP: u16 = 0x0008;  // bit 3
const CAP_PIV: u16 = 0x0010;     // bit 4
const CAP_OATH: u16 = 0x0020;    // bit 5
const CAP_FIDO2: u16 = 0x0200;   // bit 9

const PHY_OPT_DIMM: u16 = 0x02;
const PHY_OPT_DISABLE_POWER_RESET: u16 = 0x04;
const PHY_OPT_LED_STEADY: u16 = 0x08;

const CURVE_SECP256R1: u32 = 0x01;
const CURVE_SECP256K1: u32 = 0x08;
const CURVE_ED25519: u32 = 0x80;

#[derive(Parser)]
#[command(name = "boku_no_key", version = "0.1.0", about = "一个非官方的 Pico Key 配置与管理工具")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    // 开启调试模式 (打印 APDU)
    #[arg(short, long, global = true)]
    debug: bool,
}

#[derive(Subcommand)]
enum Commands {
    // 列出所有连接的设备
    List,
    // 显示设备详细信息
    Info,
    // 交互式配置设备
    Config,
    // 恢复出厂设置
    Reset,
}

// --- 数据结构 ---

#[derive(Debug, Default)]
struct DeviceInfo {
    serial: u32,
    version: String,
    form_factor: String,
    supported_caps: u16,
    enabled_caps: u16,
    platform: String,
    product_type: String,
    display_name: String,
    interface_id: String,
}

#[derive(Debug, Default, Clone)]
struct PhyConfigPatch {
    vid: Option<u16>,
    pid: Option<u16>,
    led_gpio: Option<u8>,
    led_brightness: Option<u8>,
    opts: Option<u16>, 
    presence_timeout: Option<u8>,
    product_name: Option<String>,
    curves: Option<u32>,
    led_driver: Option<u8>,
}

impl PhyConfigPatch {
    fn is_empty(&self) -> bool {
        self.vid.is_none() &&
        self.pid.is_none() &&
        self.led_gpio.is_none() &&
        self.led_brightness.is_none() &&
        self.opts.is_none() &&
        self.presence_timeout.is_none() &&
        self.product_name.is_none() &&
        self.curves.is_none() &&
        self.led_driver.is_none()
    }

    fn serialize(&self) -> Vec<u8> {
        let mut b = Vec::new();
        if let (Some(v), Some(p)) = (self.vid, self.pid) {
            b.extend_from_slice(&[TAG_VIDPID, 4]);
            b.extend_from_slice(&v.to_be_bytes());
            b.extend_from_slice(&p.to_be_bytes());
        } 
        if let Some(v) = self.led_gpio {
            b.extend_from_slice(&[TAG_LED_GPIO, 1, v]);
        }
        if let Some(v) = self.led_brightness {
            b.extend_from_slice(&[TAG_LED_BRIGHTNESS, 1, v]);
        }
        if let Some(v) = self.opts {
            b.extend_from_slice(&[TAG_OPTS, 2]);
            b.extend_from_slice(&v.to_be_bytes());
        }
        if let Some(v) = self.presence_timeout {
            b.extend_from_slice(&[TAG_PRESENCE_TIMEOUT, 1, v]);
        }
        if let Some(name) = &self.product_name {
            let name_bytes = name.as_bytes();
            let mut payload = name_bytes.to_vec();
            if !payload.contains(&0) { payload.push(0x00); }
            b.push(TAG_PRODUCT_NAME);
            b.push(payload.len() as u8);
            b.extend(payload);
        }
        if let Some(v) = self.curves {
            b.extend_from_slice(&[TAG_ENABLED_CURVES, 4]);
            b.extend_from_slice(&v.to_be_bytes());
        }
        if let Some(v) = self.led_driver {
            b.extend_from_slice(&[TAG_LED_DRIVER, 1, v]);
        }
        b
    }

    fn display_changes(&self) {
        if let Some(name) = &self.product_name {
            println!(" - 产品名称: {}", name.cyan());
        }
        if let (Some(v), Some(p)) = (self.vid, self.pid) {
            println!(" - VID:PID:  {:04X}:{:04X}", v, p);
        }
        
        if self.led_driver.is_some() || self.led_gpio.is_some() {
            let drv_str = match self.led_driver {
                Some(1) => "GPIO直驱",
                Some(2) => "Pimoroni",
                Some(3) => "WS2812",
                Some(4) => "CYW43",
                Some(5) => "NeoPixel",
                Some(0xFF) => "已禁用",
                Some(_) => "未知",
                None => "保持不变"
            };
            let gpio_str = if let Some(g) = self.led_gpio { format!("{}", g) } else { "保持不变".to_string() };
            println!(" - LED 硬件: 驱动={}, 引脚={}", drv_str.cyan(), gpio_str.cyan());
        }

        if let Some(v) = self.led_brightness {
            println!(" - LED 亮度: {}", v);
        }
        
        if let Some(v) = self.opts {
            let mut opts_str = Vec::new();
            if v & PHY_OPT_LED_STEADY != 0 { opts_str.push("常亮"); }
            if v & PHY_OPT_DIMM != 0 { opts_str.push("可调光"); }
            if v & PHY_OPT_DISABLE_POWER_RESET != 0 { opts_str.push("禁用断电重置"); }
            if opts_str.is_empty() { opts_str.push("默认/无"); }
            println!(" - LED 选项: {:?}", opts_str);
        }
        if let Some(v) = self.presence_timeout {
            println!(" - 触摸键超时: {} 秒", v);
        }
        if let Some(v) = self.curves {
            let mut curves_str = Vec::new();
            if v & CURVE_SECP256R1 != 0 { curves_str.push("P-256"); }
            if v & CURVE_SECP256K1 != 0 { curves_str.push("secp256k1"); }
            if v & CURVE_ED25519 != 0 { curves_str.push("Ed25519"); }
            println!(" - 算法曲线: {:?}", curves_str);
        }
    }
}

// --- APDU 封装 ---

struct PicoCard {
    card: Card,
    debug: bool,
}

impl PicoCard {
    fn connect(ctx: &PcscContext, reader: &std::ffi::CStr) -> Result<Self> {
        let card = ctx.connect(reader, ShareMode::Shared, Protocols::ANY)?;
        Ok(Self { card, debug: false })
    }

    fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }

    fn transmit(&self, apdu: &[u8]) -> Result<(Vec<u8>, u16)> {
        if self.debug { println!("{} {}", "->".green(), hex::encode(apdu)); }

        let mut buf = [0; MAX_BUFFER_SIZE];
        let resp = self.card.transmit(apdu, &mut buf)?;
        
        let mut sw = BigEndian::read_u16(&resp[resp.len() - 2..]);
        let mut data = resp[..resp.len() - 2].to_vec();

        while (sw >> 8) == 0x61 {
            let len = (sw & 0xFF) as u8;
            if self.debug { println!("{} {:04X} (GET RESP {}b)", "<-".blue(), sw, len); }
            let get_resp = [0x00, 0xC0, 0x00, 0x00, len];
            let mut rx_buf = [0; MAX_BUFFER_SIZE];
            let rx = self.card.transmit(&get_resp, &mut rx_buf)?;
            data.extend_from_slice(&rx[..rx.len() - 2]);
            sw = BigEndian::read_u16(&rx[rx.len() - 2..]);
        }

        if self.debug { println!("{} {} SW={:04X}", "<-".blue(), hex::encode(&data), sw); }
        Ok((data, sw))
    }

    fn select(&self, aid: &[u8]) -> Result<(Vec<u8>, u16)> {
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x04, aid.len() as u8];
        apdu.extend_from_slice(aid);
        let (data, sw) = self.transmit(&apdu)?;
        Ok((data, sw))
    }
}

// --- 名称处理 ---

fn clean_device_name(raw: &str) -> (String, String) {
    let mut name = raw.to_string();
    let mut interface = "0".to_string();

    if let Some(last_space) = name.rfind(' ') {
        let suffix = &name[last_space+1..];
        if suffix.chars().all(|c| c.is_digit(10)) {
            interface = suffix.to_string();
            name = name[..last_space].to_string();
        }
    }

    let stop_words = [" Interface", " CCID", " OTP", " FIDO", " HID", " Keyboard"];
    let mut cut_idx = name.len();
    let lower_name = name.to_lowercase();
    for word in stop_words {
        if let Some(idx) = lower_name.find(&word.to_lowercase()) {
            if idx < cut_idx {
                cut_idx = idx;
            }
        }
    }
    name = name[..cut_idx].trim().to_string();

    let prefix = "Pol Henarejos ";
    if name.starts_with(prefix) {
        name = name[prefix.len()..].to_string();
    }

    if name.is_empty() {
        if let Some(idx) = raw.rfind(' ') {
            name = raw[..idx].to_string();
        } else {
            name = raw.to_string();
        }
    }

    (name, interface)
}

fn select_reader(ctx: &PcscContext) -> Result<std::ffi::CString> {
    let mut readers_buf = [0; 2048];
    let readers_iter = ctx.list_readers(&mut readers_buf)?;
    let readers: Vec<_> = readers_iter.collect();

    if readers.is_empty() {
        return Err(anyhow!("未发现智能卡设备"));
    }

    if readers.len() == 1 {
        return Ok(readers[0].to_owned());
    }

    println!("发现多个设备，请选择一个进行操作：");
    let options: Vec<String> = readers.iter().map(|r| {
        let raw = r.to_str().unwrap_or("Unknown");
        let (name, interface) = clean_device_name(raw);
        format!("{} (Interface {})", name, interface)
    }).collect();

    let choice = Select::new("选择设备:", options.clone()).prompt()?;
    
    if let Some(index) = options.iter().position(|s| s == &choice) {
        return Ok(readers[index].to_owned());
    }

    Err(anyhow!("选择无效"))
}

// --- 辅助函数 ---

fn parse_management_tlv(data: &[u8], info: &mut DeviceInfo) {
    let mut p = 0;
    if !data.is_empty() && data[0] as usize == data.len() - 1 {
        p = 1;
    }

    let mut found_enabled = false;

    while p + 2 <= data.len() {
        let tag = data[p];
        let len = data[p + 1] as usize;
        p += 2;
        if p + len > data.len() { break; }
        let val = &data[p..p + len];

        match tag {
            MAN_TAG_SERIAL if len >= 4 => info.serial = BigEndian::read_u32(&val[0..4]),
            MAN_TAG_VERSION if len >= 3 => info.version = format!("{}.{}.{}", val[0], val[1], val[2]),
            MAN_TAG_FORM_FACTOR => {
                 info.form_factor = match val[0] {
                    1 => "Keychain (USB-A)".to_string(),
                    2 => "Keychain (USB-C)".to_string(),
                    3 => "Pico (内置)".to_string(),
                    4 => "Pico (外置)".to_string(),
                    _ => format!("Unknown (0x{:02X})", val[0]),
                };
            },
            MAN_TAG_USB_SUPPORTED if len >= 2 => info.supported_caps = BigEndian::read_u16(&val[0..2]),
            MAN_TAG_USB_ENABLED if len >= 2 => {
                info.enabled_caps = BigEndian::read_u16(&val[0..2]);
                found_enabled = true;
            },
            _ => {}
        }
        p += len;
    }

    // 如果完全没有读到 Enabled 标签，才回退
    if !found_enabled {
        info.enabled_caps = info.supported_caps;
    }
}

fn print_cap_status(name: &str, mask: u16, supported: u16, enabled: u16) {
    if supported & mask != 0 {
        let status = if enabled & mask != 0 { "Enabled".green() } else { "Disabled".red() };
        println!("{:<20} {}", name, status);
    }
}

// --- 功能实现 ---

fn run_list(debug: bool) -> Result<()> {
    let ctx = PcscContext::establish(Scope::User)?;
    let mut readers_buf = [0; 2048];
    let readers = ctx.list_readers(&mut readers_buf)?;

    println!("{}", "已连接的设备:".bold());
    let mut found = false;

    for reader in readers {
        if let Ok(mut dev) = PicoCard::connect(&ctx, reader) {
            dev.set_debug(debug);
            if let Ok((_, sw)) = dev.select(AID_FIDO_MAN) {
                if sw == 0x9000 {
                    let (mgmt_data, _) = dev.transmit(&[0x00, INS_MGMT_READ, 0x00, 0x00, 0x00]).unwrap_or((vec![], 0));
                    let mut temp_info = DeviceInfo::default();
                    parse_management_tlv(&mgmt_data, &mut temp_info);
                    
                    let raw_name = reader.to_str().unwrap_or("未知读卡器");
                    let (name, interface) = clean_device_name(raw_name);

                    print!("- {} (Interface {})", name, interface);
                    if temp_info.serial != 0 {
                        print!(" [SN: {}]", temp_info.serial);
                    }
                    println!();
                    found = true;
                }
            }
        }
    }
    if !found {
        println!("未发现支持的 Pico FIDO 设备。暂不支持 HSM 和 OpenPGP 固件");
    }
    Ok(())
}

fn run_info(debug: bool) -> Result<()> {
    let ctx = PcscContext::establish(Scope::User)?;
    
    let reader_cstr = select_reader(&ctx)?;
    let mut dev = PicoCard::connect(&ctx, &reader_cstr)?;
    dev.set_debug(debug);
    
    let raw_name = reader_cstr.to_str().unwrap_or("").to_string();
    let (name, interface) = clean_device_name(&raw_name);

    println!("{}", "=== Pico Key 设备信息 ===".bold());

    let mut info = DeviceInfo::default();
    info.display_name = name;
    info.interface_id = interface;

    // 1. 获取管理模式信息 (序列号, 版本, 应用状态)
    let (ver_raw, sw_sel) = dev.select(AID_FIDO_MAN)?;
    if sw_sel == 0x9000 {
        info.version = String::from_utf8_lossy(&ver_raw).to_string();
        let (mgmt_data, sw_man) = dev.transmit(&[0x00, INS_MGMT_READ, 0x00, 0x00, 0x00])?;
        if sw_man == 0x9000 {
            parse_management_tlv(&mgmt_data, &mut info);
        }
    }

    // 2. 获取救援模式信息 (硬件平台)
    let (rescue_data, sw_res) = dev.select(AID_PICO_RESCUE)?;
    if sw_res == 0x9000 && rescue_data.len() >= 4 {
        info.platform = match rescue_data[0] {
            0x00 => "RP2040".to_string(),
            0x01 => "RP2350".to_string(),
            0x02 => "ESP32".to_string(),
            _ => format!("未知 ({:02X})", rescue_data[0]),
        };
        info.product_type = match rescue_data[1] {
            0x01 => "Pico HSM".to_string(),
            0x02 => "Pico FIDO".to_string(),
            0x03 => "Pico OpenPGP".to_string(),
            _ => format!("未知 ({:02X})", rescue_data[1]),
        };
    } else {
        info.platform = "未知 (Rescue不可用)".to_string();
    }

    println!("{:<20} {}", "设备名称:", info.display_name);
    println!("{:<20} {}", "接口编号:", info.interface_id);
    if info.serial != 0 { println!("{:<20} {}", "序列编号:", info.serial.to_string().yellow()); }
    else { println!("{:<20} {}", "序列编号:", "N/A (非FIDO固件)".yellow()); }
    println!("{:<20} {}", "固件版本:", info.version);
    println!("{:<20} {}", "硬件平台:", info.platform);
    println!("{:<20} {}", "固件类型:", info.product_type);
    println!("{:<20} {}", "接口外形:", info.form_factor);

    println!("\n{}", "应用状态".bold());
    print_cap_status("Yubico OTP", CAP_OTP, info.supported_caps, info.enabled_caps);
    print_cap_status("FIDO U2F", CAP_U2F, info.supported_caps, info.enabled_caps);
    print_cap_status("FIDO2", CAP_FIDO2, info.supported_caps, info.enabled_caps);
    print_cap_status("OATH", CAP_OATH, info.supported_caps, info.enabled_caps);
    print_cap_status("OpenPGP", CAP_OPENPGP, info.supported_caps, info.enabled_caps);
    print_cap_status("PIV", CAP_PIV, info.supported_caps, info.enabled_caps);

    Ok(())
}

fn run_config_interactive(debug: bool) -> Result<()> {
    let ctx = PcscContext::establish(Scope::User)?;
    let reader_name = select_reader(&ctx)?;
    
    let mut dev = PicoCard::connect(&ctx, &reader_name)?;
    dev.set_debug(debug);

    let (_, sw) = dev.select(AID_PICO_RESCUE).context("无法连接配置接口 (Rescue Applet)")?;
    if sw != 0x9000 {
        return Err(anyhow!("无法连接配置接口，SW={:04X}", sw));
    }

    println!("{}", "--- 交互式配置模式 ---".yellow());
    println!("说明: 仅设置您需要修改的选项，直接回车可跳过。");

    let mut cfg = PhyConfigPatch::default();

    loop {
        let options = vec![
            "设置身份信息 (VID/PID, 产品名称)",
            "设置硬件参数 (LED, 触摸键)",
            "设置算法支持 (ECC 曲线)",
            "安全启动管理 (Secure Boot)",
            "写入配置 (Apply)",
            "退出"
        ];

        let choice = Select::new("主菜单:", options).prompt()?;

        match choice {
            "设置身份信息 (VID/PID, 产品名称)" => {
                let name = Text::new("输入产品名称 (USB 描述符):")
                    .with_help_message("直接回车不修改，最多14字符")
                    .with_validator(|s: &str| if s.len() > 14 { Ok(Validation::Invalid("名称过长".into())) } else { Ok(Validation::Valid) })
                    .prompt()?;
                if !name.is_empty() { cfg.product_name = Some(name); }

                let presets = vec![
                    "不修改 VID/PID",
                    "通用设备 (0000:0000)",
                    "Nitrokey HSM (20A0:4230)",
                    "Nitrokey FIDO2 (20A0:42B1)",
                    "Yubikey 4/5 (1050:0407)",
                    "自定义输入"
                ];
                let vendor = Select::new("设置 USB ID:", presets).prompt()?;
                match vendor {
                    "通用设备 (0000:0000)" => { cfg.vid = Some(0); cfg.pid = Some(0); }
                    "Nitrokey HSM (20A0:4230)" => { cfg.vid = Some(0x20A0); cfg.pid = Some(0x4230); }
                    "Nitrokey FIDO2 (20A0:42B1)" => { cfg.vid = Some(0x20A0); cfg.pid = Some(0x42B1); }
                    "Yubikey 4/5 (1050:0407)" => { cfg.vid = Some(0x1050); cfg.pid = Some(0x0407); }
                    "自定义输入" => {
                         let v = Text::new("输入 VID (Hex):").with_help_message("回车跳过").prompt()?;
                         let p = Text::new("输入 PID (Hex):").with_help_message("回车跳过").prompt()?;
                         if !v.is_empty() && !p.is_empty() {
                             cfg.vid = Some(u16::from_str_radix(&v, 16).unwrap_or(0));
                             cfg.pid = Some(u16::from_str_radix(&p, 16).unwrap_or(0));
                         }
                    }
                    _ => {}
                }
            },
            "设置硬件参数 (LED, 触摸键)" => {
                // 1. Brightness
                let br_str = Text::new("LED 亮度 (0-255):").with_help_message("回车不修改跳过").prompt()?;
                if !br_str.is_empty() {
                    if let Ok(val) = br_str.parse::<u8>() { cfg.led_brightness = Some(val); }
                }
                
                // 2. LED Options
                let opts_list = vec!["常亮 (Steady)", "可调光 (Dimmable)", "禁用断电重置"];
                let sel_opts = MultiSelect::new("LED 行为选项 (覆盖旧设置):", opts_list).prompt()?;
                
                let mut new_opts = 0u16;
                for s in sel_opts {
                    if s.contains("常亮") { new_opts |= PHY_OPT_LED_STEADY; }
                    if s.contains("可调光") { new_opts |= PHY_OPT_DIMM; }
                    if s.contains("禁用") { new_opts |= PHY_OPT_DISABLE_POWER_RESET; }
                }
                cfg.opts = Some(new_opts);

                // 3. Timeout
                let to_str = Text::new("触摸键超时 (秒):").with_help_message("回车不修改跳过").prompt()?;
                if !to_str.is_empty() {
                    if let Ok(val) = to_str.parse::<u8>() { cfg.presence_timeout = Some(val); }
                }

                // 4. LED Driver
                let drv_opts = vec![
                    "不修改 (保持默认)",
                    "标准 GPIO 直驱",
                    "WS2812",
                    "CYW43",
                    "Pimoroni",
                    "NeoPixel",
                    "通用 GPIO 直驱 (自定义引脚)", //以此类推提供自定义选项
                    "通用 WS2812 (自定义引脚)",
                    "禁用 LED"
                ];
                let drv_sel = Select::new("LED 驱动/预设:", drv_opts).prompt()?;
                
                let mut ask_pin = false;
                match drv_sel {
                    "标准 GPIO 直驱" => {
                        cfg.led_driver = Some(1); // PHY_LED_DRIVER_PICO
                        cfg.led_gpio = Some(25);
                    },
                    "Pimoroni" => {
                        cfg.led_driver = Some(2); // PHY_LED_DRIVER_PIMORONI
                        // Pimoroni 驱动忽略 GPIO 设置，使用固件内写死的引脚
                    },
                    "WS2812" => {
                        cfg.led_driver = Some(3); // PHY_LED_DRIVER_WS2812
                        cfg.led_gpio = Some(16);
                    },
                    "CYW43" => {
                        cfg.led_driver = Some(4); // PHY_LED_DRIVER_CYW43
                        cfg.led_gpio = Some(0);   // Pico W 的 LED 在无线芯片的 Pin 0
                    },
                    "NeoPixel" => {
                        cfg.led_driver = Some(5); // PHY_LED_DRIVER_NEOPIXEL
                        ask_pin = true; 
                    },
                    "通用 GPIO 直驱 (自定义引脚)" => {
                        cfg.led_driver = Some(1);
                        ask_pin = true;
                    },
                    "通用 WS2812 (自定义引脚)" => {
                        cfg.led_driver = Some(3);
                        ask_pin = true;
                    },
                    "禁用 LED" => {
                        cfg.led_driver = Some(0xFF);
                    },
                    _ => {} // 不修改
                }

                // 5. GPIO Pin (只有需要自定义时才问)
                if ask_pin {
                    let gpio_input = CustomType::<u8>::new("LED GPIO 引脚号:")
                        .with_placeholder("例如 16, 25, 48")
                        .with_help_message("输入开发板对应的 LED 引脚号")
                        .prompt_skippable()?;
                    if let Some(val) = gpio_input { cfg.led_gpio = Some(val); }
                }
            },
            "设置算法支持 (ECC 曲线)" => {
                // Curves
                let curve_list = vec!["P-256 (推荐)", "secp256k1", "Ed25519"];
                let sel_c = MultiSelect::new("启用的算法 (覆盖旧设置):", curve_list).prompt()?;
                let mut new_curves = 0u32;
                new_curves |= CURVE_SECP256R1; 
                for s in sel_c {
                    if s.contains("secp256k1") { new_curves |= CURVE_SECP256K1; }
                    if s.contains("Ed25519") { new_curves |= CURVE_ED25519; }
                }
                cfg.curves = Some(new_curves);
            },
            "安全启动管理 (Secure Boot)" => {
                println!("\n{}", "--- 安全启动管理 ---".bold().on_yellow().black());
                println!("{} {}", "适用芯片:".bold(), "RP2350 (Pico 2), ESP32-S3".cyan());
                
                println!("1. {}：不可逆操作。芯片启动时强制校验固件签名，无法再运行自编译的未签名固件。OTP/eFuse 寄存器仍处于可写状态。", "开启签名校验".yellow());
                println!("2. {}：不可逆操作。禁用调试接口并设置 OTP/eFuse 寄存器为只读。", "永久锁定硬件".red());

                let (sb_data, sb_sw) = dev.transmit(&[0x80, INS_RESCUE_READ_INFO, 0x03, 0x00, 0x00])?;
                if sb_sw == 0x9000 && sb_data.len() >= 2 {
                    let enabled = sb_data[0] != 0;
                    let locked = sb_data[1] != 0;
                    
                    println!("\n当前硬件状态:");
                    println!(" - 签名校验: {}", if enabled { "【已开启】".green() } else { "【未开启】".yellow() });
                    println!(" - 硬件锁定: {}", if locked { "【已锁定】(调试禁用/只读)".red() } else { "【未锁定】(可调试/可写)".green() });

                    if !locked {
                        let mut options = vec!["返回主菜单"];
                        // 只有未开启时才显示开启选项
                        if !enabled {
                            options.push("开启签名校验 (需输入指令确认)");
                        }
                        // 任何未锁定状态下都可以执行锁定
                        options.push("执行永久硬件锁定 (需输入指令确认)");

                        let act = Select::new("请选择操作:", options).prompt()?;
                        match act {
                            "开启签名校验 (需输入指令确认)" => {
                                println!("\n{}", "警告：即将烧断安全启动熔丝！".red().bold());
                                println!("此操作后，如果刷入未签名的固件，设备将无法启动（变砖）。");
                                println!("请输入 {} 以确认执行此操作：", "'ENABLE'".bold().yellow());
                                
                                let confirm = Text::new("确认指令:").prompt()?;
                                if confirm == "ENABLE" {
                                    // P1=0x02, Data=[KeyIdx=0, LockFlag=0]
                                    dev.transmit(&[0x80, INS_RESCUE_WRITE_PHY, 0x02, 0x00, 0x02, 0x00, 0x00])?;
                                    println!("{}", "操作成功：签名校验已开启。".green().bold());
                                } else {
                                    println!("输入不匹配，操作已取消。");
                                }
                            },
                            "执行永久硬件锁定 (需输入指令确认)" => {
                                println!("\n{}", "警告：即将永久锁定硬件！".on_red().white().bold());
                                println!("此操作将烧断调试接口熔丝，并将 OTP/eFuse 设为只读。此过程绝对不可逆！");
                                println!("请输入 {} 以确认执行最终锁定：", "'LOCK'".bold().red());
                                
                                let confirm = Text::new("确认指令:").prompt()?;
                                if confirm == "LOCK" {
                                    // P1=0x02, Data=[KeyIdx=0, LockFlag=1]
                                    dev.transmit(&[0x80, INS_RESCUE_WRITE_PHY, 0x02, 0x00, 0x02, 0x00, 0x01])?;
                                    println!("{}", "操作成功：设备已执行硬件锁定。".red().bold());
                                } else {
                                    println!("输入不匹配，操作已取消。");
                                }
                            },
                            _ => {}
                        }
                    } else {
                        println!("\n{}", "设备已处于硬件锁定状态，无法再更改安全配置。".yellow());
                    }
                } else {
                    println!("\n{}", "读取状态失败：当前芯片可能不支持安全启动。".red());
                }
            },
            "写入配置 (Apply)" => {
                if cfg.is_empty() {
                    println!("未做任何修改。");
                    continue;
                }
                println!("\n{}", "即将写入以下修改:".bold());
                cfg.display_changes();
                println!("");

                if Confirm::new("确认写入?").with_default(true).prompt()? {
                    let payload = cfg.serialize();
                    let mut apdu = vec![0x80, INS_RESCUE_WRITE_PHY, 0x01, 0x00, payload.len() as u8];
                    apdu.extend(payload);

                    let (_, sw) = dev.transmit(&apdu)?;
                    if sw == 0x9000 {
                        println!("{}", "写入成功! 请重插拔设备。".green().bold());
                        break;
                    } else {
                        println!("{}", format!("写入失败 SW={:04X}", sw).red());
                    }
                }
            },
            "退出" => break,
            _ => {}
        }
    }

    Ok(())
}

fn run_reset(debug: bool) -> Result<()> {
    let ctx = PcscContext::establish(Scope::User)?;
    let reader_name = select_reader(&ctx)?;
    let mut dev = PicoCard::connect(&ctx, &reader_name)?;
    dev.set_debug(debug);

    let has_fido = dev.select(AID_FIDO_MAN).is_ok();
    
    println!("\n{}", "！！！ 危险操作：恢复出厂设置 ！！！".on_red().white().bold());
    println!("提示：此操作主要针对 Pico FIDO 固件。非 FIDO 固件不支持重置指令。");
    println!("此操作将永久擦除以下所有数据：");
    println!(" 1. {}", "FIDO2 / U2F".bold());
    println!("    - 所有驻留密钥 (Passkeys)、注册信息和全局计数器。");
    println!(" 2. {}", "智能卡应用 (OpenPGP / PIV)".bold());
    println!("    - 所有导入或生成的 RSA/ECC 私钥、证书和 PIN 码。");
    println!(" 3. {}", "OATH (2FA 动态口令)".bold());
    println!("    - 所有 TOTP/HOTP 种子数据 (即 Authenticator 数据)。");
    println!("{}", "注意：此操作不可撤销！需在设备通电 10 秒内执行，并需按键确认。".red());
    
    println!("\n请先重新插拔设备（确保上电 < 10s），然后输入 {} 确认：", "'RESET'".bold().red());
    let confirm = Text::new("确认指令:").prompt()?;
    
    if confirm == "RESET" {
        println!("正在执行重置...");
        println!("请留意设备 LED 闪烁，并按下设备按键以确认操作。");
        
        if has_fido {
            // FIDO Reset: 00 1E 00 00
            match dev.transmit(&[0x00, 0x1E, 0x00, 0x00]) {
                Ok((_, sw)) => {
                    if sw == 0x9000 {
                        println!("{}", "设备已成功重置 (FIDO Management)。".green().bold());
                        println!("如果设备 LED 未闪烁或您未按键，重置可能并未实际执行（因超时或配置限制）。");
                        println!("请重新插拔设备后再重新重置。");
                    } else if sw == 0x6985 { // CTAP2_ERR_NOT_ALLOWED (Timeout)
                        println!("{}", "重置失败：超时。请重新插拔设备并在 10 秒内重试。".red());
                    } else if sw == 0x6986 { // CTAP2_ERR_USER_ACTION_TIMEOUT (No Button Press)
                        println!("{}", "重置失败：未检测到按键确认。".red());
                    } else {
                        // 处理其他未知的 SW 错误码
                        println!("{}", format!("重置失败：SW={:04X}。", sw).red());
                    }
                },
                Err(e) => {
                     println!("{}", format!("通信错误: {}", e).red());
                }
            }
        } else {
            println!("{}", "错误：未检测到 FIDO 模块。".red());
            println!("当前固件版本（如 HSM/OpenPGP 独立固件）不支持通过此工具重置。");
        }
    } else {
        println!("指令不匹配，操作已取消。");
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::List => run_list(cli.debug)?,
        Commands::Info => run_info(cli.debug)?,
        Commands::Config => run_config_interactive(cli.debug)?,
        Commands::Reset => run_reset(cli.debug)?,
    }
    Ok(())
}
