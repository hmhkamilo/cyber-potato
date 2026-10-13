//! cyber: Native runner and host environment for CYBER.EXE
use cyber_rs::{Bus, Cpu, FlatMemory, StepResult};
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const LOAD_SEG: u16 = 0x1000;

struct CyberBus {
    mem: FlatMemory,
    dac_palette: [u32; 256],
    dac_index: u8,
    dac_step: u8,
    dac_r: u8,
    dac_g: u8,
    vblank_bit: bool,
    frame_completed: bool,
    open_files: BTreeMap<u16, File>,
    next_handle: u16,
    exe_dir: PathBuf,
    scratch_dir: PathBuf,
    // Mouse state
    mouse_mickeys_x: i16,
    mouse_mickeys_y: i16,
    mouse_buttons: u16,
    mouse_left_press_count: u16,
    mouse_right_press_count: u16,
    mouse_x: u16,
    mouse_y: u16,
}

impl CyberBus {
    fn new(exe_dir: PathBuf, scratch_dir: PathBuf) -> Self {
        Self {
            mem: FlatMemory::new_1mb(),
            dac_palette: [0u32; 256],
            dac_index: 0,
            dac_step: 0,
            dac_r: 0,
            dac_g: 0,
            vblank_bit: false,
            frame_completed: false,
            open_files: BTreeMap::new(),
            next_handle: 5,
            exe_dir,
            scratch_dir,
            mouse_mickeys_x: 0,
            mouse_mickeys_y: 0,
            mouse_buttons: 0,
            mouse_left_press_count: 0,
            mouse_right_press_count: 0,
            mouse_x: 160,
            mouse_y: 100,
        }
    }
}

impl Bus for CyberBus {
    #[inline(always)]
    fn read_u8(&mut self, addr: u32) -> u8 {
        self.mem.read_u8(addr)
    }

    #[inline(always)]
    fn write_u8(&mut self, addr: u32, val: u8) {
        self.mem.write_u8(addr, val);
    }

    fn port_in(&mut self, port: u16, _size: u8) -> u32 {
        match port {
            // VGA Input Status 1 / Vertical Retrace
            0x3DA => {
                self.vblank_bit = !self.vblank_bit;
                if self.vblank_bit {
                    self.frame_completed = true;
                    0x08
                } else {
                    0x00
                }
            }
            // OPL3 status delay reads
            0x388..=0x38B => 0x00,
            _ => 0x00,
        }
    }

    fn port_out(&mut self, port: u16, val: u32, _size: u8) {
        match port {
            // VGA Palette DAC Write Index
            0x3C8 => {
                self.dac_index = val as u8;
                self.dac_step = 0;
            }
            // VGA Palette DAC Data (6-bit RGB)
            0x3C9 => {
                let v6 = val as u8 & 0x3F;
                let v8 = (v6 * 4) + (v6 >> 4);
                match self.dac_step {
                    0 => {
                        self.dac_r = v8;
                        self.dac_step = 1;
                    }
                    1 => {
                        self.dac_g = v8;
                        self.dac_step = 2;
                    }
                    2 => {
                        let b = v8;
                        let color32 = ((self.dac_r as u32) << 16) | ((self.dac_g as u32) << 8) | (b as u32);
                        self.dac_palette[self.dac_index as usize] = color32;
                        self.dac_index = self.dac_index.wrapping_add(1);
                        self.dac_step = 0;
                    }
                    _ => unreachable!(),
                }
            }
            // OPL3 FM Synthesizer (accepted and ignored for now)
            0x388..=0x38B => {}
            _ => {}
        }
    }
}

fn read_dos_string(bus: &CyberBus, seg: u16, off: u16) -> String {
    let mut s = String::new();
    let mut cur = off;
    loop {
        let linear = ((seg as u32) << 4) + cur as u32;
        let b = bus.mem.data[(linear as usize) & 0x000F_FFFF];
        if b == 0 {
            break;
        }
        s.push(b as char);
        cur = cur.wrapping_add(1);
    }
    s
}

fn load_mz_exe(exe_path: &Path, potato_patch: Option<&Path>) -> std::io::Result<(Cpu, CyberBus)> {
    let mut f = File::open(exe_path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;

    if data.len() < 512 || &data[0..2] != b"MZ" {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Not an MZ executable"));
    }

    let n_relocs = u16::from_le_bytes([data[6], data[7]]) as usize;
    let hdr_paragraphs = u16::from_le_bytes([data[8], data[9]]) as usize;
    let ss = u16::from_le_bytes([data[14], data[15]]);
    let sp = u16::from_le_bytes([data[16], data[17]]);
    let ip = u16::from_le_bytes([data[20], data[21]]);
    let cs = u16::from_le_bytes([data[22], data[23]]);
    let reloc_table_offset = u16::from_le_bytes([data[24], data[25]]) as usize;

    let hdr_bytes = hdr_paragraphs * 16;
    let image_bytes = &data[hdr_bytes..];

    let exe_dir = exe_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let scratch_dir = PathBuf::from("studio/re/work/rust/frames");
    let mut bus = CyberBus::new(exe_dir, scratch_dir);

    // Load image at physical address (LOAD_SEG << 4)
    let load_base = (LOAD_SEG as u32) << 4;
    for (i, &b) in image_bytes.iter().enumerate() {
        let addr = load_base + i as u32;
        bus.mem.write_u8(addr, b);
    }

    // Apply relocations
    for i in 0..n_relocs {
        let entry_off = reloc_table_offset + i * 4;
        let rel_off = u16::from_le_bytes([data[entry_off], data[entry_off + 1]]);
        let rel_seg = u16::from_le_bytes([data[entry_off + 2], data[entry_off + 3]]);
        let target_linear = ((rel_seg as u32 + LOAD_SEG as u32) << 4) + rel_off as u32;
        let orig_word = bus.mem.read_u16(target_linear);
        bus.mem.write_u16(target_linear, orig_word.wrapping_add(LOAD_SEG));
    }

    // Apply Potato Patch if requested
    if let Some(patch_path) = potato_patch {
        apply_potato_patch(&mut bus, load_base, patch_path)?;
    }

    // Initialize CPU context
    let mut cpu = Cpu::new();
    cpu.cs = LOAD_SEG.wrapping_add(cs);
    cpu.ip = ip;
    cpu.ss = LOAD_SEG.wrapping_add(ss);
    cpu.esp = sp as u32;
    cpu.ds = LOAD_SEG.wrapping_sub(0x10); // PSP segment
    cpu.es = LOAD_SEG.wrapping_sub(0x10);

    Ok((cpu, bus))
}

fn apply_potato_patch(bus: &mut CyberBus, load_base: u32, patch_path: &Path) -> std::io::Result<()> {
    let mut patch_str = String::new();
    File::open(patch_path)?.read_to_string(&mut patch_str)?;

    // Minimal JSON parsing for file_offset and new_hex
    let mut file_offset: Option<u32> = None;
    let mut new_hex: Option<String> = None;

    for line in patch_str.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("\"file_offset\":") {
            let val_part = trimmed["\"file_offset\":".len()..].trim_matches(|c: char| c.is_whitespace() || c == ',');
            if let Ok(num) = val_part.parse::<u32>() {
                file_offset = Some(num);
            }
        } else if trimmed.starts_with("\"new_hex\":") {
            let val_part = trimmed["\"new_hex\":".len()..].trim_matches(|c: char| c.is_whitespace() || c == '"' || c == ',');
            new_hex = Some(val_part.to_string());
        }
    }

    if let (Some(foff), Some(hex)) = (file_offset, new_hex) {
        if foff >= 512 {
            let image_offset = foff - 512;
            let target_phys = load_base + image_offset;
            let mut bytes = Vec::new();
            for i in (0..hex.len()).step_by(2) {
                if i + 2 <= hex.len() {
                    if let Ok(b) = u8::from_str_radix(&hex[i..i+2], 16) {
                        bytes.push(b);
                    }
                }
            }
            println!("  [POTATO] Applying {} patched bytes at physical 0x{:05X} (image offset 0x{:04X})",
                bytes.len(), target_phys, image_offset);
            for (i, &b) in bytes.iter().enumerate() {
                bus.mem.write_u8(target_phys + i as u32, b);
            }
        }
    } else {
        eprintln!("  [WARN] Failed to parse potato patch JSON: {:?}", patch_path);
    }
    Ok(())
}

fn render_vram_to_rgb(bus: &CyberBus, out_rgb: &mut [u32; 320 * 200]) {
    let vram_start = 0x000A_0000;
    for i in 0..(320 * 200) {
        let pal_idx = bus.mem.data[vram_start + i] as usize;
        out_rgb[i] = bus.dac_palette[pal_idx];
    }
}

fn write_ppm(path: &Path, rgb: &[u32; 320 * 200]) -> std::io::Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "P6\n320 200\n255")?;
    for &c in rgb {
        let r = ((c >> 16) & 0xFF) as u8;
        let g = ((c >> 8) & 0xFF) as u8;
        let b = (c & 0xFF) as u8;
        f.write_all(&[r, g, b])?;
    }
    Ok(())
}

fn sha256_block(h: &mut [u32; 8], block: &[u8]) {
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0x0bef9a3f, 0xc67178f2,
    ];

    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut h_val = h[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h_val.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h_val = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(h_val);
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = [
        0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut chunk = [0u8; 64];
    let mut offset = 0;

    while offset + 64 <= data.len() {
        chunk.copy_from_slice(&data[offset..offset + 64]);
        sha256_block(&mut h, &chunk);
        offset += 64;
    }

    let remainder = &data[offset..];
    let mut padded = [0u8; 128];
    padded[..remainder.len()].copy_from_slice(remainder);
    padded[remainder.len()] = 0x80;

    let pad_len = if remainder.len() < 56 { 64 } else { 128 };
    padded[pad_len - 8..pad_len].copy_from_slice(&bit_len.to_be_bytes());

    sha256_block(&mut h, &padded[..64]);
    if pad_len == 128 {
        sha256_block(&mut h, &padded[64..128]);
    }

    let mut out = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if (crc & 1) != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn write_png_chunk(file: &mut File, tag: &[u8; 4], data: &[u8]) -> std::io::Result<()> {
    file.write_all(&(data.len() as u32).to_be_bytes())?;
    file.write_all(tag)?;
    file.write_all(data)?;
    let mut crc_buf = Vec::with_capacity(4 + data.len());
    crc_buf.extend_from_slice(tag);
    crc_buf.extend_from_slice(data);
    file.write_all(&crc32(&crc_buf).to_be_bytes())?;
    Ok(())
}

fn write_png(path: &Path, rgb: &[u32; 320 * 200]) -> std::io::Result<()> {
    let mut raw = Vec::with_capacity(200 * (1 + 320 * 4));
    for y in 0..200 {
        raw.push(0); // filter type None
        for x in 0..320 {
            let c = rgb[y * 320 + x];
            raw.push(((c >> 16) & 0xFF) as u8); // R
            raw.push(((c >> 8) & 0xFF) as u8);  // G
            raw.push((c & 0xFF) as u8);         // B
            raw.push(0xFF);                     // A
        }
    }

    let mut zlib_data = Vec::new();
    zlib_data.push(0x78);
    zlib_data.push(0x01);
    let chunk_size = 65535;
    let chunks: Vec<&[u8]> = raw.chunks(chunk_size).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let is_last = i == chunks.len() - 1;
        zlib_data.push(if is_last { 0x01 } else { 0x00 });
        let len = chunk.len() as u16;
        let nlen = !len;
        zlib_data.extend_from_slice(&len.to_le_bytes());
        zlib_data.extend_from_slice(&nlen.to_le_bytes());
        zlib_data.extend_from_slice(chunk);
    }

    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for &b in &raw {
        s1 = (s1 + b as u32) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    let adler = (s2 << 16) | s1;
    zlib_data.extend_from_slice(&adler.to_be_bytes());

    let mut file = File::create(path)?;
    file.write_all(b"\x89PNG\r\n\x1a\n")?;

    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&320u32.to_be_bytes());
    ihdr.extend_from_slice(&200u32.to_be_bytes());
    ihdr.push(8);
    ihdr.push(6); // RGBA
    ihdr.push(0);
    ihdr.push(0);
    ihdr.push(0);
    write_png_chunk(&mut file, b"IHDR", &ihdr)?;
    write_png_chunk(&mut file, b"IDAT", &zlib_data)?;
    write_png_chunk(&mut file, b"IEND", &[])?;
    Ok(())
}

#[derive(Clone, Debug)]
enum ScriptAction {
    Key(u16),
    MouseMove { dx: i16, dy: i16 },
    MouseClick,
    MouseDown,
    MouseUp,
}

fn parse_script(s: &str) -> BTreeMap<u64, Vec<ScriptAction>> {
    let mut map: BTreeMap<u64, Vec<ScriptAction>> = BTreeMap::new();
    for item in s.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.is_empty() {
            continue;
        }
        if let Ok(frame) = parts[0].trim().parse::<u64>() {
            if parts.len() == 2 {
                let act_str = parts[1].trim().to_lowercase();
                match act_str.as_str() {
                    "click" | "lmb" => {
                        map.entry(frame).or_default().push(ScriptAction::MouseClick);
                    }
                    "lmb_down" | "down_btn" => {
                        map.entry(frame).or_default().push(ScriptAction::MouseDown);
                    }
                    "lmb_up" | "up_btn" => {
                        map.entry(frame).or_default().push(ScriptAction::MouseUp);
                    }
                    "enter" => {
                        map.entry(frame).or_default().push(ScriptAction::Key(0x1C0D));
                    }
                    "space" => {
                        map.entry(frame).or_default().push(ScriptAction::Key(0x3920));
                    }
                    "esc" | "escape" => {
                        map.entry(frame).or_default().push(ScriptAction::Key(0x011B));
                    }
                    "up" => {
                        map.entry(frame).or_default().push(ScriptAction::Key(0x4800));
                    }
                    "down" => {
                        map.entry(frame).or_default().push(ScriptAction::Key(0x5000));
                    }
                    "left" => {
                        map.entry(frame).or_default().push(ScriptAction::Key(0x4B00));
                    }
                    "right" => {
                        map.entry(frame).or_default().push(ScriptAction::Key(0x4D00));
                    }
                    "p" => {
                        map.entry(frame).or_default().push(ScriptAction::Key(0x1970));
                    }
                    "y" => {
                        map.entry(frame).or_default().push(ScriptAction::Key(0x1579));
                    }
                    "n" => {
                        map.entry(frame).or_default().push(ScriptAction::Key(0x316E));
                    }
                    "backspace" => {
                        map.entry(frame).or_default().push(ScriptAction::Key(0x0E08));
                    }
                    hex_str => {
                        let sc = u16::from_str_radix(hex_str.trim_start_matches("0x"), 16).unwrap_or(0x1C0D);
                        map.entry(frame).or_default().push(ScriptAction::Key(sc));
                    }
                }
            } else if parts.len() == 3 {
                // e.g. frame:m:dx,dy or frame:click:dx,dy
                let p1 = parts[1].trim().to_lowercase();
                if p1 == "m" || p1 == "mouse" {
                    let subparts: Vec<&str> = parts[2].trim().split(',').collect();
                    let dx = subparts.get(0).and_then(|v| v.trim().parse::<i16>().ok()).unwrap_or(0);
                    let dy = subparts.get(1).and_then(|v| v.trim().parse::<i16>().ok()).unwrap_or(0);
                    map.entry(frame).or_default().push(ScriptAction::MouseMove { dx, dy });
                }
            } else if parts.len() == 4 {
                // e.g. frame:m:dx:dy
                let p1 = parts[1].trim().to_lowercase();
                if p1 == "m" || p1 == "mouse" {
                    let dx = parts[2].trim().parse::<i16>().unwrap_or(0);
                    let dy = parts[3].trim().parse::<i16>().unwrap_or(0);
                    map.entry(frame).or_default().push(ScriptAction::MouseMove { dx, dy });
                }
            }
        }
    }
    map
}

struct AutoplayBot {
    prev_ball_y: [u16; 16],
    hit_offset: i32,
    held_frames: u64,
}

impl AutoplayBot {
    fn new() -> Self {
        Self {
            prev_ball_y: [0; 16],
            hit_offset: 6,
            held_frames: 0,
        }
    }

    fn update(&mut self, frame: u64, bus: &mut CyberBus, key_queue: &mut VecDeque<u16>, momentary_click: &mut bool) {
        // Automatic navigation through introductory menus to reach Level 1-1
        if frame == 700 || frame == 750 || frame == 790 {
            key_queue.push_back(0x1C0D); // Enter
            return;
        }

        if frame < 820 {
            return;
        }

        let ds_phys = ((LOAD_SEG + 0x0575) as u32) << 4; // 0x15750

        // Check held ball: DS:0x8780 (physical 0x1DED0)
        let held_ball_slot = bus.read_u16(ds_phys + 0x8780);
        if held_ball_slot != 0 {
            self.held_frames += 1;
            // Launch held ball at frame 910 or when held for ~120 frames
            if frame == 910 || self.held_frames >= 120 {
                bus.mouse_buttons |= 1;
                bus.mouse_left_press_count = bus.mouse_left_press_count.saturating_add(1);
                *momentary_click = true;
                self.held_frames = 0;
            }
        } else {
            self.held_frames = 0;
        }

        // Read paddle state
        let paddle_x_sub = bus.read_u16(ds_phys + 0x8778); // in 1/64 pixel
        let is_wide = bus.read_u16(ds_phys + 0x877A) != 0;
        let paddle_center_offset_px = if is_wide { 38 } else { 28 };
        let paddle_center_px = (paddle_x_sub >> 6) as i32 + paddle_center_offset_px;

        // Ball array at DS:0x85CA (physical 0x1DD1A), 16 slots of 12 bytes
        let ball_base = ds_phys + 0x85CA;
        let mut max_descending_y = -1;
        let mut max_active_y = -1;
        let mut best_descending: Option<i32> = None;
        let mut best_active: Option<i32> = None;

        for i in 0..16 {
            let slot_addr = ball_base + (i * 12) as u32;
            let active = bus.read_u16(slot_addr + 6) != 0;
            if active {
                let x_sub = bus.read_u16(slot_addr + 0);
                let y_sub = bus.read_u16(slot_addr + 2);
                let x_px = (x_sub >> 6) as i32;
                let y_px = (y_sub >> 6) as i32;

                let prev_y = self.prev_ball_y[i];
                let is_descending = y_sub > prev_y;
                self.prev_ball_y[i] = y_sub;

                if is_descending && y_px > max_descending_y {
                    max_descending_y = y_px;
                    best_descending = Some(x_px);
                }
                if y_px > max_active_y {
                    max_active_y = y_px;
                    best_active = Some(x_px);
                }
            } else {
                self.prev_ball_y[i] = 0;
            }
        }

        let target_x_px = if let Some(bx) = best_descending {
            bx
        } else if let Some(bx) = best_active {
            bx
        } else {
            160 // Default to playfield center if no balls active
        };

        // Paddle target center with alternating hit offset
        let target_paddle_center = target_x_px - self.hit_offset;
        let error_px = target_paddle_center - paddle_center_px;

        // P-controller: about 0.5 px per mickey -> 2 mickeys per pixel error
        // Clamped to +/- 30 mickeys per frame
        let mickeys = (error_px * 2).clamp(-30, 30) as i16;
        bus.mouse_mickeys_x = bus.mouse_mickeys_x.saturating_add(mickeys);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut exe_path: Option<PathBuf> = None;
    let mut frames_limit: Option<u64> = None;
    let mut dump_path: Option<PathBuf> = None;
    let mut script_str: Option<String> = None;
    let mut potato_path: Option<PathBuf> = None;
    let mut record_path: Option<PathBuf> = None;
    let mut record_start: u64 = 0;
    let mut autoplay = false;
    let mut headless = false;
    let mut rust_routines_str: Option<String> = None;
    let mut frame_hashes_path: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--exe" => {
                i += 1;
                if i < args.len() { exe_path = Some(PathBuf::from(&args[i])); }
            }
            "--frames" => {
                i += 1;
                if i < args.len() { frames_limit = args[i].parse::<u64>().ok(); }
            }
            "--dump" => {
                i += 1;
                if i < args.len() { dump_path = Some(PathBuf::from(&args[i])); }
            }
            "--script" => {
                i += 1;
                if i < args.len() { script_str = Some(args[i].clone()); }
            }
            "--potato" => {
                i += 1;
                if i < args.len() { potato_path = Some(PathBuf::from(&args[i])); }
            }
            "--record" => {
                i += 1;
                if i < args.len() { record_path = Some(PathBuf::from(&args[i])); }
            }
            "--record-start" => {
                i += 1;
                if i < args.len() { record_start = args[i].parse::<u64>().unwrap_or(0); }
            }
            "--autoplay" => {
                autoplay = true;
            }
            "--headless" => {
                headless = true;
            }
            "--rust-routines" => {
                i += 1;
                if i < args.len() { rust_routines_str = Some(args[i].clone()); }
            }
            "--frame-hashes" => {
                i += 1;
                if i < args.len() { frame_hashes_path = Some(PathBuf::from(&args[i])); }
            }
            _ => {
                if exe_path.is_none() && !args[i].starts_with("--") {
                    exe_path = Some(PathBuf::from(&args[i]));
                }
            }
        }
        i += 1;
    }

    let exe = match exe_path {
        Some(p) => p,
        None => {
            eprintln!("Usage: cyber --exe <CYBER.EXE> [--frames N] [--dump <out.png|ppm>] [--script <f:k,...>] [--potato <patch.json>] [--headless] [--record <out.mp4>] [--record-start N] [--autoplay] [--rust-routines <all|list>] [--frame-hashes <out.hashes>]");
            std::process::exit(1);
        }
    };

    let (rust_routines_active, hook_mask) = if let Some(ref r_str) = rust_routines_str {
        (true, cyber_rs::routines::HookMask::parse(r_str))
    } else {
        (false, cyber_rs::routines::HookMask::default())
    };
    let mut hook_call_counts = [0u64; 5];

    println!("============================================================");
    println!(" cyber-rs Native x86 Real-Mode Runner");
    println!(" Target: {}", exe.display());
    if let Some(ref p) = potato_path {
        println!(" Potato Mode: ACTIVE ({})", p.display());
    }
    if autoplay {
        println!(" Autoplay Bot: ACTIVE");
    }
    if rust_routines_active {
        println!(" Hybrid Rust Routines: ACTIVE");
        println!("   PRNG (0x4506):           {}", if hook_mask.prng { "HOOKED" } else { "interpreter" });
        println!("   Paddle Bounce (0x3477):  {}", if hook_mask.paddle_bounce { "HOOKED" } else { "interpreter" });
        println!("   Multiball (0x21FC):      {}", if hook_mask.multiball { "HOOKED" } else { "interpreter" });
        println!("   Trig Collision (0x34B7): {}", if hook_mask.trig_step { "HOOKED" } else { "interpreter" });
        println!("   Brick Grid Hit (0x35BA): {}", if hook_mask.brick_hit { "HOOKED" } else { "interpreter" });
    }
    if let Some(ref rec) = record_path {
        println!(" Video Record: ACTIVE (out: {}, start_frame: {})", rec.display(), record_start);
    }
    println!("============================================================");

    let (mut cpu, mut bus) = match load_mz_exe(&exe, potato_path.as_deref()) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("[ERROR] Failed to load executable: {}", e);
            std::process::exit(1);
        }
    };

    // Spawn ffmpeg child process if video recording requested
    let mut ffmpeg_child: Option<std::process::Child> = None;
    let mut ffmpeg_stdin: Option<std::process::ChildStdin> = None;
    if let Some(ref rec_path) = record_path {
        if let Some(parent) = rec_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut cmd = std::process::Command::new("ffmpeg");
        cmd.arg("-y")
           .arg("-loglevel").arg("error")
           .arg("-f").arg("rawvideo")
           .arg("-pix_fmt").arg("rgb24")
           .arg("-s").arg("320x200")
           .arg("-r").arg("70")
           .arg("-i").arg("-")
           .arg("-vf").arg("scale=640:400:flags=neighbor")
           .arg("-c:v").arg("libx264")
           .arg("-pix_fmt").arg("yuv420p")
           .arg("-crf").arg("16")
           .arg(rec_path)
           .stdin(std::process::Stdio::piped());
        match cmd.spawn() {
            Ok(mut child) => {
                ffmpeg_stdin = child.stdin.take();
                ffmpeg_child = Some(child);
                println!("  [RECORD] Spawned ffmpeg pipe to {}", rec_path.display());
            }
            Err(e) => {
                eprintln!("  [ERROR] Failed to spawn ffmpeg: {}", e);
            }
        }
    }

    let scripted_input = script_str.map(|s| parse_script(&s)).unwrap_or_default();
    let mut autoplay_bot = if autoplay { Some(AutoplayBot::new()) } else { None };
    let mut key_queue: VecDeque<u16> = VecDeque::new();
    let mut frame_count: u64 = 0;
    let mut rgb_buffer = [0u32; 320 * 200];
    let mut paddle_bounces: u64 = 0;
    let mut bricks_destroyed: u64 = 0;
    let mut initial_lives: Option<u16> = None;
    let mut recorded_frames_count: u64 = 0;

    // Optional minifb window
    let mut window = if !headless {
        match minifb::Window::new(
            "CYBERSPHERE (Rust, native)",
            640,
            400,
            minifb::WindowOptions {
                scale: minifb::Scale::X2,
                resize: false,
                ..minifb::WindowOptions::default()
            },
        ) {
            Ok(mut w) => {
                w.limit_update_rate(Some(std::time::Duration::from_micros(14285))); // ~70 Hz
                Some(w)
            }
            Err(e) => {
                eprintln!("[WARN] Could not create minifb window (falling back to headless): {}", e);
                None
            }
        }
    } else {
        None
    };

    let mut prev_mouse_pos: Option<(f32, f32)> = None;
    let mut prev_l_down = false;
    let mut prev_r_down = false;
    let mut momentary_script_click = false;
    let mut last_reported_score = 0u32;

    let mut frame_hashes_file: Option<File> = if let Some(ref fh_path) = frame_hashes_path {
        if let Some(parent) = fh_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match File::create(fh_path) {
            Ok(f) => {
                println!("  Frame Hashes: ACTIVE (output: {})", fh_path.display());
                Some(f)
            }
            Err(e) => {
                eprintln!("  [ERROR] Could not create frame hashes file: {}", e);
                None
            }
        }
    } else {
        None
    };

    println!("  Execution started at CS:IP = {:04X}:{:04X}", cpu.cs, cpu.ip);

    let mut total_instructions: u64 = 0;
    let start_instant = std::time::Instant::now();

    let mut last_traced_ip = 0xFFFFu16;

    loop {
        if cpu.cs == LOAD_SEG && cpu.ip != last_traced_ip {
            match cpu.ip {
                0x046C => println!("  [TRACE frame={}] Entered splash logo (0x046C)", frame_count),
                0x0567 => println!("  [TRACE frame={}] Entered title menu (0x0567)", frame_count),
                0x0129 => println!("  [TRACE frame={}] Entered game_session_main (0x0129)", frame_count),
                0x1182 => println!("  [TRACE frame={}] Entered sector_select_screen (0x1182)", frame_count),
                0x0A54 => println!("  [TRACE frame={}] Entered stage splash (0x0A54)", frame_count),
                0x1D30 => println!("  [TRACE frame={}] Entered run_level_loop (0x1D30)", frame_count),
                0x21FC => println!("  [TRACE frame={}] Called spawn_multiball (0x21FC)", frame_count),
                0x3477 => {
                    let held = bus.read_u16(0x15750 + 0x8780);
                    if held == 0 {
                        paddle_bounces += 1;
                        if let Some(ref mut bot) = autoplay_bot {
                            bot.hit_offset = -bot.hit_offset;
                        }
                        println!("  [BOUNCE frame={}] Paddle bounce #{}", frame_count, paddle_bounces);
                    }
                }
                0x23A4 => {
                    bricks_destroyed += 1;
                    println!("  [BRICK frame={}] Brick destroyed #{}", frame_count, bricks_destroyed);
                }
                _ => {}
            }
            last_traced_ip = cpu.ip;
        }

        let step_res = if rust_routines_active && cyber_rs::routines::try_dispatch_hook(&mut cpu, &mut bus, LOAD_SEG, &hook_mask, &mut hook_call_counts) {
            StepResult::Ok
        } else {
            cpu.step(&mut bus)
        };
        total_instructions += 1;

        match step_res {
            StepResult::Ok => {}
            StepResult::PortIn { port, size } => {
                let val = bus.port_in(port, size);
                match size {
                    1 => cpu.set_al(val as u8),
                    2 => cpu.set_ax(val as u16),
                    4 => cpu.eax = val,
                    _ => {}
                }
            }
            StepResult::PortOut { port, val, size } => {
                bus.port_out(port, val, size);
            }
            StepResult::Int(vector) => {
                match vector {
                    // BIOS Video
                    0x10 => {
                        // AX = 0013h (Mode 13h) or AX = 0003h (Text mode)
                        cpu.set_ax(0);
                    }
                    // Keyboard Services
                    0x16 => {
                        let ah = cpu.ah();
                        if ah == 0x01 {
                            // Check keystroke
                            if let Some(&k) = key_queue.front() {
                                cpu.set_zf(false);
                                cpu.set_ax(k);
                            } else {
                                cpu.set_zf(true);
                            }
                        } else if ah == 0x00 {
                            // Read keystroke
                            let k = key_queue.pop_front().unwrap_or(0);
                            println!("  [KEY frame={}] Read key 0x{:04X} at CS:IP={:04X}:{:04X}", frame_count, k, cpu.cs, cpu.ip);
                            cpu.set_ax(k);
                        }
                    }
                    // Mouse Services
                    0x33 => {
                        let ax = cpu.ax();
                        match ax {
                            0x0000 => {
                                // Reset / installed check
                                cpu.set_ax(0xFFFF); // Driver present
                                cpu.set_bx(2);      // 2 buttons
                            }
                            0x0003 => {
                                // Return position and button status
                                cpu.set_bx(bus.mouse_buttons);
                                cpu.set_cx(bus.mouse_x.wrapping_mul(2));
                                cpu.set_dx(bus.mouse_y);
                                cpu.set_ax(0);
                            }
                            0x0005 => {
                                // Return button press information
                                let btn = cpu.bx();
                                let cur_btn = bus.mouse_buttons | if bus.mouse_left_press_count > 0 { 1 } else { 0 };
                                cpu.set_ax(cur_btn);
                                if btn == 0 {
                                    cpu.set_bx(bus.mouse_left_press_count);
                                    bus.mouse_left_press_count = 0;
                                } else if btn == 1 {
                                    cpu.set_bx(bus.mouse_right_press_count);
                                    bus.mouse_right_press_count = 0;
                                } else {
                                    cpu.set_bx(0);
                                }
                                cpu.set_cx(bus.mouse_x.wrapping_mul(2));
                                cpu.set_dx(bus.mouse_y);
                            }
                            0x000B => {
                                // Read motion counters (mickeys)
                                cpu.set_cx(bus.mouse_mickeys_x as u16);
                                cpu.set_dx(bus.mouse_mickeys_y as u16);
                                bus.mouse_mickeys_x = 0;
                                bus.mouse_mickeys_y = 0;
                                cpu.set_ax(0);
                            }
                            0x0013 => {
                                // Set double speed threshold
                                cpu.set_ax(0);
                            }
                            _ => {
                                cpu.set_ax(0);
                            }
                        }
                    }
                    // DOS Services
                    0x21 => {
                        let ah = cpu.ah();
                        match ah {
                            // Open File
                            0x3D => {
                                let filename = read_dos_string(&bus, cpu.ds, cpu.dx());
                                let file_path = bus.exe_dir.join(&filename);
                                match File::open(&file_path) {
                                    Ok(f) => {
                                        let h = bus.next_handle;
                                        bus.next_handle += 1;
                                        bus.open_files.insert(h, f);
                                        cpu.set_ax(h);
                                        cpu.set_cf(false);
                                    }
                                    Err(_) => {
                                        // Case-insensitive fallback
                                        let mut found = None;
                                        if let Ok(entries) = std::fs::read_dir(&bus.exe_dir) {
                                            for entry in entries.flatten() {
                                                if entry.file_name().to_string_lossy().eq_ignore_ascii_case(&filename) {
                                                    found = Some(entry.path());
                                                    break;
                                                }
                                            }
                                        }
                                        if let Some(p) = found {
                                            if let Ok(f) = File::open(&p) {
                                                let h = bus.next_handle;
                                                bus.next_handle += 1;
                                                bus.open_files.insert(h, f);
                                                cpu.set_ax(h);
                                                cpu.set_cf(false);
                                                continue;
                                            }
                                        }
                                        cpu.set_ax(2); // File not found
                                        cpu.set_cf(true);
                                    }
                                }
                            }
                            // Read File
                            0x3F => {
                                let h = cpu.bx();
                                let count = cpu.cx() as usize;
                                let dest_linear = ((cpu.ds as u32) << 4) + cpu.dx() as u32;
                                if let Some(f) = bus.open_files.get_mut(&h) {
                                    let mut buf = vec![0u8; count];
                                    match f.read(&mut buf) {
                                        Ok(n) => {
                                            for j in 0..n {
                                                bus.mem.write_u8(dest_linear + j as u32, buf[j]);
                                            }
                                            cpu.set_ax(n as u16);
                                            cpu.set_cf(false);
                                        }
                                        Err(_) => {
                                            cpu.set_ax(0);
                                            cpu.set_cf(true);
                                        }
                                    }
                                } else {
                                    cpu.set_ax(6); // Invalid handle
                                    cpu.set_cf(true);
                                }
                            }
                            // Close File
                            0x3E => {
                                let h = cpu.bx();
                                bus.open_files.remove(&h);
                                cpu.set_ax(0);
                                cpu.set_cf(false);
                            }
                            // Create File
                            0x3C => {
                                let filename = read_dos_string(&bus, cpu.ds, cpu.dx());
                                let scratch_file = bus.scratch_dir.join(&filename);
                                let _ = std::fs::create_dir_all(&bus.scratch_dir);
                                match File::create(&scratch_file) {
                                    Ok(f) => {
                                        let h = bus.next_handle;
                                        bus.next_handle += 1;
                                        bus.open_files.insert(h, f);
                                        cpu.set_ax(h);
                                        cpu.set_cf(false);
                                    }
                                    Err(_) => {
                                        cpu.set_ax(4); // Too many open files
                                        cpu.set_cf(true);
                                    }
                                }
                            }
                            // Write File
                            0x40 => {
                                let h = cpu.bx();
                                let count = cpu.cx() as usize;
                                let src_linear = ((cpu.ds as u32) << 4) + cpu.dx() as u32;
                                if let Some(f) = bus.open_files.get_mut(&h) {
                                    let mut buf = vec![0u8; count];
                                    for j in 0..count {
                                        buf[j] = bus.mem.read_u8(src_linear + j as u32);
                                    }
                                    let _ = f.write_all(&buf);
                                    cpu.set_ax(count as u16);
                                    cpu.set_cf(false);
                                } else {
                                    cpu.set_ax(6);
                                    cpu.set_cf(true);
                                }
                            }
                            // Print '$'-terminated string
                            0x09 => {
                                let mut s = String::new();
                                let mut cur = cpu.dx();
                                loop {
                                    let linear = ((cpu.ds as u32) << 4) + cur as u32;
                                    let b = bus.mem.read_u8(linear);
                                    if b == b'$' { break; }
                                    s.push(b as char);
                                    cur = cur.wrapping_add(1);
                                }
                                print!("{}", s);
                            }
                            // Exit Process
                            0x4C => {
                                println!("\n[EXIT] Guest process called int 21h AH=4Ch with exit code {}", cpu.al());
                                break;
                            }
                            _ => {
                                cpu.set_ax(0);
                                cpu.set_cf(false);
                            }
                        }
                    }
                    _ => {}
                }
            }
            StepResult::Halt => {
                println!("[HALT] CPU halted");
                break;
            }
            StepResult::Fault(f) => {
                let phys = ((cpu.cs as u32) << 4) + cpu.ip as u32;
                let b0 = bus.mem.read_u8(phys);
                let b1 = bus.mem.read_u8(phys + 1);
                let b2 = bus.mem.read_u8(phys + 2);
                eprintln!("[FAULT] CPU stopped at CS:IP={:04X}:{:04X} (phys 0x{:05X}) bytes=[{:02X}, {:02X}, {:02X}]: {:?}",
                    cpu.cs, cpu.ip, phys, b0, b1, b2, f);
                break;
            }
        }

        // Frame boundary check (vblank wait completed)
        if bus.frame_completed {
            bus.frame_completed = false;
            frame_count += 1;

            if frame_count >= 820 && initial_lives.is_none() {
                initial_lives = Some(bus.read_u16(0x1DEF6));
            }

            if momentary_script_click {
                bus.mouse_buttons &= !1;
                momentary_script_click = false;
            }

            // Autoplay bot update
            if let Some(ref mut bot) = autoplay_bot {
                bot.update(frame_count, &mut bus, &mut key_queue, &mut momentary_script_click);
            }

            // Process scripted input for this frame
            if let Some(actions) = scripted_input.get(&frame_count) {
                for act in actions {
                    match act {
                        ScriptAction::Key(k) => key_queue.push_back(*k),
                        ScriptAction::MouseMove { dx, dy } => {
                            bus.mouse_mickeys_x = bus.mouse_mickeys_x.saturating_add(*dx);
                            bus.mouse_mickeys_y = bus.mouse_mickeys_y.saturating_add(*dy);
                        }
                        ScriptAction::MouseClick => {
                            bus.mouse_buttons |= 1;
                            bus.mouse_left_press_count = bus.mouse_left_press_count.saturating_add(1);
                            momentary_script_click = true;
                        }
                        ScriptAction::MouseDown => {
                            bus.mouse_buttons |= 1;
                            bus.mouse_left_press_count = bus.mouse_left_press_count.saturating_add(1);
                        }
                        ScriptAction::MouseUp => {
                            bus.mouse_buttons &= !1;
                        }
                    }
                }
            }

            // Window update and live user input if not headless
            if let Some(ref mut win) = window {
                // Live mouse position & deltas
                if let Some((mx, my)) = win.get_mouse_pos(minifb::MouseMode::Discard) {
                    let cur_x = mx.clamp(0.0, 639.0);
                    let cur_y = my.clamp(0.0, 399.0);
                    bus.mouse_x = (cur_x / 2.0) as u16;
                    bus.mouse_y = (cur_y / 2.0) as u16;

                    if let Some((px, py)) = prev_mouse_pos {
                        let dx = ((cur_x - px) / 2.0) as i16;
                        let dy = ((cur_y - py) / 2.0) as i16;
                        bus.mouse_mickeys_x = bus.mouse_mickeys_x.saturating_add(dx);
                        bus.mouse_mickeys_y = bus.mouse_mickeys_y.saturating_add(dy);
                    }
                    prev_mouse_pos = Some((cur_x, cur_y));
                }

                // Live mouse buttons
                let l_down = win.get_mouse_down(minifb::MouseButton::Left);
                let r_down = win.get_mouse_down(minifb::MouseButton::Right);
                if l_down { bus.mouse_buttons |= 1; } else if !momentary_script_click { bus.mouse_buttons &= !1; }
                if r_down { bus.mouse_buttons |= 2; } else { bus.mouse_buttons &= !2; }

                if l_down && !prev_l_down {
                    bus.mouse_left_press_count = bus.mouse_left_press_count.saturating_add(1);
                }
                if r_down && !prev_r_down {
                    bus.mouse_right_press_count = bus.mouse_right_press_count.saturating_add(1);
                }
                prev_l_down = l_down;
                prev_r_down = r_down;

                // Live window keyboard
                for key in win.get_keys_pressed(minifb::KeyRepeat::Yes) {
                    let scancode_ascii = match key {
                        minifb::Key::Enter => Some(0x1C0D),
                        minifb::Key::Escape => Some(0x011B),
                        minifb::Key::Space => Some(0x3920),
                        minifb::Key::P => Some(0x1970),
                        minifb::Key::Up => Some(0x4800),
                        minifb::Key::Down => Some(0x5000),
                        minifb::Key::Left => Some(0x4B00),
                        minifb::Key::Right => Some(0x4D00),
                        minifb::Key::Y => Some(0x1579),
                        minifb::Key::N => Some(0x316E),
                        minifb::Key::Backspace => Some(0x0E08),
                        _ => None,
                    };
                    if let Some(sc) = scancode_ascii {
                        key_queue.push_back(sc);
                    }
                }

                render_vram_to_rgb(&bus, &mut rgb_buffer);
                if win.update_with_buffer(&rgb_buffer, 320, 200).is_err() {
                    break;
                }
                if !win.is_open() {
                    break;
                }
            }

            // Pipe frame to ffmpeg if video recording active
            if frame_count >= record_start && (frames_limit.is_none() || frame_count <= frames_limit.unwrap()) {
                if let Some(ref mut stdin) = ffmpeg_stdin {
                    render_vram_to_rgb(&bus, &mut rgb_buffer);
                    let mut raw_frame = [0u8; 320 * 200 * 3];
                    for i in 0..(320 * 200) {
                        let c = rgb_buffer[i];
                        raw_frame[i * 3 + 0] = ((c >> 16) & 0xFF) as u8;
                        raw_frame[i * 3 + 1] = ((c >> 8) & 0xFF) as u8;
                        raw_frame[i * 3 + 2] = (c & 0xFF) as u8;
                    }
                    let _ = stdin.write_all(&raw_frame);
                    recorded_frames_count += 1;
                }
            }

            // Record frame hash if requested
            if let Some(ref mut f) = frame_hashes_file {
                render_vram_to_rgb(&bus, &mut rgb_buffer);
                let frame_bytes = unsafe {
                    std::slice::from_raw_parts(rgb_buffer.as_ptr() as *const u8, rgb_buffer.len() * 4)
                };
                let h = sha256(frame_bytes);
                let hex_str: String = h.iter().map(|b| format!("{:02x}", b)).collect();
                let _ = writeln!(f, "{}:{}", frame_count, hex_str);
            }

            // Track score changes during gameplay (score at DS:0x87A8 = physical 0x1DEF8)
            let cur_score = bus.read_u32(0x1DEF8);
            if cur_score != last_reported_score {
                println!("  [SCORE frame={}] Score updated: {} -> {}", frame_count, last_reported_score, cur_score);
                last_reported_score = cur_score;
            }

            // Target frame limit reached?
            if let Some(limit) = frames_limit {
                if frame_count >= limit {
                    println!("  [STOP] Target frame limit {} reached (total insns: {})", limit, total_instructions);
                    break;
                }
            }
        }
    }

    drop(ffmpeg_stdin);
    if let Some(mut child) = ffmpeg_child {
        let _ = child.wait();
        println!("  [RECORD] Recording finished. Total frames piped: {}", recorded_frames_count);
    }

    let elapsed = start_instant.elapsed();
    let cur_score = bus.read_u32(0x1DEF8);
    let cur_lives = bus.read_u16(0x1DEF6);
    let lives_lost = initial_lives.map(|init| init.saturating_sub(cur_lives)).unwrap_or(0);

    println!("============================================================");
    println!(" Simulation Completed:");
    println!("   Total Frames:       {}", frame_count);
    println!("   Total Instructions: {}", total_instructions);
    println!("   Elapsed Time:       {:.2}s ({:.1} frames/sec, {:.1}M insn/sec)",
        elapsed.as_secs_f64(),
        frame_count as f64 / elapsed.as_secs_f64().max(0.001),
        (total_instructions as f64 / elapsed.as_secs_f64().max(0.001)) / 1_000_000.0);
    println!("   Paddle Bounces:     {}", paddle_bounces);
    println!("   Bricks Destroyed:   {}", bricks_destroyed);
    println!("   Final Score:        {}", cur_score);
    println!("   Lives Lost:         {}", lives_lost);
    if rust_routines_active {
        println!(" Hook Dispatch Call Counts:");
        println!("   PRNG (0x4506):           {}", hook_call_counts[0]);
        println!("   Paddle Bounce (0x3477):  {}", hook_call_counts[1]);
        println!("   Multiball (0x21FC):      {}", hook_call_counts[2]);
        println!("   Trig Collision (0x34B7): {}", hook_call_counts[3]);
        println!("   Brick Grid Hit (0x35BA): {}", hook_call_counts[4]);
    }
    if let Some(ref p) = record_path {
        println!("   Recorded Video:     {} ({} frames)", p.display(), recorded_frames_count);
    }

    // Frame dump if requested
    if let Some(ref dump) = dump_path {
        render_vram_to_rgb(&bus, &mut rgb_buffer);
        if let Some(parent) = dump.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let ext = dump.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
        let res = if ext == "ppm" {
            write_ppm(dump, &rgb_buffer)
        } else {
            write_png(dump, &rgb_buffer)
        };
        match res {
            Ok(_) => println!("   Dumped Frame:       {}", dump.display()),
            Err(e) => eprintln!("   [ERROR] Failed to dump frame: {}", e),
        }
    }
    println!("============================================================");
}
