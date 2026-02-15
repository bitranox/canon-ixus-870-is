# Canon IXUS 870 IS — USB Webcam via CHDK

Turn a Canon IXUS 870 IS into a USB webcam streaming 640x480 video at ~5 FPS. Uses a custom CHDK module on the camera and a PC-side bridge application that presents a DirectShow virtual webcam device visible in Zoom, Teams, OBS, and any other video app.

**Camera:** Canon IXUS 870 IS / PowerShot SD880 IS / IXY DIGITAL 920 IS
**Firmware:** 1.01a (Digic IV, ARM926EJ-S, DryOS)
**Status:** v0.0.1 — working, stable streaming

## Performance

| Metric | Value |
|--------|-------|
| Resolution | 640x480 (native ISP output) |
| Frame rate | ~4.9 FPS sustained |
| Frame size | 614,400 bytes (uncompressed UYVY) |
| USB throughput | ~24 Mbps (~3 MB/s) |
| Dropped frames | 0 (stable over 5000+ frames) |
| Camera CPU encoding load | 0% (raw DMA passthrough) |
| Streaming duration | Unlimited (auto-power-off disabled) |

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  CANON IXUS 870 IS (Digic IV, ARM926EJ-S, DryOS)               │
│                                                                  │
│  CCD ──► ISP ──► Recording Pipeline (640x480 UYVY @ 30fps)     │
│  10MP    Image    DMA → 3 ring buffers in uncached RAM          │
│          Signal                  │                               │
│          Proc     rec_callback_spy ← pipeline callback @ 30fps  │
│                     │ captures UYVY buffer address (arg2)        │
│                     │                                            │
│                   capture_frame_uyvy()                           │
│                     │ word-aligned copy 614KB                    │
│                     │                                            │
│                   PTP opcode 0x9999 (GetMJPEGFrame)             │
│                     │ sends 614,400 bytes raw UYVY              │
│                     │ format in param4 high byte                 │
└─────────────────────┼────────────────────────────────────────────┘
                      │ USB 2.0 High Speed (480 Mbps)
┌─────────────────────┼────────────────────────────────────────────┐
│  PC (Windows)       │                                            │
│                     │                                            │
│  chdk-webcam.exe    │                                            │
│    PTPClient (libusb-1.0) ── receives raw UYVY frames           │
│    FrameProcessor ────────── BT.601 UYVY→RGB24 conversion       │
│    PreviewWindow ─────────── Win32 GDI live preview              │
│    VirtualWebcam ─────────── DirectShow "CHDK Webcam" device    │
└──────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

| Component | Purpose |
|-----------|---------|
| Canon IXUS 870 IS | Camera (firmware 1.01a) |
| SD card (≤2GB, FAT16) | CHDK boot medium |
| USB cable (Mini-B) | Camera to PC connection |
| Docker | CHDK cross-compilation |
| Visual Studio 2019/2022 | Bridge C++ build |
| vcpkg | Package manager for libusb + libjpeg-turbo |
| Zadig | USB driver replacement (libusb-win32) |

### 1. Build CHDK (camera firmware)

```bash
docker run --rm -v "/path/to/chdk:/srv/src" chdkbuild \
    make PLATFORM=ixus870_sd880 PLATFORMSUB=101a fir
```

Output: `chdk/bin/DISKBOOT.BIN` + `chdk/CHDK/MODULES/webcam.flt`

### 2. Build the bridge (PC application)

```batch
:: Install dependencies
C:\vcpkg\vcpkg install libusb:x64-windows libjpeg-turbo:x64-windows

:: Configure
cmake -B bridge\build -S bridge -G "Visual Studio 17 2022" -A x64 ^
    -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake

:: Build
cmake --build bridge\build --config Release
```

Output: `bridge/build/Release/chdk-webcam.exe`

### 3. Deploy to camera

1. Copy `DISKBOOT.BIN` to SD card root
2. Copy `webcam.flt` to `CHDK/MODULES/` on SD card
3. Insert SD card into camera (must be **unlocked**)
4. Boot camera in **Playback mode**
5. Load CHDK: MENU → Settings → press **UP arrow** → Firmware Ver. → confirm with FUNC.SET

> **Note:** "Firmware Ver." is hidden at the bottom of the Settings menu. You must press **UP** to jump past "Reset All" to reveal it.

### 4. Install USB driver

The camera must use the `libusb-win32` driver instead of the default Canon PTP driver:

1. Connect camera, power on, load CHDK
2. Run [Zadig](https://zadig.akeo.ie/)
3. Select "Canon Digital Camera"
4. Choose "libusb-win32" as target driver
5. Click "Replace Driver"

### 5. Stream

```bash
# Preview window + virtual webcam
chdk-webcam.exe

# Preview only (no virtual webcam device)
chdk-webcam.exe --no-webcam

# Mirror for selfie mode
chdk-webcam.exe --flip-h
```

The camera appears as **"CHDK Webcam"** in any video application.

## Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-q, --quality N` | 50 | JPEG quality (software fallback path only) |
| `--flip-h` | off | Mirror horizontally |
| `--flip-v` | off | Flip vertically |
| `--no-webcam` | off | Skip DirectShow virtual webcam |
| `--no-preview` | off | Skip preview window |
| `--verbose` | off | Per-frame statistics |

## How It Works

### Camera Side (CHDK Module)

The webcam module (`webcam.c`) performs these steps:

1. **Switch to video mode** — `switch_mode_usb(1)` then `shooting_set_mode_chdk(MODE_VIDEO_STD)` activates the ISP video pipeline at 640x480 UYVY @ 30fps internally.

2. **Activate recording pipeline** — `StartMjpegMaking()` enables the JPCORE subsystem, then `state[+0xD4] = 2` forces the `FrameProcessing` dispatcher to take the video recording path instead of the EVF/LCD path. Without this, no recording callbacks fire.

3. **Install callback spy** — A function pointer at `state[+0x114]` is set to `rec_callback_spy`, which receives the UYVY frame buffer address in `arg2` at 30fps. The firmware rotates through 3 DMA ring buffers in uncached RAM.

4. **Capture frames** — `capture_frame_uyvy()` copies 614KB from the DMA buffer using word-aligned transfer (~3ms). Stale frame detection skips duplicates.

5. **PTP transfer** — Frames are sent over USB using CHDK PTP opcode `0x9999` (sub-command 15). The frame format (UYVY vs JPEG) is encoded in the high byte of `param4`.

### PC Side (Bridge)

The bridge receives raw UYVY frames and:

1. **Converts color** — BT.601 fixed-point UYVY→RGB24 with Digic IV signed chroma handling
2. **Outputs to DirectShow** — Virtual webcam filter ("CHDK Webcam") visible in all video apps
3. **Shows preview** — Win32 GDI window for live monitoring

### Digic IV Signed Chroma

Digic IV stores U/V chroma as **signed int8** centered at 0 (range -128..+127), NOT unsigned centered at 128 (standard UYVY). You must interpret them as `int8_t`:

```cpp
// CORRECT — Digic IV signed chroma
int u = static_cast<int>(static_cast<int8_t>(src[0]));  // -128..+127
int v = static_cast<int>(static_cast<int8_t>(src[2]));  // -128..+127

// WRONG — produces green color cast on whites
int u = static_cast<int>(src[0]) - 128;
```

## Project Structure

```
├── CLAUDE.md                           Project documentation / dev notes
├── README.md                           This file
├── CHANGELOG.md                        Version history
│
├── chdk/                               CHDK source tree
│   ├── modules/
│   │   ├── webcam.c                    Webcam CHDK module (main)
│   │   ├── webcam.h                    Module interface
│   │   ├── tje.c                       Tiny JPEG Encoder (software fallback)
│   │   └── tje.h                       TJE header
│   ├── core/
│   │   └── ptp.c                       PTP handler (GetMJPEGFrame command)
│   └── platform/ixus870_sd880/sub/101a/
│       └── stubs_entry.S              Firmware function stubs
│
├── bridge/                             PC-side bridge application
│   ├── CMakeLists.txt                  CMake build config
│   └── src/
│       ├── main.cpp                    Entry point, streaming loop
│       ├── ptp/
│       │   ├── ptp_client.cpp          libusb PTP client
│       │   └── ptp_client.h            PTP/CHDK protocol definitions
│       └── webcam/
│           ├── frame_processor.cpp     BT.601 UYVY→RGB + JPEG decode
│           ├── frame_processor.h       Frame processor interface
│           ├── preview_window.cpp      Win32 GDI preview window
│           ├── preview_window.h        Preview window interface
│           ├── virtual_webcam.cpp      DirectShow virtual webcam
│           └── virtual_webcam.h        Virtual webcam interface
│
├── 640x480_raw/                        Snapshot of working source files
│
├── firmware-analysis/                  Ghidra RE scripts and output
│   ├── Decompile*.java                 Ghidra decompilation scripts
│   ├── ResolveDAT*.java                Data reference resolution scripts
│   └── *_decompiled.txt                Decompilation output
│
└── firmware-dumps/                     Canon firmware dump collection
```

## PTP Protocol

All webcam communication uses CHDK's vendor PTP opcode `0x9999` with sub-command 15 (`GetMJPEGFrame`).

### Start Streaming

```
Command:  opcode=0x9999, param1=15, param2=quality, param3=0x01
Response: param1=0 (success), param4=0xBEEF
Data:     576 bytes pipeline diagnostics
```

### Get Frame

```
Command:  opcode=0x9999, param1=15, param2=0, param3=0
Response: param1=frame_size, param2=width, param3=height,
          param4=(format<<24)|(frame_num & 0xFFFFFF)
Data:     frame_size bytes (UYVY or JPEG)
```

Format in `param4` high byte: `0x00` = JPEG, `0x01` = UYVY

### Stop Streaming

```
Command:  opcode=0x9999, param1=15, param2=0, param3=0x02
Response: param1=0
```

## Firmware Reverse Engineering

Extensive reverse engineering was performed on the IXUS 870 IS firmware (1.01a) using Ghidra. Key findings are documented in `firmware-analysis/` and include:

- **Video pipeline architecture** — ISP → FrameProcessing → recording callbacks
- **JPCORE hardware encoder** — state structures, power management, DMA configuration
- **ISP routing registers** — source selection, resizer, JPCORE pipeline modes
- **Recording callback chain** — how `state[+0xD4]` controls EVF vs video path
- **DMA buffer management** — triple ring buffer rotation in uncached RAM
- **~40 firmware functions decompiled** — pipeline, callbacks, state machine, power

### Key Firmware Addresses (fw 1.01a)

| Function | Address | Purpose |
|----------|---------|---------|
| `StartMjpegMaking` | `0xFF9E8DD8` | Activate recording pipeline |
| `StopMjpegMaking` | `0xFF9E8DF8` | Deactivate recording pipeline |
| `GetMovieJpegVRAMHPixelsSize` | `0xFF8C4178` | Returns frame width (640) |
| `GetMovieJpegVRAMVPixelsSize` | `0xFF8C4184` | Returns frame height (480) |
| `JPCORE_PowerInit` | `0xFF8EEB6C` | Ref-counted JPCORE power-on |

### State Structure at RAM 0x70D8

| Offset | Purpose |
|--------|---------|
| `+0x48` | MJPEG active flag (0=off, 1=on) |
| `+0xD4` | **Video mode (1=EVF/LCD, 2=VGA recording)** |
| `+0xEC` | Pipeline active (must be 1 before StartMjpegMaking) |
| `+0x114` | **Recording callback 1 — our spy goes here** |
| `+0x144` | DMA double-buffer 0 address |
| `+0x148` | DMA double-buffer 1 address |

### Hardware Encoding Investigation

The IXUS 870 IS uses **H.264 (MOV container)** for video recording, not MJPEG. The `StartMjpegMaking` firmware functions appear to be legacy from older Digic generations that used AVI/MJPEG. While JPCORE initializes and reports active, it never produces JPEG output on this camera. The raw UYVY approach bypasses encoding entirely — all compression is handled PC-side.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Operation timed out" on connect | Power-cycle the camera |
| No frames (all dropped) | Verify CHDK is loaded and `webcam.flt` exists on SD card |
| Green/wrong colors | U/V chroma must be treated as signed `int8_t` (see above) |
| ~1.3 FPS instead of ~5 FPS | Falling back to software JPEG — check `state[+0xD4]` is set to 2 |
| Camera powers off during streaming | `disable_shutdown()` may not have taken effect — increase startup delay |
| Build fails: pwsh.exe not found | Harmless vcpkg post-build error — the exe was built successfully |

## Camera Specifications

| Spec | Value |
|------|-------|
| Model | Canon IXUS 870 IS (P-ID: 3196) |
| Also known as | PowerShot SD880 IS / IXY DIGITAL 920 IS |
| Processor | Digic IV (ARM926EJ-S) |
| OS | DryOS |
| Sensor | 10.0 MP, 1/2.3" CCD |
| Lens | 4x zoom (28-112mm equiv.), F2.8-5.8 |
| Video | 640x480@30fps MOV (H.264 + Linear PCM) |
| USB | Mini-B, USB 2.0 High Speed |
| Battery | NB-5L lithium-ion |
| Released | 2008 |

## License

This project uses CHDK (GPL) components. The Tiny JPEG Encoder (`tje.c`) is MIT licensed. Provided for educational and personal use.

## Acknowledgments

- [CHDK project](https://chdk.fandom.com/) — the foundation that makes this possible
- [Ghidra](https://ghidra-sre.org/) — firmware reverse engineering
- [libusb](https://libusb.info/) — cross-platform USB access
