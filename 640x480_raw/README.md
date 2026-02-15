# Canon IXUS 870 IS — Hardware 640x480 Video Encoder & Webcam Bridge

Turn a Canon IXUS 870 IS (PowerShot SD880 IS / IXY DIGITAL 920 IS) into a USB webcam streaming 640x480 video at ~5 FPS via CHDK and a PC-side bridge application.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  CANON IXUS 870 IS (Digic IV, ARM926EJ-S, DryOS)              │
│                                                                 │
│  ┌──────────┐    ┌──────────┐    ┌────────────────────────┐    │
│  │  CCD     │───>│  ISP     │───>│  Recording Pipeline    │    │
│  │  Sensor  │    │  (Image  │    │  (640x480 UYVY @ 30fps)│    │
│  │  10MP    │    │  Signal  │    │                        │    │
│  └──────────┘    │  Proc)   │    │  DMA → 3 ring buffers  │    │
│                  └──────────┘    │  0x40BAADD0            │    │
│                                  │  0x40C7DCD0            │    │
│                                  │  0x40D50BD0            │    │
│                                  └───────────┬────────────┘    │
│                                              │                  │
│  ┌──────────────────────────────────────────┐│                  │
│  │  CHDK webcam.flt Module                  ││                  │
│  │                                          ││                  │
│  │  rec_callback_spy ←──────────────────────┘│                  │
│  │    │ captures arg2 = UYVY buffer addr      │                  │
│  │    │                                       │                  │
│  │  capture_frame_uyvy()                      │                  │
│  │    │ word-aligned copy 614KB               │                  │
│  │    │ from uncached DMA buffer              │                  │
│  │    └─→ uyvy_buf (private copy)             │                  │
│  │         │                                  │                  │
│  │  PTP opcode 0x9999                         │                  │
│  │    │ sub-command: GetMJPEGFrame (15)       │                  │
│  │    │ sends 614,400 bytes raw UYVY          │                  │
│  │    │ format encoded in param4 high byte    │                  │
│  └────┼───────────────────────────────────────┘                  │
│       │                                                          │
│       │ USB 2.0 High Speed (480 Mbps)                            │
└───────┼──────────────────────────────────────────────────────────┘
        │
┌───────┼──────────────────────────────────────────────────────────┐
│       │  PC (Windows)                                            │
│       │                                                          │
│  ┌────┴───────────────────────────────────┐                     │
│  │  chdk-webcam.exe (Bridge)              │                     │
│  │                                        │                     │
│  │  PTPClient (libusb-1.0)                │                     │
│  │    │ receives raw UYVY frames          │                     │
│  │    │ extracts format from param4       │                     │
│  │    │                                   │                     │
│  │  FrameProcessor                        │                     │
│  │    │ BT.601 UYVY→RGB conversion        │                     │
│  │    │ Digic IV signed chroma handling    │                     │
│  │    │                                   │                     │
│  │  PreviewWindow (Win32 GDI)             │                     │
│  │  VirtualWebcam (DirectShow)            │                     │
│  └────────────────────────────────────────┘                     │
└──────────────────────────────────────────────────────────────────┘
```

## Performance

| Metric | Value |
|--------|-------|
| Resolution | 640x480 (native, no upscaling) |
| Frame rate | ~4.7-4.9 FPS |
| Frame size | 614,400 bytes (uncompressed UYVY) |
| USB throughput | ~23 Mbps (~2.9 MB/s) |
| Dropped frames | 0 (stable over 5000+ frames) |
| Encoding CPU load (camera) | ~0% (raw passthrough, no encoding) |
| PC-side output | 640x480 RGB24 (upscaling currently disabled) |
| Previous software JPEG path | ~1.3 FPS (for comparison) |

## How It Works — Complete Pipeline

### Step 1: Camera enters Video Mode

The webcam module (`webcam.c`) switches the camera from Playback/PTP mode to Video Recording mode:

```c
// Step 1: Switch from playback to record mode
switch_mode_usb(1);  // PTP → Record
// Step 2: Switch shooting mode to video
shooting_set_mode_chdk(MODE_VIDEO_STD);  // → 640x480 video
```

This activates the camera's ISP (Image Signal Processor) video pipeline, which captures CCD frames and outputs 640x480 UYVY (YUV422) at 30 FPS internally.

### Step 2: Hardware MJPEG Engine Activation

Even though we don't use the JPCORE hardware JPEG encoder for output, we MUST activate it to get the recording pipeline callback chain running:

```c
// Power on the JPCORE hardware block
call_func_ptr(FW_JPCORE_PowerInit, 0, 0);

// Activate JPCORE encoder — sets state[+0x48]=1 (MJPEG active flag)
call_func_ptr(FW_StartMjpegMaking, 0, 0);

// CRITICAL: Force video recording path in FrameProcessing
state[0xD4/4] = 2;  // Video mode (not EVF/LCD mode)

// Install our callback spy in the recording callback slot
state[0x114/4] = (unsigned int)rec_callback_spy;
```

**Why `state[+0xD4] = 2` is critical:** The pipeline dispatcher (`FrameProcessing`) checks this value to decide which processing path to use:
- Value 2 or 3 → `FUN_ff9e508c` (video recording path, ISP mode 5) — routes sensor data through the full recording pipeline, fires callbacks
- Any other value → `FUN_ff9e51d8` (EVF/LCD path, ISP mode 4) — only feeds the LCD, no callbacks

Without setting this to 2, the recording callbacks never fire and we get no frame data.

### Step 3: Pipeline Callback Captures Frame Addresses

Once the recording pipeline is active, Canon's firmware calls our `rec_callback_spy` at 30 FPS with the address of the current UYVY frame buffer in `arg2`:

```c
static void rec_callback_spy(
    unsigned int a0, unsigned int a1, unsigned int a2, unsigned int a3)
{
    rec_cb_arg0 = a0;
    rec_cb_arg1 = a1;
    rec_cb_arg2 = a2;  // THIS is the UYVY frame buffer address
    rec_cb_arg3 = a3;
    rec_cb_count++;
}
```

The firmware rotates through 3 DMA buffers:
- `0x40BAADD0`
- `0x40C7DCD0`
- `0x40D50BD0`

These are in the **uncached RAM mirror** (`0x40000000` + physical offset), ensuring CPU reads see the latest DMA-written data without cache coherency issues.

### Step 4: Raw UYVY Frame Capture

Each frame capture copies 614,400 bytes from the DMA buffer to a private buffer:

```c
static int capture_frame_uyvy(void) {
    unsigned int cb_addr = rec_cb_arg2;
    // Validate address is in uncached DMA range
    if (cb_addr < 0x40010000 || cb_addr >= 0x44000000) return 0;
    // Skip if same frame as last time
    if (rec_cb_count == last_cb_count_raw) return 0;

    // Word-aligned copy: ~3ms vs ~16ms byte-by-byte
    const unsigned int *src = (const unsigned int *)cb_addr;
    unsigned int *dst = (unsigned int *)uyvy_buf;
    for (i = 0; i < UYVY_BUF_SIZE / 4; i++) dst[i] = src[i];

    frame_format = WEBCAM_FMT_UYVY;
    return UYVY_BUF_SIZE;
}
```

### Step 5: PTP Transfer to PC

The frame is sent over USB using CHDK's PTP extension (opcode `0x9999`, sub-command `GetMJPEGFrame = 15`):

```c
// Camera side (ptp.c):
ptp.param1 = frame.size;      // 614400
ptp.param2 = frame.width;     // 640
ptp.param3 = frame.height;    // 480
ptp.param4 = ((unsigned)frame.format << 24) | (frame.frame_num & 0x00FFFFFF);
send_ptp_data_buffered(data, memcpy, frame.data, frame.size);
```

The format is encoded in the high byte of `param4`:
- `0x00xxxxxx` = JPEG
- `0x01xxxxxx` = UYVY (raw)

### Step 6: PC-side UYVY to RGB Conversion

The bridge extracts the format and converts UYVY to RGB24 using BT.601 fixed-point math:

```cpp
// Digic IV stores U/V as SIGNED bytes centered at 0, NOT unsigned centered at 128
int u  = static_cast<int>(static_cast<int8_t>(src[0]));  // signed, -128..+127
int y0 = static_cast<int>(src[1]);
int v  = static_cast<int>(static_cast<int8_t>(src[2]));  // signed, -128..+127
int y1 = static_cast<int>(src[3]);

// BT.601 fixed-point: R = Y + 1.402*V, G = Y - 0.344*U - 0.714*V, B = Y + 1.772*U
int r0 = y0 + ((359 * v) >> 8);
int g0 = y0 - ((88 * u + 183 * v) >> 8);
int b0 = y0 + ((454 * u) >> 8);
```

**Critical:** Digic IV uses signed chroma. If you treat U/V as unsigned and subtract 128 (standard UYVY), whites turn green. The U/V bytes must be cast to `int8_t` first.

## Firmware Details — Digic IV IXUS 870 IS (fw 1.01a)

### Memory Map

| Address Range | Region | Notes |
|---------------|--------|-------|
| `0x00000000`-`0x03FFFFFF` | RAM (DRAM) | ~64 MB, cached |
| `0x40000000`-`0x43FFFFFF` | Uncached RAM mirror | Same physical RAM, bypasses CPU cache |
| `0xC0000000`-`0xCFFFFFFF` | I/O registers | Hardware peripheral control |
| `0xFF800000`-`0xFFFFFFFF` | Flash ROM | Firmware code + read-only data |

### Key Firmware Functions

| Function | ROM Address | Args | Purpose |
|----------|------------|------|---------|
| `StartMjpegMaking` | `0xFF9E8DD8` | 0 | Activate JPCORE encoder, set state[+0x48]=1 |
| `StopMjpegMaking` | `0xFF9E8DF8` | 0 | Deactivate JPCORE encoder |
| `GetContinuousMovieJpegVRAMData` | `0xFFAA234C` | 4 | Synchronous one-frame DMA capture (blocks on event flag) |
| `GetMovieJpegVRAMHPixelsSize` | `0xFF8C4178` | 0 | Returns frame width (640) |
| `GetMovieJpegVRAMVPixelsSize` | `0xFF8C4184` | 0 | Returns frame height (480) |
| `StopContinuousVRAMData` | `0xFF8C425C` | 4 | Release DMA for current frame |
| `StartEVFMovVGA` | `0xFF9E8944` | 4 | Start EVF at 640x480 @ 30fps |

### JPCORE Power Management

| Function | ROM Address | Purpose |
|----------|------------|---------|
| `FW_JPCORE_PowerInit` | `0xFF8EEB6C` | Ref-counted JPCORE power-on |
| `FW_JPCORE_PowerDeinit` | `0xFF8EEBC8` | Ref-counted JPCORE power-off |
| `FW_JPCORE_ClockEnable` | `0xFF815288` | Clock/power gate enable (arg: 0) |
| `FW_JPCORE_ClockEnable2` | `0xFF8152E8` | Additional clock domain enable |
| `FW_JPCORE_SubsystemInit` | `0xFF8EF6B4` | JPCORE subsystem init (DMA, interrupts, buffers) |

**Note:** `FW_JPCORE_PowerInit` checks `*(0x8028) != 0` before proceeding. If the JPCORE module wasn't loaded at boot, this flag is 0 and the function is a no-op. In that case, the three sub-functions must be called directly.

### Global State Structure at `0x70D8`

Both `DAT_ff8c2e24` and `DAT_ff8c43f4` (ROM literal pool) resolve to RAM address `0x000070D8`. This is the central state structure for the video recording pipeline.

| Offset | Type | Purpose | Values |
|--------|------|---------|--------|
| `+0x48` | uint32 | MJPEG active flag | 0=off, 1=on (set by `StartMjpegMaking`) |
| `+0x4C` | uint32 | Paired flag | Set alongside +0x48 |
| `+0x54` | uint32 | DMA status | Cleared by trigger, set by pipeline |
| `+0x58` | uint32 | Frame index for DMA | Stored by DMA trigger function |
| `+0x5C` | uint32 | DMA request state | 3=requested, 4=stopped, 5=stopping |
| `+0x60` | uint32 | Ring buffer address | Set by state machine |
| `+0x64` | uint32 | VRAM buffer address | Should be `0x40EA23D0` |
| `+0x6C` | uint32 | Recording buffer | Set by `sub_FF8C3BFC` |
| `+0x80` | ptr | Cleanup callback | Called during stop |
| `+0xA0` | ptr | DMA callback | Stored by DMA trigger |
| `+0xB0` | uint32 | Event flag handle | DryOS synchronization |
| `+0xD4` | uint32 | **Video mode** | **2=VGA recording, 1=EVF/LCD** |
| `+0xEC` | uint32 | Pipeline active | 1=EVF running (prerequisite for StartMjpegMaking) |
| `+0xF0` | uint32 | Frame skip flag | Pipeline frame skip |
| `+0x114` | ptr | **Recording callback 1** | **Our spy function goes here** |
| `+0x118` | ptr | Recording callback 2 | Set by `sub_FF8C3BFC` |
| `+0x144` | uint32 | Double-buffer 0 addr | Frame DMA target |
| `+0x148` | uint32 | Double-buffer 1 addr | Frame DMA target |

### JPCORE Hardware Registers

| Register | Address | Purpose |
|----------|---------|---------|
| JPCORE base | `0xC0F04900` | Slot 0xb base |
| JPCORE +4 | `0xC0F04904` | Slot config |
| JPCORE +8 | `0xC0F04908` | DMA output destination address |
| JPCORE +0xC | `0xC0F0490C` | DMA config |
| JPCORE enable | `0xC0F0103C` | JPCORE enable register |
| ISP source | `0xC0F110C4` | ISP routing (4=EVF, 5=VIDEO) |

### JPCORE VRAM Buffer Constants

Embedded in firmware ROM literal pool:

| Constant | ROM Address | Value | Meaning |
|----------|------------|-------|---------|
| Buffer address | `0xFFAA2314` | `0x40EA23D0` | Uncached RAM (physical: `0x00EA23D0`) |
| Buffer max size | `0xFFAA2318` | `0x000D2F00` | 864,000 bytes (~844 KB) |

### Recording Pipeline Callback Chain

When the video pipeline is in recording mode (`state[+0xD4] = 2`), the firmware's `FrameProcessing` function (called from `PipelineFrameCallback`) takes the video recording path. This path processes each ISP frame and calls the function pointer at `state[+0x114]` with 4 arguments:

```
PipelineFrameCallback (ISR, 30fps)
  └─ FrameProcessing
       └─ checks state[+0xD4]
            ├─ value 2,3 → FUN_ff9e508c (video path, ISP mode 5)
            │   └─ FUN_ff8c335c
            │       └─ calls *(state+0x114)(arg0, arg1, arg2, arg3)
            │            └─ rec_callback_spy captures arg2 = UYVY buffer
            └─ other    → FUN_ff9e51d8 (EVF path, ISP mode 4) — no callback
```

`arg2` contains the address of the current 640x480 UYVY frame in uncached DMA memory. The firmware rotates through 3 buffers automatically.

### Why Hardware JPEG Encoding Doesn't Work (for reference)

The JPCORE hardware JPEG encoder is initialized and reports active, but **never receives input data**. Root cause analysis:

1. `StartMjpegMaking` correctly sets `state[+0x48]=1` (MJPEG active) and calls `FUN_ff9e8190` (JPCORE enable)
2. JPCORE power is on, DMA is configured, completion masks show pre/post steps completed
3. BUT: The ISP-to-JPCORE routing (`0xC0F110C4`) reads `0x00000000` instead of the expected source address
4. The recording pipeline setup function `sub_FF8C3BFC` (which connects ISP output to JPCORE input) **crashes** when called without full movie_record_task context — it expects ring buffer state, AVI writer state, and specific callbacks that are only valid during actual movie recording
5. Result: JPCORE sits idle, VRAM buffer at `0x40EA23D0` never receives JPEG data

This is why the raw UYVY approach was developed — it bypasses JPCORE entirely and captures the pre-encoding ISP output directly.

## File Structure

```
640x480_raw/
├── README.md                      ← This file
├── CMakeLists.txt                 ← Bridge CMake build config
├── bridge_build.md                ← Bridge build instructions
├── bridge_src/                    ← PC-side bridge application
│   ├── main.cpp                   ← Entry point, streaming loop
│   ├── ptp/
│   │   ├── ptp_client.h           ← PTP/CHDK protocol definitions
│   │   └── ptp_client.cpp         ← libusb PTP client
│   └── webcam/
│       ├── frame_processor.h      ← UYVY/JPEG decoder interface
│       ├── frame_processor.cpp    ← BT.601 UYVY→RGB + JPEG decode
│       ├── preview_window.h       ← Win32 GDI preview window
│       ├── preview_window.cpp
│       ├── virtual_webcam.h       ← DirectShow virtual webcam
│       └── virtual_webcam.cpp
├── chdk_modules/                  ← Camera-side CHDK code
│   ├── webcam.c                   ← Main webcam module (1400+ lines)
│   ├── webcam.h                   ← Module interface
│   ├── tje.c                      ← Tiny JPEG Encoder (software fallback)
│   ├── tje.h                      ← TJE header
│   └── ptp.c                      ← PTP handler (GetMJPEGFrame command)
└── chdk_platform/
    └── stubs_entry.S              ← Firmware function stubs (IXUS 870 IS fw 1.01a)
```

**Note:** The CMakeLists.txt references source files under `src/` (e.g. `src/ptp/ptp_client.cpp`), but the actual source directory is `bridge_src/`. When building, either rename `bridge_src` to `src` or update the CMakeLists.txt paths.

## Building

### Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| Visual Studio 2019/2022 | Build Tools or Community | C++ compiler |
| vcpkg | Latest | Package manager |
| libusb | 1.0.x | USB communication (`vcpkg install libusb:x64-windows`) |
| libjpeg-turbo | 3.x | JPEG decode for fallback path (`vcpkg install libjpeg-turbo:x64-windows`) |
| Docker | Latest | CHDK cross-compilation |
| CHDK source tree | 1.6.x | Camera firmware (with platform files for ixus870_sd880) |

### Bridge (PC-side)

**Important:** The CMakeLists.txt references `src/` for source paths, but the actual directory is `bridge_src/`. Before building, either rename `bridge_src` to `src`, or update the paths in CMakeLists.txt.

```batch
set CMAKE="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

:: Fix source directory name (one-time)
ren bridge_src src

:: Configure (once)
%CMAKE% -B build -S . -G "Visual Studio 17 2022" -A x64 ^
    -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake

:: Build
%CMAKE% --build build --config Release
```

Output: `build/Release/chdk-webcam.exe`

### CHDK (Camera-side)

```bash
# Build via Docker cross-compiler
docker run --rm -v "/path/to/chdk:/srv/src" chdkbuild \
    make PLATFORM=ixus870_sd880 PLATFORMSUB=101a fir
```

Output: `bin/DISKBOOT.BIN` + `CHDK/MODULES/webcam.flt`

### Deploying to Camera

The CHDK modules in `chdk_modules/` must be integrated into the CHDK source tree at `chdk/modules/` before building. The stubs in `chdk_platform/stubs_entry.S` go to `chdk/platform/ixus870_sd880/sub/101a/stubs_entry.S`.

After building CHDK:

1. Copy `DISKBOOT.BIN` to SD card root
2. Copy `webcam.flt` to `CHDK/MODULES/` on SD card
3. Insert SD card into camera
4. Boot camera in Playback mode
5. Load CHDK: MENU > Settings > press UP arrow > Firmware Ver. > confirm with FUNC.SET

**Note:** The "Firmware Ver." menu item is hidden at the bottom of the Settings menu. You must press the **UP arrow** to jump to the bottom and reveal it. The SD card must be **unlocked** (write-protect tab in unlocked position).

## Running

```bash
# Basic usage (preview window only, 640x480 native)
chdk-webcam.exe --no-webcam

# With verbose frame logging
chdk-webcam.exe --no-webcam --verbose

# With virtual webcam (appears as "CHDK Webcam" in apps)
chdk-webcam.exe

# Mirror horizontally (selfie mode)
chdk-webcam.exe --flip-h
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-q, --quality N` | 50 | JPEG quality on camera (only affects SW fallback path) |
| `-w, --width N` | 1280 | Output width (currently unused — upscaling disabled) |
| `-h, --height N` | 720 | Output height (currently unused — upscaling disabled) |
| `-f, --fps N` | 30 | Target frame rate |
| `--flip-h` | off | Mirror horizontally |
| `--flip-v` | off | Flip vertically |
| `--no-webcam` | off | Skip virtual webcam creation (preview only) |
| `--no-preview` | off | Skip preview window |
| `--verbose` | off | Show per-frame statistics |

**Note on resolution:** The raw UYVY path always outputs at 640x480 (camera native). The bilinear upscaler exists in `frame_processor.cpp` but is currently disabled (`#if 0`). The `--width` and `--height` options are parsed but have no effect on the output. The preview window is fixed at 640x480.

## USB Driver Setup

The camera must use the `libusb-win32` driver (not the default Canon PTP driver). Use [Zadig](https://zadig.akeo.ie/) to replace the driver:

1. Connect camera, power on, load CHDK
2. Run Zadig
3. Select "Canon Digital Camera" from the device list
4. Select "libusb-win32" as the target driver
5. Click "Replace Driver"

## PTP Protocol Details

### Opcode

All webcam communication uses CHDK's vendor-specific PTP opcode:
- **Opcode:** `0x9999` (PTP_OC_CHDK)
- **Sub-command:** `15` (CHDK_GetMJPEGFrame)

### Start Streaming

```
Command:  opcode=0x9999, param1=15, param2=quality, param3=0x01 (WEBCAM_START)
Response: param1=0, param2=active, param3=0, param4=0xBEEF
Data:     576 bytes of DMA chain diagnostics
```

### Get Frame

```
Command:  opcode=0x9999, param1=15, param2=0, param3=0
Response: param1=frame_size, param2=width, param3=height,
          param4=(format<<24)|(frame_num&0xFFFFFF)
Data:     frame_size bytes of frame data (UYVY or JPEG)
```

Format encoding in `param4`:
- Bits 31-24: format (0=JPEG, 1=UYVY)
- Bits 23-0: frame counter

### Stop Streaming

```
Command:  opcode=0x9999, param1=15, param2=0, param3=0x02 (WEBCAM_STOP)
Response: param1=0
Data:     1 byte (null)
```

## UYVY Frame Format (Digic IV Specific)

Each 640x480 UYVY frame is 614,400 bytes (640 * 480 * 2).

**Pixel layout (4 bytes = 2 pixels):**
```
Byte 0: U  (Cb, SIGNED: -128..+127, centered at 0)
Byte 1: Y0 (Luma for pixel 0, unsigned: 0..255)
Byte 2: V  (Cr, SIGNED: -128..+127, centered at 0)
Byte 3: Y1 (Luma for pixel 1, unsigned: 0..255)
```

**Digic IV chroma encoding is non-standard:**
- Standard UYVY: U and V are unsigned bytes centered at 128 (range 0-255)
- Digic IV UYVY: U and V are **signed** bytes centered at 0 (range -128 to +127)
- You MUST interpret U/V as `int8_t` (signed char), NOT as `uint8_t - 128`
- Getting this wrong produces a green color cast on all neutral/white areas

## Troubleshooting

### "Operation timed out" on connect
The camera's PTP session from a previous run wasn't cleanly closed. Power-cycle the camera.

### No frames received (all dropped)
- Verify CHDK is loaded (camera shows `--ALT--` indicator)
- Check that `webcam.flt` is present at `CHDK/MODULES/webcam.flt` on the SD card
- Ensure no other PTP client is running (Windows photo import, Canon software)

### Green/wrong colors
The U/V chroma bytes are being treated as unsigned. See the "UYVY Frame Format" section above.

### Camera hangs during streaming
- Avoid reading uncached DMA buffers (`0x40xxxxxx`) from ISR context on ARM926EJ-S
- Don't call `sub_FF8C3BFC` (recording pipeline setup) without full movie_record_task context — it crashes
- Reading >64 KB of uncached memory per frame causes cumulative bus stalls (~600 frames before hang)

### ~1.3 FPS instead of ~5 FPS
The module is falling back to software JPEG encoding. Check that `rec_cb_count` is incrementing (visible in diagnostics data). If not, `state[+0xD4]` may not be set to 2. The raw UYVY path requires the recording pipeline callback to be firing.

### Build fails: "cannot find src/ptp/ptp_client.cpp"
The CMakeLists.txt references `src/` but the actual source directory is `bridge_src/`. Either rename `bridge_src` to `src`, or update the paths in CMakeLists.txt.

### Camera powers off after ~3 minutes
The webcam module calls `disable_shutdown()` on start and `enable_shutdown()` on stop to prevent the camera's inactivity timer from killing the USB connection. If streaming stops unexpectedly, the auto-power-off may have triggered before `disable_shutdown()` took effect.

## License

This project uses CHDK (GPL) and is provided for educational and personal use.
