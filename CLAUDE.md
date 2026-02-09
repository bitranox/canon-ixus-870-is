# Canon IXUS 870 IS Firmware Upgrade

## Project Overview

This project contains resources and instructions for upgrading the firmware on the Canon IXUS 870 IS.

- **Also known as**: Canon PowerShot SD 880 IS (North America) / Canon IXY DIGITAL 920 IS (Japan)
- **Current firmware**: GM1.00E (version 1.00e — initial release, 2008-08-22)
- **Reference**: https://chdk.fandom.com/wiki/IXUS870IS
- **CHDK 1.6 User Manual**: https://chdk.fandom.com/wiki/CHDK_1.6_User_Manual

## Camera Specifications

- **Model**: Canon IXUS 870 IS (P-ID: 3196)
- **Processor**: Digic IV
- **Operating System**: DryOS
- **Sensor**: 10.0 MP effective, 1/2.3" CCD
- **Lens**: 4x optical zoom (28-112mm equiv.), F2.8-5.8
- **Stabilization**: Optical IS (lens shift)
- **Display**: 3" LCD, 230,000 pixels
- **Video**: 640x480@30fps, 320x240@30fps, 160x120@15fps (MOV, H.264 + Linear PCM)
- **Battery**: NB-5L lithium-ion (~310 shots per charge)
- **Dimensions**: 94 x 57 x 24mm, 155g

## Firmware Versions

| Version | Canon Version | Date | IS Firmware | IS Parameter | Dump File |
|---------|--------------|------|-------------|--------------|-----------|
| **1.02b** | — | 2009-01-09 | 2.09 | 2.07 | `ixus870_sd880_102b.7z` |
| **1.01a** *(current)* | 1.0.1.0 | 2008-10-15 | — | — | `ixus870_sd880_101a.7z` |
| **1.00e** | — | 2008-08-22 | — | — | `ixus870_sd880_100e.7z` |

- **1.01a** received an official Canon update released on 2009-02-05.

## Firmware Dumps

Firmware dumps are located in `firmware-dumps\IXUS - SD Series\`. This directory contains a broad collection of Canon PowerShot P&S firmware dumps across the full IXUS/SD lineup. The three files relevant to this camera are listed in the table above.

## Firmware Upgrade Process

**IMPORTANT — Accessing "Firmware Ver." on this camera:**
The "Firmware Ver." menu item is HIDDEN at the bottom of the Settings menu and is NOT visible by normal scrolling. To reach it:
1. Power on in **Playback mode**
2. Press **MENU**
3. Navigate to the **Settings tab** (wrench icon)
4. Press **UP arrow** — this jumps to the bottom of the menu, revealing "Firmware Ver." below "Grundeinstellungen" / "Reset All"

**SD card must be UNLOCKED** (write-protect tab in the unlocked position) for the firmware update option to appear.

### Steps

1. **Check current firmware version**: Playback mode > MENU > Settings > UP > Firmware Ver.
2. **Download firmware**: The update file is `IXY_920.FI2` (same file for all regional variants: IXUS 870 IS, SD880 IS, IXY 920 IS). Original Canon source (archived): `https://web.archive.org/web/2024/http://web.canon.jp/imaging/dcp/firm-e/pssd880is/data/pssd880is1010.exe` — extract `IXY_920.FI2` from the self-extracting .exe with 7-Zip.
3. **Prepare SD card**: Place the `.fi2` file in the **root** of the SD card. SD card must be **unlocked**.
4. **Install update**: Playback mode > MENU > Settings > UP > Firmware Ver. > follow prompts > confirm with FUNC.SET.
5. **Do not power off** the camera during the update process.

### Important Notes

- Always ensure the battery (NB-5L) is fully charged before starting a firmware update.
- Do not remove the SD card or battery during the update.
- After updating, rebuild CHDK with the matching `PLATFORMSUB` (e.g., `100e` → `101a`).

## CHDK (Canon Hack Development Kit)

CHDK is an optional third-party firmware enhancement that runs alongside the original Canon firmware. It does not overwrite or replace the factory firmware.

- **Supported firmware versions**: 1.00e, 1.01a, 1.02b
- **Features**: RAW/DNG shooting, scripting (uBASIC/Lua), extended bracketing, live histogram, zebra mode, override shutter/aperture/ISO, and more.
- **Installation**: Load CHDK onto a bootable SD card; it runs from the card without modifying the camera's internal firmware.
- **Compatibility**: You must download the CHDK build that matches your exact firmware version.

### CHDK Installation Methods

1. **Firmware Update Method (manual load each time)**:
   - Start camera in Playback mode
   - Press MENU > UP arrow > select Firmware Update > confirm with FUNC.SET
   - CHDK loads into RAM; must repeat after each power-off

2. **Bootable SD Card Method (automatic)**:
   - Configure SD card as bootable for automatic CHDK loading on startup
   - SD card lock switch must remain in the locked position

### Entering ALT Mode

CHDK features are accessed via ALT mode (typically short-press PRINT, SHORTCUT, or PLAY button). The `--ALT--` indicator appears on-screen. Exit ALT mode to take photos normally.

**Controls in ALT mode**:
- MENU: Access CHDK main menu
- FUNC.SET: Display scripts menu
- DISP: Return to previous menu
- Full Shutter: Execute or end scripts

**Half-shutter shortcuts**:
- Left: Toggle Zebra
- Right: Toggle OSD
- Up: Toggle Histogram
- Down: Toggle Overrides

### CHDK Main Menu Structure

- **Enhanced Photo Operations**: Exposure/focus overrides (Tv, Av, ISO, manual focus, hyperfocal)
- **Video Parameters**: Bitrate/quality control, remove 1GB file-size limit, optical zoom during recording
- **RAW (Digital Negative)**: RAW/DNG capture, bad-pixel removal, cached buffering, file naming
- **Edge Overlay**: Panorama alignment tools
- **Histogram**: Live exposure graphing
- **Zebra**: Highlight/shadow exposure warnings
- **Scripting**: Custom automation via uBASIC/Lua scripts, autostart, parameter management
- **CHDK Settings**: Display, interface, system configuration
- **Miscellaneous Stuff**: Utilities, debugging, battery/temperature/memory OSD

### OSD Display

Configurable on-screen display including: battery status, temperature, memory usage, DOF calculator, clock, USB indicator. Layout editor available for element positioning.

### Using as a Webcam (via CHDK + chdkptp)

CHDK enables a live view feed from the camera to a PC using the **PTP Extension** and the **chdkptp** client. The IXUS 870 IS is explicitly listed as a supported camera. This is not a native webcam — the camera does not appear as a video device — but the live view window can be captured with OBS to create a virtual webcam.

- **Reference**: https://chdk.fandom.com/wiki/PTP_Extension

**Required software**:

| Component | Purpose |
|-----------|---------|
| CHDK (1.00e build) | Firmware enhancement on camera |
| chdkptp | PC client for PTP communication + live view |
| libusb-win32 | Alternative USB driver (Windows) |
| OBS Studio (optional) | Capture live view window as virtual webcam for Zoom/Teams/etc. |

**Setup**:

1. Install CHDK on the camera (must match firmware version 1.00e)
2. Connect camera to PC via USB
3. Install libusb-win32 driver on PC
4. Run chdkptp and connect to the camera
5. Start live view in chdkptp — the camera's LCD feed streams to a window on the PC
6. (Optional) Use OBS Studio to capture the chdkptp window and enable Virtual Camera for use in video conferencing apps

**Limitations**:

- Frame rate is tied to the camera's LCD refresh — do not expect smooth 30fps video
- Live view may stop updating or show artifacts if the camera LCD turns off
- Requires chdkptp running on the PC at all times
- Resolution is limited to the camera's LCD buffer, not the full sensor resolution
- Additional features: camera can save JPGs directly to PC without storing on SD card

### Known CHDK Issues

- DNG file colors may be slightly misaligned.
- Brief power-on button presses can trigger review mode instead of normal startup.
- Optical/digital zoom transitions in video mode require releasing the zoom lever between steps.
- CHDK is experimental software — no confirmed camera damage reports, but provided without warranty.

## Native Webcam Project (Phase 1: MJPEG Streaming)

Goal: Turn the IXUS 870 IS into a native webcam using CHDK's video mode buffer (640x480) + MJPEG compression + PTP streaming + PC-side virtual webcam bridge. Camera appears as "CHDK Webcam" in Zoom/Teams/OBS.

### Development Environment (checked 2026-02-08)

#### Installed Software

| Tool | Version | Path | Status |
|------|---------|------|--------|
| Docker Desktop | 29.2.0 | (in PATH) | Installed |
| Git for Windows | 2.53.0 | (in PATH) | Installed |
| Visual Studio 2019 | Community + BuildTools | `C:\Program Files (x86)\Microsoft Visual Studio\2019\` | Installed (plan calls for 2022, but 2019 works) |
| CMake (VS-bundled) | 3.20 | `C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe` | Installed (not in PATH — use full path or VS Developer Command Prompt) |
| MSVC C++ Toolset | 14.29.30133 | (inside VS 2019) | Installed |
| vcpkg | 2025-12-16 | `C:\vcpkg\vcpkg.exe` | Installed |
| 7-Zip | 25.01 | `C:\Program Files\7-Zip\7z.exe` | Installed |
| libusb | 1.0.29#1 | vcpkg (x64-windows) | Installed |
| libjpeg-turbo | 3.1.3 | vcpkg (x64-windows) | Installed |

#### Not Yet Installed / Not Found

| Tool | Purpose | Status |
|------|---------|--------|
| Wireshark + USBPcap | USB packet capture & debugging | Not installed |
| Ghidra | Firmware reverse engineering | Not installed |
| chdkptp | PTP connectivity testing | Not installed |
| Zadig | USB driver replacement (libusb-win32) | Not installed |
| softcam | Virtual webcam DirectShow filter | Not installed |
| OpenCV | Image processing (Phase 2) | Not installed via vcpkg |
| FFmpeg | H.264 decode (Phase 2) | Not installed via vcpkg |

### Project Directory Layout

```
C:\projects\ixus870IS\                          -- Project root
├── CLAUDE.md                                   -- This file (project docs)
├── CONCEPT.md                                  -- Project concept/plan
├── firmware-dumps\                             -- Canon P&S firmware dumps
├── chdk\                                       -- CHDK source tree
│   ├── modules\webcam.c                        -- Webcam CHDK module (created)
│   ├── modules\webcam.h                        -- Webcam module header (created)
│   ├── modules\tje.c                           -- Tiny JPEG Encoder (created)
│   ├── modules\tje.h                           -- TJE header (created)
│   ├── core\ptp.c                              -- PTP handler (modified — added GetMJPEGFrame)
│   ├── core\ptp.h                              -- PTP header (modified)
│   ├── core\modules.c                          -- Module loader (modified)
│   ├── core\modules.h                          -- Module header (modified)
│   ├── modules\Makefile                        -- Module build rules (modified)
│   └── modules\module_exportlist.c             -- Module exports (modified)
└── bridge\                                     -- PC-side bridge application
    ├── CLAUDE.md                               -- Bridge build instructions
    ├── CMakeLists.txt                          -- CMake build config
    ├── build\                                  -- VS solution (generated)
    │   └── Release\                            -- Build output
    ├── src\ptp\ptp_client.h                    -- PTP client header
    ├── src\ptp\ptp_client.cpp                  -- PTP client (libusb, opcode 0x9999)
    ├── src\webcam\frame_processor.h            -- Frame processor header
    ├── src\webcam\frame_processor.cpp          -- MJPEG decode + YUV conversion
    ├── src\webcam\virtual_webcam.h             -- Virtual webcam header
    ├── src\webcam\virtual_webcam.cpp           -- DirectShow virtual webcam
    ├── src\main.cpp                            -- Main entry point
    └── driver\                                 -- USB driver files
```

### Build Status (checked 2026-02-08)

#### CHDK (camera-side)
- **Platform files**: `chdk\platform\ixus870_sd880\sub\101a\` — fully present
- **Build**: Docker image `chdkbuild` used for cross-compilation
- **Output**: `chdk\bin\DISKBOOT.BIN`, `chdk\CHDK\MODULES\webcam.flt`

#### PC-side bridge (`chdk-webcam.exe`)
- **Build output**: `bridge\build\Release\` contains:
  - `chdk-webcam.exe` — main bridge application
  - `libusb-1.0.dll` — USB communication library
  - `turbojpeg.dll` — JPEG decode library
- **VS solution**: `bridge\build\chdk-webcam.sln`

### Build Commands

**Starting Docker Desktop** (required before CHDK builds — daemon takes ~2 minutes to be ready):
```
"C:/Program Files/Docker/Docker/Docker Desktop.exe" &
```
Wait until `docker info` succeeds before running builds.

**CHDK (camera-side) — Docker:**
```
docker run --rm -v "C:\projects\ixus870IS\chdk:/srv/src" chdkbuild make PLATFORM=ixus870_sd880 PLATFORMSUB=101a fir
```

**PC-side bridge — VS 2022 Build Tools:**

cmake is not on PATH; use the full path:
```
set CMAKE="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
```

Configure (only needed once or after CMakeLists.txt changes):
```
%CMAKE% -B C:\projects\ixus870IS\bridge\build -S C:\projects\ixus870IS\bridge -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
```

Build:
```
%CMAKE% --build C:\projects\ixus870IS\bridge\build --config Release
```

Output binary: `bridge\build\Release\chdk-webcam.exe`

### Deploying CHDK to SD Card via SSH

The SD card reader is attached to a Linux host at `192.168.0.54` (accessible as `root` via SSH).

**SSH key**: `~/.ssh/id_ed25519` (passwordless, deployed via `ssh-copy-id`). No password prompt required.

**SD card device**: `/dev/mmcblk0p1` (FAT16, ~2GB)

**CRITICAL: The SD card must be physically inserted into the card reader on the Linux host.
It is NOT automatically mounted. `/mnt/sdcard` is just a directory on the root filesystem —
writing to it without mounting first will NOT write to the SD card!**

**Deployment workflow:**

1. **Ask the user to insert the SD card** into the reader on the Linux host
2. **Mount the SD card** (always ask user before mounting):
   ```
   ssh root@192.168.0.54 "mkdir -p /mnt/sdcard && mount /dev/mmcblk0p1 /mnt/sdcard"
   ```
3. **Copy files:**
   ```
   scp "C:/projects/ixus870IS/chdk/bin/DISKBOOT.BIN" root@192.168.0.54:/mnt/sdcard/DISKBOOT.BIN
   scp "C:/projects/ixus870IS/chdk/CHDK/MODULES/webcam.flt" root@192.168.0.54:/mnt/sdcard/CHDK/MODULES/webcam.flt
   ```
4. **Verify the file is correct** (always check after deploy):
   ```
   ssh root@192.168.0.54 "ls -la /mnt/sdcard/CHDK/MODULES/webcam.flt && md5sum /mnt/sdcard/CHDK/MODULES/webcam.flt"
   ```
   Compare the MD5 with the local file: `certutil -hashfile "C:\projects\ixus870IS\chdk\CHDK\MODULES\webcam.flt" MD5`
5. **Sync and unmount:**
   ```
   ssh root@192.168.0.54 "sync && umount /mnt/sdcard"
   ```
6. **Ask the user to move the SD card** back to the camera and power cycle
