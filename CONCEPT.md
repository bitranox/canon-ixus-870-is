# Plan: CHDK Native Webcam Support for Canon IXUS 870 IS

## Context

The Canon IXUS 870 IS (GM1.00E firmware) can currently stream its LCD buffer to a PC via CHDK's PTP extension + chdkptp, but this requires a custom client app and OBS window capture to use as a webcam. Such basic solutions already exist. The goal is to build something **better** — a native webcam experience using the camera's **video mode sensor buffer (640x480)** and **hardware H.264 encoder**, visible in Zoom, Teams, OBS, etc. without workarounds.

## Available Frame Buffers

| Buffer | Resolution | Format | Availability | FPS potential |
|--------|-----------|--------|-------------|---------------|
| Viewport | 360x240 | YUV411 (6 bytes/4 pixels) | Always, real-time | ~10-15 via PTP |
| **Video mode buffer** | **640x480** | YUV, triple-buffered | In record/movie mode | Up to 30 FPS |
| Raw sensor | 3648x2736 (10MP) | 12-bit Bayer | Only during still capture | Not continuous |

**Chosen data source**: The **video mode pre-encoder buffer** at 640x480. This is the uncompressed YUV data *before* H.264 encoding, triple-buffered at 30 FPS natively. The camera already processes sensor data down to 640x480 in video mode — we tap into this pipeline.

## Hardware Limits (confirmed)

- **Max continuous resolution**: 640x480 — no intermediate buffer between this and full 10MP sensor
- **No audio streaming**: Microphone is not accessible as a separate stream via CHDK/PTP
- **Hardware JPEG encoder (JPCORE)**: Exists on Digic IV but not safely callable from CHDK without firmware RE
- **Hardware H.264 encoder**: Exists and actively used for video recording — interceptable
- **EDMAC (DMA engine)**: Exists but no CHDK API — not our bottleneck (USB transfer is)
- **Digic IV ISP pipeline**: Runs automatically (white balance, NR, color correction) — CHDK controls inputs (exposure, focus) but cannot tune ISP internals

## Recommended Approach: Phased Strategy

- **Phase 1**: CHDK module to access video mode buffer (640x480) + MJPEG compression + PC-side virtual webcam bridge.
- **Phase 2**: Switch to hardware H.264 encoder interception for 30 FPS + PC-side image enhancement.
- **Phase 3** (optional, long-term): Investigate native UVC by reverse-engineering the Digic IV USB controller.

---

## Phase 1: Video Mode Buffer + MJPEG Streaming (6-8 weeks)

Access the 640x480 video mode sensor buffer, compress with MJPEG, stream via PTP, and expose as a virtual webcam on the PC.

### Camera-side development

1. **Clone CHDK source** from `https://github.com/01luna/CHDK`
2. **Build CHDK** for IXUS 870 IS using Docker:
   ```
   docker build -t chdkbuild tools/docker/chdkbuild/
   docker run --rm -v C:\chdk\trunk:/srv/src chdkbuild make PLATFORM=ixus870_sd880 PLATFORMSUB=100e fir
   ```
3. **Investigate video mode buffer access** on IXUS 870 IS:
   - Locate the triple-buffered movie frame buffers in memory (search firmware for `"VRAM Address"` string)
   - Determine exact YUV format on Digic IV (Y411 vs UYVY)
   - Verify buffer dimensions and stride in 640x480 video mode
4. **Create CHDK module** `modules/webcam.c`:
   - Put camera in video/record mode to activate 640x480 buffers
   - Read from the triple-buffered pre-encoder YUV frames
   - Add software JPEG encoder (Tiny JPEG Encoder, ~500 lines C):
     - Input: 640x480 YUV from video buffer
     - Output: MJPEG frame (~30-40 KB vs ~460 KB uncompressed)
   - Follow existing module patterns (`modules/dng.c`, `modules/zebra.c`)
5. **Add new PTP sub-command** `PTP_CHDK_GetMJPEGFrame` in `core/ptp.c`:
   - Returns the latest JPEG-compressed video frame
   - Camera-side: grab newest of triple-buffered frames, encode, send
6. **"Webcam mode"** in CHDK:
   - Prevent LCD sleep
   - Lock camera into video-mode buffer configuration
   - Disable unnecessary processing to free CPU
   - Pre-configure optimal exposure for streaming (ISO, shutter, WB)

### PC-side development

7. **Develop `chdk-webcam.exe`** (C++, Visual Studio 2022):
   - Connect to camera via libusb/PTP (opcode `0x9999`, new `PTP_CHDK_GetMJPEGFrame` sub-command)
   - Receive MJPEG frames (~30-40 KB each at 640x480)
   - Decode with libjpeg-turbo → RGB24
   - Lanczos upscale to 720p for video call output
   - Feed into virtual webcam via [softcam](https://github.com/tshino/softcam) DirectShow filter
8. **Register virtual webcam**: `regsvr32 softcam.dll` (32-bit + 64-bit)
9. **Test** in Zoom/Teams/OBS — camera appears as "CHDK Webcam"

### Critical: avoid PTP client conflicts
- Ensure no other PTP clients (Canon software, Windows photo import) are running — documented to cause **1000x slowdown**
- Zadig driver replacement prevents Windows auto-detecting camera as a photo device

### Key source files
- `core/ptp.c` / `core/ptp.h` — PTP command handler, opcode `0x9999`
- `core/live_view.h` — Frame buffer format (`lv_data_header`, `lv_framebuffer_desc`, YUV layout)
- `platform/ixus870_sd880/sub/100e/stubs_entry.S` — Firmware function addresses
- `modules/dng.c`, `modules/zebra.c` — Module pattern reference

### Expected result
- Native 640x480 resolution, upscaled to 720p on PC
- 15-20 FPS (MJPEG compression reduces USB transfer time)
- ~30-40 KB per frame
- Visible as native webcam in all apps

---

## Phase 2: H.264 Hardware Encoder + Image Enhancement (6-10 weeks)

Switch from software MJPEG to the camera's **hardware H.264 encoder** for 30 FPS at 3-8x better compression. Add PC-side image enhancement.

### Codec comparison

| Codec | Frame size (640x480) | Encoding | CPU load | Notes |
|-------|---------------------|----------|----------|-------|
| MJPEG (Phase 1) | ~30-40 KB | Software (ARM926) | High | Each frame independent |
| **H.264 (Phase 2)** | **~5-10 KB** | **Hardware (Digic IV)** | **Zero** | Inter-frame compression |

### Camera-side: H.264 bitstream interception

1. **Reverse-engineer the H.264 encoding pipeline** using Ghidra on firmware dump:
   - Trace Canon's video recording code path from `capt_seq.c` hooks
   - Locate the H.264 encoder output buffer (where encoded NAL units are written before MOV muxing)
   - Identify functions: encoder start/stop, bitstream buffer address, frame completion callbacks
   - Map EDMAC channels used for encoder I/O (data flows: sensor → ISP → YUV buffer → H.264 encoder → output buffer)
2. **Intercept encoded bitstream**:
   - Hook into the H.264 output stage — read NAL units (SPS, PPS, I-frames, P-frames) before MOV file writing
   - Add new PTP sub-command `PTP_CHDK_GetH264Frame` to stream encoded NAL units to PC
   - Configure encoder for low-latency profile (minimize B-frames, reduce GOP size for faster seeking)
   - Target: I-frame every 1-2 seconds, P-frames in between
3. **Async double-buffered streaming** using `CreateTask()` (DryOS task):
   - Dedicated task monitors H.264 encoder output buffer
   - PTP handler returns latest encoded frame (near zero-copy — data is already compressed)
   - Decouples encoder from USB transfer

### PC-side: H.264 decode + image enhancement

4. **H.264 decoding** on PC:
   - Use FFmpeg/libavcodec for H.264 → RGB decode
   - Hardware-accelerated decode via DXVA2 / D3D11VA (near-zero CPU cost)
   - Fallback: software decode (still fast — 640x480 H.264 is trivial for modern CPUs)
5. **Upscaling pipeline** (640x480 → 720p or 1080p output):
   - Lanczos3 or bicubic upscaling for clean output at higher resolutions
   - GPU-accelerated scaling via DirectX/OpenGL if available
6. **Real-time image processing**:
   - Auto white balance correction (compensate for indoor lighting)
   - Adaptive sharpening (unsharp mask, tuned for webcam content)
   - Noise reduction (lightweight temporal NR — average across frames to reduce noise)
   - Exposure/brightness normalization
   - Optional: face detection for auto-crop/zoom (using OpenCV)
7. **Frame rate smoothing**:
   - Frame interpolation to fill gaps (repeat or blend frames)
   - Consistent output timing for smooth video in calls

### USB/transfer optimization

8. **Minimize PTP transaction overhead**:
   - H.264 frames at ~5-10 KB transfer in <0.2 ms on USB 2.0 HS
   - Investigate batching multiple frames per PTP data phase
   - Consider "streaming mode" where camera pushes frames without per-frame PTP commands
9. **PC-side latency reduction**:
   - Dedicated high-priority USB transfer thread
   - Frame pipelining: decode frame N while transferring frame N+1
   - Target: end-to-end latency under 150 ms

### Expected result
- **30 FPS at 640x480** (native hardware encoder rate)
- **~5-10 KB per frame** (3-8x smaller than MJPEG)
- **Zero CPU encoding overhead** on camera (hardware H.264)
- Upscaled to 720p/1080p with PC-side enhancement
- Sub-150 ms latency

---

## Phase 3: Native UVC Investigation (3-6 months, optional)

1. Load firmware dump (`ixus870_sd880_100e.7z`) into **Ghidra**
2. Trace Canon's USB initialization, map Digic IV USB controller registers (suspected `0xC0220000` range)
3. Attempt UVC descriptor injection + bulk/isochronous endpoint setup
4. If successful: camera appears as native UVC webcam with zero PC-side software

---

## Development Environment Setup (Windows)

### Software to Install

| Tool | Purpose | Download |
|------|---------|----------|
| **Docker Desktop** | CHDK cross-compilation (ARM gcc toolchain) | docker.com |
| **Git for Windows** | Clone repositories | git-scm.com |
| **Visual Studio 2022 Community** | Build PC-side bridge app (C++) | visualstudio.microsoft.com |
| **vcpkg** | C++ package manager (libusb, libjpeg-turbo, OpenCV, FFmpeg) | github.com/microsoft/vcpkg |
| **softcam** | Virtual webcam DirectShow filter | github.com/tshino/softcam |
| **Zadig** | Replace Canon USB driver with libusb-win32 | zadig.akeo.ie |
| **chdkptp** | Verify PTP connectivity before custom development | CHDK wiki downloads |
| **Wireshark + USBPcap** | USB packet capture & debugging | wireshark.org |
| **7-Zip** | Extract firmware dump archives | 7-zip.org |
| **Ghidra** | Firmware reverse engineering (Phase 1 buffer RE + Phase 2 H.264 RE) | ghidra-sre.org |

### Project Directory Layout

```
C:\Data\IXUS870IS\                          -- Project root (existing)
C:\chdk\trunk\                              -- CHDK source tree (git clone)
C:\projects\chdk-webcam\                    -- PC-side bridge application
C:\projects\chdk-webcam\lib\softcam\        -- Virtual webcam library
C:\projects\chdk-webcam\src\ptp\            -- PTP protocol implementation
C:\projects\chdk-webcam\src\yuv_convert\    -- YUV-to-RGB conversion
C:\projects\chdk-webcam\src\webcam\         -- Virtual webcam integration
C:\projects\chdk-webcam\src\enhance\        -- Image enhancement pipeline
```

---

## Hardware Setup for Testing

### Required Hardware

| Item | Purpose |
|------|---------|
| Canon IXUS 870 IS (GM1.00E) | Target camera |
| NB-5L battery (2x recommended) | Power supply |
| NB-5L compatible AC adapter | Continuous power for extended sessions |
| SD card (2-4 GB, FAT32) | CHDK firmware |
| SD card reader | Copy builds to card |
| Mini-USB to USB-A cable | Camera-to-PC connection |

### Connection & Testing Workflow

```
[Edit source] → [Build (Docker or VS)] → [Copy to SD card] → [Camera power on + load CHDK]
     → [Connect USB] → [Run chdk-webcam.exe] → [Test in Zoom/Teams] → [Debug with Wireshark]
```

**Development inner loop**: Docker build → SD card copy → camera reboot → test. ~2-3 min per cycle.

**PC-only changes**: Edit bridge code → rebuild in VS → run → test. No SD card swapping needed.

### USB Driver Setup

1. Connect camera with CHDK running
2. Open Zadig → select Canon camera → replace driver with **libusb-win32**
3. Verify with chdkptp: `chdkptp -c -e"luar get_buildinfo()"`
4. Ensure no other PTP clients running (Canon software, Windows photo import) — causes 1000x slowdown

### Optimal Camera Settings for Webcam Use

Configure via CHDK ALT mode menu before streaming:
- **ISO**: 400-800 (for indoor lighting)
- **Shutter**: 1/30s or 1/60s (smooth motion)
- **Focus**: Manual focus at desk distance (~50-80 cm), or continuous AF
- **Display**: Press DISP to remove UI overlays (clean image in viewport)
- **IS**: Leave enabled (stabilizes handheld or light desk vibrations)

---

## Risks and Mitigations

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| PTP polling caps frame rate at ~10 FPS | Medium | Optimize polling interval; MJPEG compression reduces transfer size; Phase 2 H.264 at ~5 KB/frame |
| Software JPEG encoding too slow on ARM926 (~200 MHz) | Medium | Start with quality 50; input is already YUV; Phase 2 switches to hardware H.264 (zero CPU cost) |
| H.264 bitstream interception requires firmware RE | Medium | MJPEG (Phase 1) works as permanent fallback; Ghidra analysis of video recording code path; safe RAM-only testing via CHDK |
| Video mode buffer access not straightforward | Medium | Reverse-engineer buffer addresses via firmware dump in Ghidra; CHDK `vid_get_viewport_active_buffer()` as fallback |
| Camera overheating during extended streaming | Low-Medium | Monitor CHDK temperature OSD; use AC adapter; reduce frame rate if needed |
| Corrupted frames when LCD sleeps or camera state changes | High (documented) | Detect bad frames PC-side; repeat last good frame; "webcam mode" prevents LCD sleep |
| libusb-win32 driver conflicts | Low-Medium | Test with chdkptp first; keep system restore point; Canon VID `0x04A9` |
| Virtual webcam DLL not visible in apps | Low | Register both 32-bit and 64-bit DLLs; OBS capture remains as fallback |
| PC-side enhancement adds latency | Low | Use GPU acceleration; keep enhancement pipeline under 10 ms per frame |
