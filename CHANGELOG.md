# Changelog

All notable changes to this project will be documented in this file.

## [0.0.1] - 2026-02-15

### Summary

First stable release. The Canon IXUS 870 IS streams 640x480 raw UYVY video at ~4.9 FPS over USB to a PC-side bridge that presents a DirectShow virtual webcam device.

### Camera Module (webcam.flt)

- **Raw UYVY streaming** — captures uncompressed 640x480 frames directly from the Digic IV ISP recording pipeline DMA buffers, bypassing all on-camera encoding
- **Pipeline callback spy** — installs a callback at `state[+0x114]` in the firmware's recording pipeline to intercept frame buffer addresses at 30fps
- **Video mode activation** — switches camera from Playback/PTP to Video Recording mode, forces `state[+0xD4]=2` for recording path dispatch
- **JPCORE power management** — powers on JPCORE hardware block (required for recording pipeline callbacks to fire, even though JPEG output is unused)
- **Auto-power-off disabled** — prevents camera shutdown during streaming via `disable_shutdown()`
- **Software JPEG fallback** — Tiny JPEG Encoder (tje.c) for UYVY-to-JPEG conversion at ~1.3 FPS when raw path is unavailable
- **PTP integration** — opcode 0x9999 sub-command 15 (GetMJPEGFrame) with start/stop/get_frame multiplexing and format encoding in param4 high byte

### PC Bridge (chdk-webcam.exe)

- **PTP client** — libusb-1.0 based Canon PTP/CHDK protocol implementation with session management
- **UYVY-to-RGB conversion** — BT.601 fixed-point color conversion with Digic IV signed chroma handling (int8_t, not uint8_t-128)
- **DirectShow virtual webcam** — "CHDK Webcam" source filter visible in Zoom, Teams, OBS, and all DirectShow-compatible apps
- **Preview window** — Win32 GDI live preview at native 640x480
- **Automatic format detection** — handles both UYVY (raw) and JPEG frames based on param4 format byte
- **Diagnostic output** — pipeline state dump on start, per-second FPS/bitrate/dropped frame statistics
- **CLI options** — quality, flip-h/v, no-webcam, no-preview, verbose modes

### Firmware Reverse Engineering

- **Ghidra project** — fully analyzed IXUS 870 IS firmware 1.01a (ARM:LE:32:v5t, base 0xFF810000)
- **~40 firmware functions decompiled** — video pipeline, JPCORE encoder, ISP routing, DMA management, power control, state machine
- **20+ Ghidra scripts** — Java-based headless decompilation scripts for targeted function analysis
- **Key discoveries:**
  - Recording pipeline state structure at RAM 0x70D8 with ~20 documented offsets
  - JPCORE hardware encoder state at RAM 0x2554 and buffer array at 0x2580
  - ISP routing registers (0xC0F110C4) and their write-only behavior with shadow copies at 0x340000+
  - PipelineFrameCallback → FrameProcessing dispatch controlled by state[+0xD4]
  - Triple DMA ring buffer rotation (0x40BAADD0, 0x40C7DCD0, 0x40D50BD0)
  - Digic IV signed chroma encoding (non-standard UYVY format)
  - IXUS 870 IS uses H.264 (MOV) for video, not MJPEG — StartMjpegMaking functions are legacy/unused for encoding on this generation

### Known Limitations

- Frame rate limited to ~5 FPS by USB 2.0 bulk transfer of 614KB/frame
- Resolution fixed at 640x480 (camera video mode native output)
- Windows only (DirectShow bridge) — Linux v4l2loopback port would be straightforward
- Firmware addresses hardcoded for IXUS 870 IS fw 1.01a
- Camera LCD may show artifacts during streaming (recording path overrides display pipeline)
