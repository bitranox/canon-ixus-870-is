// CHDK Webcam Module
// Switches camera to video mode and captures the viewport buffer as MJPEG.
// The compressed frame is made available via the module interface for
// streaming over PTP to a PC-side virtual webcam bridge.
//
// On start, the module switches the camera from playback/PTP mode into
// record mode and then sets the shooting mode to video (MODE_VIDEO_STD).
// This activates the camera's video pipeline at 640x480.
//
// The viewport buffer in video mode is 720x240 YUV411 on Digic IV
// (the LCD preview of the 640x480 video).  A future improvement is to
// read the 640x480 video pre-encoder buffer directly.
//
// The module uses a software JPEG encoder (tje.c) to compress each frame.

#include "camera_info.h"
#include "viewport.h"
#include "shooting.h"
#include "modes.h"
#include "levent.h"
#include "clock.h"
#include "stdlib.h"
#include "module_def.h"
#include "webcam.h"
#include "tje.h"

// Maximum JPEG output buffer size.
// 720x240 at quality 50+ can exceed 64 KB, so use 256 KB.
#define JPEG_BUF_SIZE       (256 * 1024)

// Double-buffer JPEG output to avoid tearing
#define NUM_JPEG_BUFS       2

// Module state
static int webcam_active = 0;
static int webcam_jpeg_quality = 50;
static int webcam_mode_switched = 0;    // 1 if we switched to video mode

// JPEG double buffer
static unsigned char *jpeg_buf[NUM_JPEG_BUFS] = { 0, 0 };
static int jpeg_buf_size[NUM_JPEG_BUFS] = { 0, 0 };
static int jpeg_buf_current = 0;    // Index of the buffer being written
static int jpeg_buf_ready = -1;     // Index of the buffer ready for reading (-1 = none)

// Frame counter and timing
static unsigned int frame_count = 0;
static unsigned int last_frame_tick = 0;
static int current_fps = 0;

// Captured frame dimensions
static unsigned int frame_width = 0;
static unsigned int frame_height = 0;

// Stale frame detection: checksum of a few bytes at the start of the viewport
static unsigned int last_vp_checksum = 0;

// ============================================================
// Frame capture and compression
// ============================================================

// Test pattern removed to save ~259KB BSS (camera has limited memory)

// Capture a frame from the viewport buffer and compress to JPEG.
// Returns the size of the compressed JPEG, or 0 on error.
static int capture_and_compress_frame(void)
{
    void *vp_buf;
    int vp_width, vp_height, vp_byte_width;
    int jpeg_size;
    int buf_idx;

    // Get viewport buffer (vid_get_viewport_active_buffer is the exported symbol)
    vp_buf = vid_get_viewport_active_buffer();
    if (!vp_buf) {
        return 0;
    }

    // Stale frame detection: quick checksum of a few viewport bytes.
    // If the buffer hasn't changed since last capture, the viewport isn't
    // being refreshed (camera may be in playback/USB mode without live view).
    {
        const unsigned char *p = (const unsigned char *)vp_buf;
        unsigned int cksum = p[0] ^ (p[100] << 8) ^ (p[540] << 16) ^ (p[1080] << 24);
        if (cksum == last_vp_checksum && frame_count > 0) {
            // Buffer unchanged — skip encoding to avoid sending identical frames
            return 0;
        }
        last_vp_checksum = cksum;
    }

    // Get viewport dimensions.
    //
    // vid_get_viewport_byte_width() returns the reliable, hardcoded physical
    // row stride (1080 bytes on IXUS 870 IS).  We derive pixel width from it
    // rather than from vid_get_viewport_width(), because the latter reads
    // camera_screen.width which can return unexpected values when the camera
    // is in PTP/USB mode (e.g. 104 instead of 360, yielding 208 pixels).
    //
    // YUV411 (UYVYYY) format: 6 bytes per 4 pixels, so:
    //   pixel_width = byte_width * 4 / 6
    vp_byte_width = vid_get_viewport_byte_width();
    vp_height = vid_get_viewport_height_proper();

    if (vp_byte_width >= 6) {
        vp_width = (vp_byte_width * 4) / 6;
    } else {
        vp_width = 0;
    }

    if (vp_width < 16 || vp_height < 16 || vp_byte_width < 16) {
        // Fallback to known IXUS 870 IS defaults
        vp_width = 720;
        vp_height = 240;
        vp_byte_width = (720 * 6) / 4; // YUV411: 6 bytes per 4 pixels = 1080
    }

    // Select the next write buffer
    buf_idx = jpeg_buf_current;

    // Ensure buffer is allocated
    if (!jpeg_buf[buf_idx]) {
        jpeg_buf[buf_idx] = malloc(JPEG_BUF_SIZE);
        if (!jpeg_buf[buf_idx]) {
            return 0;
        }
    }

    // Compress using YUV411 encoder (native Digic IV format: UYVYYY)
    jpeg_size = tje_encode_yuv411(
        jpeg_buf[buf_idx],
        JPEG_BUF_SIZE,
        vp_width,
        vp_height,
        (const unsigned char *)vp_buf,
        vp_byte_width,
        webcam_jpeg_quality
    );

    if (jpeg_size > 0 && jpeg_size <= JPEG_BUF_SIZE) {
        jpeg_buf_size[buf_idx] = jpeg_size;
        frame_width = vp_width;
        frame_height = vp_height;

        // Swap buffers: make this one ready, start writing to the other
        jpeg_buf_ready = buf_idx;
        jpeg_buf_current = (buf_idx + 1) % NUM_JPEG_BUFS;

        // Update frame counter and FPS
        frame_count++;
        {
            unsigned int now = get_tick_count();
            if (last_frame_tick > 0 && now > last_frame_tick) {
                // Simple exponential moving average FPS
                int delta = now - last_frame_tick;
                if (delta > 0) {
                    int instant_fps = 1000 / delta;
                    current_fps = (current_fps * 7 + instant_fps * 3) / 10;
                }
            }
            last_frame_tick = now;
        }
    }

    return jpeg_size;
}

// ============================================================
// Module interface implementation
// ============================================================

// Switch camera to video mode for webcam streaming.
// Returns 0 on success, -1 on failure.
static int switch_to_video_mode(void)
{
    int retries;

    // Step 1: Switch from playback to record mode.
    // switch_mode_usb() is the PTP-safe way to do this while USB is connected.
    if (camera_info.state.mode_play) {
        switch_mode_usb(1);

        // Wait for mode switch to complete (up to 2 seconds)
        for (retries = 0; retries < 20; retries++) {
            msleep(100);
            if (!camera_info.state.mode_play) break;
        }
        if (camera_info.state.mode_play) {
            return -1;
        }
    }

    // Step 2: Switch shooting mode to video (MODE_VIDEO_STD).
    // shooting_set_mode_chdk() calls SetCurrentCaptureModeType internally.
    if (!camera_info.state.mode_video) {
        shooting_set_mode_chdk(MODE_VIDEO_STD);

        // Wait for video mode to stabilize (up to 3 seconds)
        for (retries = 0; retries < 30; retries++) {
            msleep(100);
            if (camera_info.state.mode_video) break;
        }
    }

    webcam_mode_switched = 1;
    return 0;
}

static int webcam_start(int jpeg_quality)
{
    if (webcam_active) {
        return 0; // Already active
    }

    if (jpeg_quality < 1) jpeg_quality = 1;
    if (jpeg_quality > 100) jpeg_quality = 100;
    webcam_jpeg_quality = jpeg_quality;

    // Mark active BEFORE the slow mode switch to prevent
    // module_tick_unloader() from unloading us during msleep() calls.
    webcam_active = 1;

    // Switch camera to video mode
    if (switch_to_video_mode() < 0) {
        webcam_active = 0;
        return -2; // Mode switch failed
    }

    // Allocate JPEG buffers
    {
        int i;
        for (i = 0; i < NUM_JPEG_BUFS; i++) {
            if (!jpeg_buf[i]) {
                jpeg_buf[i] = malloc(JPEG_BUF_SIZE);
                if (!jpeg_buf[i]) {
                    // Cleanup on failure
                    int j;
                    for (j = 0; j < i; j++) {
                        free(jpeg_buf[j]);
                        jpeg_buf[j] = 0;
                    }
                    webcam_active = 0;
                    return -1;
                }
            }
            jpeg_buf_size[i] = 0;
        }
    }

    jpeg_buf_current = 0;
    jpeg_buf_ready = -1;
    frame_count = 0;
    last_frame_tick = 0;
    current_fps = 0;
    frame_width = 0;
    frame_height = 0;
    last_vp_checksum = 0;

    // webcam_active already set to 1 above (before mode switch)
    return 0;
}

static int webcam_stop(void)
{
    int i;

    webcam_active = 0;

    for (i = 0; i < NUM_JPEG_BUFS; i++) {
        if (jpeg_buf[i]) {
            free(jpeg_buf[i]);
            jpeg_buf[i] = 0;
        }
        jpeg_buf_size[i] = 0;
    }

    jpeg_buf_current = 0;
    jpeg_buf_ready = -1;
    frame_count = 0;
    current_fps = 0;

    // Switch back to playback mode if we changed it
    if (webcam_mode_switched) {
        switch_mode_usb(0);
        webcam_mode_switched = 0;
    }

    return 0;
}

static int webcam_get_frame(webcam_frame_t *frame)
{
    int jpeg_size;

    if (!webcam_active || !frame) {
        return -1;
    }

    // Capture a new frame
    jpeg_size = capture_and_compress_frame();

    if (jpeg_size <= 0 || jpeg_buf_ready < 0) {
        return -1;
    }

    // Return the ready buffer
    frame->data = jpeg_buf[jpeg_buf_ready];
    frame->size = jpeg_buf_size[jpeg_buf_ready];
    frame->width = frame_width;
    frame->height = frame_height;
    frame->frame_num = frame_count;

    return 0;
}

static void webcam_get_status(webcam_status_t *status)
{
    if (!status) return;

    status->active = webcam_active;
    status->frames_sent = frame_count;
    status->fps = current_fps;
    status->jpeg_quality = webcam_jpeg_quality;
    status->frame_size = (jpeg_buf_ready >= 0) ? jpeg_buf_size[jpeg_buf_ready] : 0;
    status->width = frame_width;
    status->height = frame_height;
}

// ============================================================
// Module lifecycle
// ============================================================

static int _module_unloader(void)
{
    webcam_stop();
    return 0;
}

static int _module_can_unload(void)
{
    return (webcam_active == 0);
}

static int _module_exit_alt(void)
{
    webcam_stop();
    return 0;
}

// ============================================================
// Module definition
// ============================================================

libwebcam_sym _libwebcam = {
    {
        0,                      // loader
        _module_unloader,       // unloader
        _module_can_unload,     // can_unload
        _module_exit_alt,       // exit_alt
        0                       // run
    },
    webcam_start,
    webcam_stop,
    webcam_get_frame,
    webcam_get_status
};

ModuleInfo _module_info = {
    MODULEINFO_V1_MAGICNUM,
    sizeof(ModuleInfo),
    WEBCAM_VERSION,
    ANY_CHDK_BRANCH, 0, OPT_ARCHITECTURE,
    ANY_PLATFORM_ALLOWED,
    (int32_t)"Webcam",
    MTYPE_EXTENSION,
    &_libwebcam.base,
    ANY_VERSION,                // conf_ver
    ANY_VERSION,                // cam_screen_ver
    ANY_VERSION,                // cam_sensor_ver
    ANY_VERSION,                // cam_info_ver
    0                           // symbol
};
