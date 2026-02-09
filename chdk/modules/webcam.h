// CHDK Webcam Module
// Captures video mode frame buffer (640x480 YUV) and compresses to MJPEG
// for streaming over PTP to a PC-side virtual webcam bridge.

#ifndef WEBCAM_H
#define WEBCAM_H

#include "flt.h"

// Update version if changes are made to the module interface
#define WEBCAM_VERSION          {1,0}

// MJPEG frame info returned to callers
typedef struct {
    unsigned char  *data;       // Pointer to JPEG data
    unsigned int    size;       // Size of JPEG data in bytes
    unsigned int    width;      // Frame width
    unsigned int    height;     // Frame height
    unsigned int    frame_num;  // Monotonic frame counter
} webcam_frame_t;

// Webcam status
typedef struct {
    int             active;         // 1 if webcam streaming is active
    int             frames_sent;    // Total frames sent
    int             fps;            // Approximate current FPS
    int             jpeg_quality;   // Current JPEG quality (1-100)
    int             frame_size;     // Last frame size in bytes
    unsigned int    width;          // Current frame width
    unsigned int    height;         // Current frame height
} webcam_status_t;

// Module interface
typedef struct {
    base_interface_t    base;

    // Start webcam streaming mode.
    // jpeg_quality: 1-100 (lower = smaller frames, higher = better quality)
    // Returns 0 on success, non-zero on error.
    int (*start)(int jpeg_quality);

    // Stop webcam streaming mode.
    // Returns 0 on success.
    int (*stop)(void);

    // Get the latest MJPEG frame.
    // frame: output pointer to frame info (valid until next get_frame call)
    // Returns 0 on success, non-zero if no frame available.
    int (*get_frame)(webcam_frame_t *frame);

    // Get current webcam status.
    void (*get_status)(webcam_status_t *status);
} libwebcam_sym;

extern libwebcam_sym* libwebcam;

#endif
