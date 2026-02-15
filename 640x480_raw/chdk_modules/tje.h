// Tiny JPEG Encoder - minimal JPEG encoder for embedded use
// Based on the public domain Tiny JPEG Encoder by Sergio Gonzalez
// Adapted for CHDK (no libc stdio, uses memory buffer output)

#ifndef TJE_H
#define TJE_H

// Encode a YUV411 (UYVYYY) image to JPEG in memory.
// This is the native CHDK viewport format on Digic IV (LV_FB_YUV8).
// Each group of 4 pixels = 6 bytes: U Y0 V Y1 Y2 Y3
// Parameters:
//   dst_buf:     Output buffer for JPEG data
//   dst_buf_len: Size of output buffer
//   width:       Image width in pixels (must be multiple of 8)
//   height:      Image height in pixels (must be multiple of 8)
//   yuv_data:    Input UYVYYY data
//   yuv_stride:  Bytes per row of input data
//   quality:     JPEG quality 1-100
// Returns: size of JPEG data written, or 0 on error.
int tje_encode_yuv411(
    unsigned char *dst_buf,
    int dst_buf_len,
    int width,
    int height,
    const unsigned char *yuv_data,
    int yuv_stride,
    int quality
);

// Encode a UYVY (YUV422) image to JPEG in memory.
// This is the Digic IV video pipeline output format (640x480).
// Each pair of 2 pixels = 4 bytes: U Y0 V Y1
// Parameters same as tje_encode_yuv411.
// yuv_stride should be width * 2.
int tje_encode_uyvy(
    unsigned char *dst_buf,
    int dst_buf_len,
    int width,
    int height,
    const unsigned char *yuv_data,
    int yuv_stride,
    int quality
);

#endif
