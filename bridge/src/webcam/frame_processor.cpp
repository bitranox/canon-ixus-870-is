#include "frame_processor.h"
#include <cstring>
#include <string>
#include <algorithm>
#include <cmath>

#ifdef HAS_TURBOJPEG
#include <turbojpeg.h>
#else
// Minimal JPEG decoder using standard jpeglib
extern "C" {
#include <jpeglib.h>
}
#endif

namespace webcam {

struct FrameProcessor::Impl {
    ProcessorConfig config;
    std::string last_error;

#ifdef HAS_TURBOJPEG
    tjhandle tj_handle = nullptr;
#endif

    // Intermediate buffer for decoded image (before scaling)
    std::vector<uint8_t> decoded_buf;
    int decoded_width = 0;
    int decoded_height = 0;

    Impl() {
#ifdef HAS_TURBOJPEG
        tj_handle = tjInitDecompress();
#endif
    }

    ~Impl() {
#ifdef HAS_TURBOJPEG
        if (tj_handle) {
            tjDestroy(tj_handle);
        }
#endif
    }

    bool decode_jpeg(const uint8_t* jpeg_data, int jpeg_size) {
#ifdef HAS_TURBOJPEG
        int width, height, subsamp, colorspace;
        if (tjDecompressHeader3(tj_handle, jpeg_data, jpeg_size,
                                &width, &height, &subsamp, &colorspace) < 0) {
            last_error = "JPEG header decode failed: " + std::string(tjGetErrorStr2(tj_handle));
            return false;
        }

        decoded_width = width;
        decoded_height = height;
        int stride = width * 3;
        decoded_buf.resize(stride * height);

        if (tjDecompress2(tj_handle, jpeg_data, jpeg_size,
                          decoded_buf.data(), width, stride, height,
                          TJPF_RGB, TJFLAG_FASTDCT) < 0) {
            const char* err = tjGetErrorStr2(tj_handle);
            // "extraneous bytes" is a non-fatal warning — image decoded OK.
            // This happens when the JPEG encoder writes slightly more MCU
            // data than the SOF0 header declares.
            if (err && strstr(err, "extraneous bytes")) {
                return true;
            }
            last_error = "JPEG decode failed: " + std::string(err ? err : "unknown");
            return false;
        }
        return true;
#else
        // Use standard libjpeg
        struct jpeg_decompress_struct cinfo;
        struct jpeg_error_mgr jerr;

        cinfo.err = jpeg_std_error(&jerr);
        jpeg_create_decompress(&cinfo);
        jpeg_mem_src(&cinfo, jpeg_data, jpeg_size);

        if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
            last_error = "JPEG header read failed";
            jpeg_destroy_decompress(&cinfo);
            return false;
        }

        cinfo.out_color_space = JCS_RGB;
        cinfo.dct_method = JDCT_IFAST;

        jpeg_start_decompress(&cinfo);

        decoded_width = cinfo.output_width;
        decoded_height = cinfo.output_height;
        int stride = decoded_width * 3;
        decoded_buf.resize(stride * decoded_height);

        while (cinfo.output_scanline < cinfo.output_height) {
            uint8_t* row = decoded_buf.data() + cinfo.output_scanline * stride;
            jpeg_read_scanlines(&cinfo, &row, 1);
        }

        jpeg_finish_decompress(&cinfo);
        jpeg_destroy_decompress(&cinfo);
        return true;
#endif
    }

    // Bilinear upscale from decoded_buf to output
    void bilinear_scale(uint8_t* dst, int dst_w, int dst_h, int dst_stride) {
        if (decoded_width <= 0 || decoded_height <= 0) return;

        int src_stride = decoded_width * 3;
        float x_ratio = static_cast<float>(decoded_width) / dst_w;
        float y_ratio = static_cast<float>(decoded_height) / dst_h;

        for (int y = 0; y < dst_h; y++) {
            float src_y = y * y_ratio;
            int y0 = static_cast<int>(src_y);
            int y1 = std::min(y0 + 1, decoded_height - 1);
            float fy = src_y - y0;
            float fy_inv = 1.0f - fy;

            uint8_t* dst_row = dst + y * dst_stride;
            const uint8_t* src_row0 = decoded_buf.data() + y0 * src_stride;
            const uint8_t* src_row1 = decoded_buf.data() + y1 * src_stride;

            for (int x = 0; x < dst_w; x++) {
                float src_x = x * x_ratio;
                int x0 = static_cast<int>(src_x);
                int x1 = std::min(x0 + 1, decoded_width - 1);
                float fx = src_x - x0;
                float fx_inv = 1.0f - fx;

                int x0_3 = x0 * 3;
                int x1_3 = x1 * 3;

                for (int c = 0; c < 3; c++) {
                    float v = src_row0[x0_3 + c] * fx_inv * fy_inv
                            + src_row0[x1_3 + c] * fx * fy_inv
                            + src_row1[x0_3 + c] * fx_inv * fy
                            + src_row1[x1_3 + c] * fx * fy;
                    dst_row[x * 3 + c] = static_cast<uint8_t>(std::min(255.0f, std::max(0.0f, v + 0.5f)));
                }
            }
        }
    }

    void flip_frame(uint8_t* data, int width, int height, int stride, bool h, bool v) {
        if (h) {
            for (int y = 0; y < height; y++) {
                uint8_t* row = data + y * stride;
                for (int x = 0; x < width / 2; x++) {
                    int x2 = width - 1 - x;
                    std::swap(row[x * 3 + 0], row[x2 * 3 + 0]);
                    std::swap(row[x * 3 + 1], row[x2 * 3 + 1]);
                    std::swap(row[x * 3 + 2], row[x2 * 3 + 2]);
                }
            }
        }
        if (v) {
            std::vector<uint8_t> tmp(stride);
            for (int y = 0; y < height / 2; y++) {
                uint8_t* row1 = data + y * stride;
                uint8_t* row2 = data + (height - 1 - y) * stride;
                memcpy(tmp.data(), row1, stride);
                memcpy(row1, row2, stride);
                memcpy(row2, tmp.data(), stride);
            }
        }
    }
};

FrameProcessor::FrameProcessor() : impl_(std::make_unique<Impl>()) {}
FrameProcessor::~FrameProcessor() = default;

void FrameProcessor::configure(const ProcessorConfig& config) {
    impl_->config = config;
}

bool FrameProcessor::process(const uint8_t* jpeg_data, int jpeg_size, RGBFrame& rgb_out) {
    if (!jpeg_data || jpeg_size <= 0) {
        impl_->last_error = "Invalid JPEG data";
        return false;
    }

    // Decode JPEG
    if (!impl_->decode_jpeg(jpeg_data, jpeg_size)) {
        return false;
    }

    // TODO: upscaling temporarily disabled to see raw camera output
#if 0
    int out_w = impl_->config.output_width;
    int out_h = impl_->config.output_height;
    int out_stride = out_w * 3;

    // If decoded size matches output, skip scaling
    if (impl_->decoded_width == out_w && impl_->decoded_height == out_h) {
        rgb_out.data = impl_->decoded_buf;
        rgb_out.width = out_w;
        rgb_out.height = out_h;
        rgb_out.stride = out_stride;
    } else {
        // Scale to output size
        rgb_out.data.resize(out_stride * out_h);
        rgb_out.width = out_w;
        rgb_out.height = out_h;
        rgb_out.stride = out_stride;
        impl_->bilinear_scale(rgb_out.data.data(), out_w, out_h, out_stride);
    }
#else
    // Pass through at native decoded resolution
    int out_w = impl_->decoded_width;
    int out_h = impl_->decoded_height;
    int out_stride = out_w * 3;

    rgb_out.data = impl_->decoded_buf;
    rgb_out.width = out_w;
    rgb_out.height = out_h;
    rgb_out.stride = out_stride;
#endif

    // Apply flips if configured
    if (impl_->config.flip_horizontal || impl_->config.flip_vertical) {
        impl_->flip_frame(rgb_out.data.data(), rgb_out.width, rgb_out.height,
                          rgb_out.stride, impl_->config.flip_horizontal,
                          impl_->config.flip_vertical);
    }

    return true;
}

std::string FrameProcessor::get_last_error() const {
    return impl_->last_error;
}

} // namespace webcam
