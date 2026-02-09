#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace webcam {

// Output frame format
struct RGBFrame {
    std::vector<uint8_t> data;  // RGB24 pixel data
    int width;
    int height;
    int stride;                 // Bytes per row (width * 3, may be padded)
};

// Frame processor configuration
struct ProcessorConfig {
    int output_width = 1280;    // Output width (default 720p)
    int output_height = 720;    // Output height (default 720p)
    bool flip_horizontal = false;
    bool flip_vertical = false;
};

class FrameProcessor {
public:
    FrameProcessor();
    ~FrameProcessor();

    // Configure output dimensions and processing
    void configure(const ProcessorConfig& config);

    // Decode JPEG data and upscale to configured output size.
    // Returns true on success, output in rgb_out.
    bool process(const uint8_t* jpeg_data, int jpeg_size, RGBFrame& rgb_out);

    // Get last error
    std::string get_last_error() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace webcam
