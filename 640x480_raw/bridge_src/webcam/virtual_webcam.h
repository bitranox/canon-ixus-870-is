#pragma once

#include <cstdint>
#include <string>
#include <memory>

namespace webcam {

// Virtual webcam configuration
struct VirtualWebcamConfig {
    int width = 1280;           // Output width
    int height = 720;           // Output height
    int fps = 30;               // Target frame rate
    std::string name = "CHDK Webcam";  // Device name
};

class VirtualWebcam {
public:
    VirtualWebcam();
    ~VirtualWebcam();

    // Initialize virtual webcam device
    // Returns true on success
    bool init(const VirtualWebcamConfig& config);

    // Send a frame to the virtual webcam
    // rgb_data: RGB24 pixel data, top-to-bottom, left-to-right
    // Must be width * height * 3 bytes
    bool send_frame(const uint8_t* rgb_data, int width, int height, int stride);

    // Shut down the virtual webcam
    void shutdown();

    // Check if initialized
    bool is_active() const;

    // Get last error
    std::string get_last_error() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace webcam
