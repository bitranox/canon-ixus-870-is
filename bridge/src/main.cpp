// chdk-webcam: Bridge between Canon IXUS 870 IS (CHDK) and virtual webcam
//
// Connects to a Canon camera running CHDK via PTP/USB, retrieves MJPEG frames
// from the webcam module, decodes and upscales them, and feeds them into a
// virtual webcam device visible to Zoom, Teams, OBS, etc.
//
// Usage:
//   chdk-webcam [options]
//
// Options:
//   -q, --quality N     JPEG quality on camera (1-100, default 50)
//   -w, --width N       Output width (default 1280)
//   -h, --height N      Output height (default 720)
//   -f, --fps N         Target frame rate (default 30)
//   --flip-h            Flip image horizontally (mirror)
//   --flip-v            Flip image vertically
//   --no-webcam         Don't create virtual webcam (display only)
//   --verbose           Show frame statistics

#include "ptp/ptp_client.h"
#include "webcam/frame_processor.h"
#include "webcam/preview_window.h"
#include "webcam/virtual_webcam.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <csignal>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

// Global flag for graceful shutdown
static volatile bool g_running = true;

static void signal_handler(int) {
    g_running = false;
}

struct Options {
    int jpeg_quality = 50;
    int output_width = 1280;
    int output_height = 720;
    int target_fps = 30;
    bool flip_h = false;
    bool flip_v = false;
    bool no_webcam = false;
    bool no_preview = false;
    bool verbose = false;
};

static void print_usage(const char* prog) {
    fprintf(stderr,
        "CHDK Webcam Bridge v1.0\n"
        "Streams video from Canon IXUS 870 IS (CHDK) as a virtual webcam.\n"
        "\n"
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  -q, --quality N     JPEG quality on camera (1-100, default 50)\n"
        "  -w, --width N       Output width (default 1280)\n"
        "  -h, --height N      Output height (default 720)\n"
        "  -f, --fps N         Target FPS (default 30)\n"
        "  --flip-h            Mirror horizontally\n"
        "  --flip-v            Flip vertically\n"
        "  --no-webcam         Skip virtual webcam creation\n"
        "  --no-preview        Skip preview window\n"
        "  --verbose           Show per-frame statistics\n"
        "  --help              Show this help\n"
        "\n"
        "Prerequisites:\n"
        "  1. Camera running CHDK with webcam module\n"
        "  2. libusb-win32 driver installed (use Zadig)\n"
        "  3. No other PTP clients running (Canon software, Windows photo import)\n"
        "\n", prog);
}

static Options parse_args(int argc, char* argv[]) {
    Options opts;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if ((arg == "-q" || arg == "--quality") && i + 1 < argc) {
            opts.jpeg_quality = atoi(argv[++i]);
        } else if ((arg == "-w" || arg == "--width") && i + 1 < argc) {
            opts.output_width = atoi(argv[++i]);
        } else if ((arg == "-h" || arg == "--height") && i + 1 < argc) {
            opts.output_height = atoi(argv[++i]);
        } else if ((arg == "-f" || arg == "--fps") && i + 1 < argc) {
            opts.target_fps = atoi(argv[++i]);
        } else if (arg == "--flip-h") {
            opts.flip_h = true;
        } else if (arg == "--flip-v") {
            opts.flip_v = true;
        } else if (arg == "--no-webcam") {
            opts.no_webcam = true;
        } else if (arg == "--no-preview") {
            opts.no_preview = true;
        } else if (arg == "--verbose") {
            opts.verbose = true;
        } else if (arg == "--help") {
            print_usage(argv[0]);
            exit(0);
        } else {
            fprintf(stderr, "Unknown option: %s\n", arg.c_str());
            print_usage(argv[0]);
            exit(1);
        }
    }
    return opts;
}

int main(int argc, char* argv[]) {
    Options opts = parse_args(argc, argv);

    // Install signal handler for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

#ifdef _WIN32
    // Enable ANSI escape codes on Windows 10+
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    if (GetConsoleMode(hConsole, &mode)) {
        SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif

    printf("CHDK Webcam Bridge v1.0\n");
    printf("Output: %dx%d @ %d FPS, JPEG quality: %d\n\n",
           opts.output_width, opts.output_height, opts.target_fps, opts.jpeg_quality);

    // --- Connect to camera ---
    printf("Connecting to camera...\n");
    ptp::PTPClient client;
    if (!client.connect()) {
        fprintf(stderr, "ERROR: %s\n", client.get_last_error().c_str());
        return 1;
    }

    auto info = client.get_camera_info();
    printf("Connected: %s\n", info.description.c_str());
    printf("CHDK protocol: %d.%d\n\n", info.chdk_major, info.chdk_minor);

    // --- Initialize frame processor ---
    webcam::FrameProcessor processor;
    {
        webcam::ProcessorConfig pconf;
        pconf.output_width = opts.output_width;
        pconf.output_height = opts.output_height;
        pconf.flip_horizontal = opts.flip_h;
        pconf.flip_vertical = opts.flip_v;
        processor.configure(pconf);
    }

    // --- Initialize virtual webcam ---
    webcam::VirtualWebcam vwebcam;
    if (!opts.no_webcam) {
        printf("Creating virtual webcam...\n");
        webcam::VirtualWebcamConfig wconf;
        wconf.width = opts.output_width;
        wconf.height = opts.output_height;
        wconf.fps = opts.target_fps;
        wconf.name = "CHDK Webcam";
        if (!vwebcam.init(wconf)) {
            fprintf(stderr, "WARNING: Virtual webcam init failed: %s\n", vwebcam.get_last_error().c_str());
            fprintf(stderr, "Continuing without virtual webcam output.\n");
        } else {
            printf("Virtual webcam active: \"%s\"\n", wconf.name.c_str());
        }
    }

    // --- Initialize preview window ---
    webcam::PreviewWindow preview;
    if (!opts.no_preview) {
        printf("Opening preview window...\n");
        webcam::PreviewConfig pvc;
        pvc.width = 640;
        pvc.height = 480;
        pvc.title = "CHDK Webcam Preview";
        if (!preview.init(pvc)) {
            fprintf(stderr, "WARNING: Preview window failed to open.\n");
        }
    }

    // --- Start webcam streaming on camera ---
    printf("Starting webcam on camera (quality=%d)...\n", opts.jpeg_quality);
    bool start_ok = client.start_webcam(opts.jpeg_quality);
    if (!start_ok) {
        fprintf(stderr, "WARNING: start_webcam returned false: %s\n", client.get_last_error().c_str());
        fprintf(stderr, "Will try to get frames anyway (module may auto-load).\n");
    }
    printf("\nStreaming. Press Ctrl+C to stop.\n\n");

    // --- Main streaming loop ---
    auto frame_interval = std::chrono::microseconds(1000000 / opts.target_fps);
    auto stats_interval = std::chrono::seconds(2);
    auto last_stats = std::chrono::steady_clock::now();
    int frames_received = 0;
    int frames_dropped = 0;
    int total_bytes = 0;
    uint32_t last_frame_num = 0;

    while (g_running) {
        auto frame_start = std::chrono::steady_clock::now();

        // Get frame from camera
        ptp::MJPEGFrame mjpeg;
        if (!client.get_frame(mjpeg)) {
            frames_dropped++;
            // Brief sleep before retry
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        // Check for duplicate frames
        if (mjpeg.frame_num == last_frame_num && last_frame_num != 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        last_frame_num = mjpeg.frame_num;

        // Decode and upscale
        webcam::RGBFrame rgb;
        if (!processor.process(mjpeg.data.data(), static_cast<int>(mjpeg.data.size()), rgb)) {
            if (opts.verbose) {
                fprintf(stderr, "Decode error: %s\n", processor.get_last_error().c_str());
            }
            frames_dropped++;
            continue;
        }

        // Send to virtual webcam
        if (vwebcam.is_active()) {
            vwebcam.send_frame(rgb.data.data(), rgb.width, rgb.height, rgb.stride);
        }

        // Send to preview window
        if (preview.is_open()) {
            preview.show_frame(rgb.data.data(), rgb.width, rgb.height, rgb.stride);
        }

        frames_received++;
        total_bytes += static_cast<int>(mjpeg.data.size());

        if (opts.verbose) {
            printf("\rFrame %u: %dx%d, %zu bytes, cam=%ux%u  ",
                   mjpeg.frame_num, rgb.width, rgb.height,
                   mjpeg.data.size(), mjpeg.width, mjpeg.height);
            fflush(stdout);
        }

        // Print stats periodically
        auto now = std::chrono::steady_clock::now();
        if (now - last_stats >= stats_interval) {
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_stats).count();
            float fps = (elapsed_ms > 0) ? (frames_received * 1000.0f / elapsed_ms) : 0;
            float kbps = (elapsed_ms > 0) ? (total_bytes * 8.0f / elapsed_ms) : 0;
            printf("\r[Stats] FPS: %.1f | Frames: %d | Dropped: %d | Bitrate: %.0f kbps | Avg frame: %.1f KB    \n",
                   fps, frames_received, frames_dropped, kbps,
                   frames_received > 0 ? (total_bytes / 1024.0f / frames_received) : 0.0f);
            frames_received = 0;
            frames_dropped = 0;
            total_bytes = 0;
            last_stats = now;
        }

        // Pump window messages (also detects window close)
        if (preview.is_open() && !preview.pump_messages()) {
            g_running = false;
        }

        // Frame rate limiting
        auto frame_end = std::chrono::steady_clock::now();
        auto frame_time = frame_end - frame_start;
        if (frame_time < frame_interval) {
            std::this_thread::sleep_for(frame_interval - frame_time);
        }
    }

    // --- Cleanup ---
    printf("\nStopping...\n");
    preview.shutdown();
    client.stop_webcam();
    vwebcam.shutdown();
    client.disconnect();
    printf("Done.\n");

    return 0;
}
