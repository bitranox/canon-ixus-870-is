#include "ptp_client.h"
#include <libusb.h>
#include <cstring>
#include <chrono>
#include <thread>

namespace ptp {

// USB transfer timeout in milliseconds
constexpr int USB_TIMEOUT = 2000;

// PTP packet header sizes
constexpr int PTP_HEADER_SIZE = 12;
constexpr int PTP_MAX_PARAMS = 5;

struct PTPClient::Impl {
    libusb_context* ctx = nullptr;
    libusb_device_handle* handle = nullptr;
    uint8_t ep_in = 0;
    uint8_t ep_out = 0;
    uint8_t ep_int = 0;
    uint32_t transaction_id = 0;
    bool connected = false;
    std::string last_error;
    CameraInfo camera_info{};

    // PTP session
    uint32_t session_id = 1;

    bool init_libusb() {
        int r = libusb_init(&ctx);
        if (r < 0) {
            last_error = "Failed to initialize libusb: " + std::string(libusb_strerror(static_cast<libusb_error>(r)));
            return false;
        }
        return true;
    }

    void cleanup_libusb() {
        if (handle) {
            libusb_release_interface(handle, 0);
            libusb_close(handle);
            handle = nullptr;
        }
        if (ctx) {
            libusb_exit(ctx);
            ctx = nullptr;
        }
        connected = false;
    }

    bool find_canon_camera() {
        libusb_device** devs;
        ssize_t cnt = libusb_get_device_list(ctx, &devs);
        if (cnt < 0) {
            last_error = "Failed to get USB device list";
            return false;
        }

        bool found = false;
        for (ssize_t i = 0; i < cnt; i++) {
            libusb_device_descriptor desc;
            if (libusb_get_device_descriptor(devs[i], &desc) < 0) continue;

            if (desc.idVendor == CANON_VID) {
                int r = libusb_open(devs[i], &handle);
                if (r < 0) {
                    continue;
                }

                camera_info.vendor_id = desc.idVendor;
                camera_info.product_id = desc.idProduct;

                // Find PTP endpoints
                libusb_config_descriptor* config;
                if (libusb_get_active_config_descriptor(devs[i], &config) == 0) {
                    for (int j = 0; j < config->bNumInterfaces; j++) {
                        const libusb_interface& iface = config->interface[j];
                        for (int k = 0; k < iface.num_altsetting; k++) {
                            const libusb_interface_descriptor& alt = iface.altsetting[k];
                            // PTP class: 6 (Image), subclass: 1, protocol: 1
                            if (alt.bInterfaceClass == 6 || alt.bInterfaceClass == 0xFF) {
                                for (int e = 0; e < alt.bNumEndpoints; e++) {
                                    const libusb_endpoint_descriptor& ep = alt.endpoint[e];
                                    if ((ep.bmAttributes & 0x03) == LIBUSB_TRANSFER_TYPE_BULK) {
                                        if (ep.bEndpointAddress & LIBUSB_ENDPOINT_IN) {
                                            ep_in = ep.bEndpointAddress;
                                        } else {
                                            ep_out = ep.bEndpointAddress;
                                        }
                                    } else if ((ep.bmAttributes & 0x03) == LIBUSB_TRANSFER_TYPE_INTERRUPT) {
                                        ep_int = ep.bEndpointAddress;
                                    }
                                }
                            }
                        }
                    }
                    libusb_free_config_descriptor(config);
                }

                if (ep_in && ep_out) {
                    found = true;
                    break;
                }

                // Didn't find endpoints, close and try next device
                libusb_close(handle);
                handle = nullptr;
                ep_in = ep_out = ep_int = 0;
            }
        }

        libusb_free_device_list(devs, 1);

        if (!found) {
            last_error = "No Canon camera found. Ensure camera is connected and libusb-win32 driver is installed (use Zadig).";
        }
        return found;
    }

    bool claim_interface() {
        // Detach kernel driver if attached (Linux)
#ifdef LIBUSB_HAS_DETACH_KERNEL_DRIVER
        if (libusb_kernel_driver_active(handle, 0) == 1) {
            libusb_detach_kernel_driver(handle, 0);
        }
#endif
        int r = libusb_claim_interface(handle, 0);
        if (r < 0) {
            last_error = "Failed to claim USB interface: " + std::string(libusb_strerror(static_cast<libusb_error>(r)));
            return false;
        }
        return true;
    }

    // Send a PTP command (no data phase)
    bool send_command(uint16_t opcode, const uint32_t* params, int num_params) {
        uint8_t buf[PTP_HEADER_SIZE + PTP_MAX_PARAMS * 4];
        int len = PTP_HEADER_SIZE + num_params * 4;

        transaction_id++;

        // Build PTP container
        memcpy(buf + 0, &len, 4);              // Length
        uint16_t type = PTP_TYPE_COMMAND;
        memcpy(buf + 4, &type, 2);             // Type = Command
        memcpy(buf + 6, &opcode, 2);           // Operation Code
        memcpy(buf + 8, &transaction_id, 4);   // Transaction ID

        for (int i = 0; i < num_params; i++) {
            memcpy(buf + PTP_HEADER_SIZE + i * 4, &params[i], 4);
        }

        int transferred = 0;
        int r = libusb_bulk_transfer(handle, ep_out, buf, len, &transferred, USB_TIMEOUT);
        if (r < 0) {
            last_error = "USB send error: " + std::string(libusb_strerror(static_cast<libusb_error>(r)));
            return false;
        }
        return true;
    }

    // Receive PTP response (command response + optional data)
    bool receive_response(PTPContainer& resp, std::vector<uint8_t>* data = nullptr, int timeout_ms = USB_TIMEOUT) {
        // Buffer for receiving - large enough for data + headers
        constexpr int MAX_BUF = 512 * 1024; // 512 KB max per transfer
        std::vector<uint8_t> buf(MAX_BUF);
        int transferred = 0;

        // First read: may contain data or response
        int r = libusb_bulk_transfer(handle, ep_in, buf.data(), MAX_BUF, &transferred, timeout_ms);
        if (r < 0) {
            last_error = "USB receive error: " + std::string(libusb_strerror(static_cast<libusb_error>(r)));
            return false;
        }

        if (transferred < PTP_HEADER_SIZE) {
            last_error = "Short PTP response";
            return false;
        }

        // Parse header
        uint32_t pkt_len;
        uint16_t pkt_type, pkt_code;
        uint32_t pkt_tid;
        memcpy(&pkt_len, buf.data() + 0, 4);
        memcpy(&pkt_type, buf.data() + 4, 2);
        memcpy(&pkt_code, buf.data() + 6, 2);
        memcpy(&pkt_tid, buf.data() + 8, 4);

        if (pkt_type == PTP_TYPE_DATA) {
            // This is a data phase - collect or drain all data
            uint32_t data_total = pkt_len - PTP_HEADER_SIZE;
            int data_in_first = transferred - PTP_HEADER_SIZE;
            if (data) {
                data->resize(data_total);
                if (data_in_first > 0 && data_in_first <= static_cast<int>(data_total)) {
                    memcpy(data->data(), buf.data() + PTP_HEADER_SIZE, data_in_first);
                }
            }

            // Read remaining data if needed (or drain it if data is NULL)
            uint32_t total_read = (data_in_first > 0) ? static_cast<uint32_t>(data_in_first) : 0;
            while (total_read < data_total) {
                r = libusb_bulk_transfer(handle, ep_in, buf.data(), MAX_BUF, &transferred, timeout_ms);
                if (r < 0) {
                    last_error = "USB data receive error";
                    return false;
                }
                uint32_t to_copy = std::min(static_cast<uint32_t>(transferred), data_total - total_read);
                if (data) {
                    memcpy(data->data() + total_read, buf.data(), to_copy);
                }
                total_read += to_copy;
            }

            // Now read the actual response
            r = libusb_bulk_transfer(handle, ep_in, buf.data(), MAX_BUF, &transferred, timeout_ms);
            if (r < 0) {
                last_error = "USB response receive error";
                return false;
            }
            if (transferred < PTP_HEADER_SIZE) {
                last_error = "Short PTP response after data";
                return false;
            }
            memcpy(&pkt_len, buf.data() + 0, 4);
            memcpy(&pkt_type, buf.data() + 4, 2);
            memcpy(&pkt_code, buf.data() + 6, 2);
            memcpy(&pkt_tid, buf.data() + 8, 4);
        }

        if (pkt_type != PTP_TYPE_RESPONSE) {
            last_error = "Unexpected PTP packet type: " + std::to_string(pkt_type);
            return false;
        }

        resp.length = pkt_len;
        resp.type = pkt_type;
        resp.code = pkt_code;
        resp.transaction_id = pkt_tid;
        resp.num_params = (pkt_len - PTP_HEADER_SIZE) / 4;

        for (int i = 0; i < resp.num_params && i < PTP_MAX_PARAMS; i++) {
            memcpy(&resp.params[i], buf.data() + PTP_HEADER_SIZE + i * 4, 4);
        }

        return true;
    }

    // Open PTP session
    bool open_session() {
        uint32_t params[1] = { session_id };
        // OpenSession opcode = 0x1002
        uint16_t opcode = 0x1002;

        uint8_t buf[PTP_HEADER_SIZE + 4];
        int len = PTP_HEADER_SIZE + 4;
        transaction_id = 0; // Reset for new session

        transaction_id++;
        memcpy(buf + 0, &len, 4);
        uint16_t type = PTP_TYPE_COMMAND;
        memcpy(buf + 4, &type, 2);
        memcpy(buf + 6, &opcode, 2);
        memcpy(buf + 8, &transaction_id, 4);
        memcpy(buf + PTP_HEADER_SIZE, &params[0], 4);

        int transferred = 0;
        int r = libusb_bulk_transfer(handle, ep_out, buf, len, &transferred, USB_TIMEOUT);
        if (r < 0) {
            last_error = "Failed to open PTP session";
            return false;
        }

        // Read response
        PTPContainer resp{};
        if (!receive_response(resp)) return false;
        if (resp.code != PTP_RC_OK) {
            // Session may already be open
            if (resp.code != 0x201E) { // SessionAlreadyOpen
                last_error = "OpenSession failed: 0x" + std::to_string(resp.code);
                return false;
            }
        }
        return true;
    }

    // Send CHDK command with params, receive response + optional data
    bool chdk_command(ChdkCommand cmd, uint32_t p2, uint32_t p3, uint32_t p4,
                      PTPContainer& resp, std::vector<uint8_t>* data = nullptr,
                      int timeout_ms = USB_TIMEOUT) {
        uint32_t params[5] = { static_cast<uint32_t>(cmd), p2, p3, p4, 0 };
        if (!send_command(PTP_OC_CHDK, params, 4)) return false;
        if (!receive_response(resp, data, timeout_ms)) return false;
        return true;
    }
};

PTPClient::PTPClient() : impl_(std::make_unique<Impl>()) {}

PTPClient::~PTPClient() {
    disconnect();
}

bool PTPClient::connect() {
    if (!impl_->init_libusb()) return false;
    if (!impl_->find_canon_camera()) {
        impl_->cleanup_libusb();
        return false;
    }
    if (!impl_->claim_interface()) {
        impl_->cleanup_libusb();
        return false;
    }
    if (!impl_->open_session()) {
        impl_->cleanup_libusb();
        return false;
    }

    impl_->connected = true;
    impl_->camera_info.description = "Canon Camera (PID: 0x" +
        ([](uint16_t v) {
            char buf[8];
            snprintf(buf, sizeof(buf), "%04X", v);
            return std::string(buf);
        })(impl_->camera_info.product_id) + ")";

    // Get CHDK version
    get_chdk_version(impl_->camera_info.chdk_major, impl_->camera_info.chdk_minor);

    return true;
}

void PTPClient::disconnect() {
    if (impl_->connected) {
        // Try to close session gracefully
        uint16_t opcode = 0x1003; // CloseSession
        impl_->send_command(opcode, nullptr, 0);
        PTPContainer resp{};
        impl_->receive_response(resp);
    }
    impl_->cleanup_libusb();
}

bool PTPClient::is_connected() const {
    return impl_->connected;
}

CameraInfo PTPClient::get_camera_info() const {
    return impl_->camera_info;
}

bool PTPClient::get_chdk_version(int& major, int& minor) {
    PTPContainer resp{};
    if (!impl_->chdk_command(CHDK_Version, 0, 0, 0, resp)) {
        return false;
    }
    if (resp.code != PTP_RC_OK || resp.num_params < 2) {
        return false;
    }
    major = resp.params[0];
    minor = resp.params[1];
    return true;
}

bool PTPClient::start_webcam(int quality) {
    PTPContainer resp{};
    std::vector<uint8_t> dummy;

    // Start command triggers module load + mode switch on camera, which can take ~5s
    if (!impl_->chdk_command(CHDK_GetMJPEGFrame, quality, WEBCAM_START, 0, resp, &dummy, 10000)) {
        return false;
    }

    // If start failed (0xDEAD marker), report error string from camera
    if (resp.num_params >= 3 && resp.params[2] == 0xDEAD) {
        if (!dummy.empty() && dummy[0] != 0) {
            std::string err_msg(dummy.begin(), dummy.end());
            impl_->last_error = "Camera module error: " + err_msg;
        } else {
            impl_->last_error = "Camera start failed (rc=" + std::to_string(static_cast<int>(resp.params[1])) + ")";
        }
    }

    return (resp.code == PTP_RC_OK);
}

bool PTPClient::stop_webcam() {
    PTPContainer resp{};
    std::vector<uint8_t> dummy;
    if (!impl_->chdk_command(CHDK_GetMJPEGFrame, 0, WEBCAM_STOP, 0, resp, &dummy)) {
        return false;
    }
    return (resp.code == PTP_RC_OK);
}

bool PTPClient::get_frame(MJPEGFrame& frame) {
    PTPContainer resp{};
    std::vector<uint8_t> data;

    if (!impl_->chdk_command(CHDK_GetMJPEGFrame, 0, 0, 0, resp, &data)) {
        return false;
    }

    if (resp.code != PTP_RC_OK) {
        return false;
    }

    if (resp.num_params < 1 || resp.params[0] == 0) {
        return false;
    }

    frame.data = std::move(data);
    frame.width = (resp.num_params >= 2) ? resp.params[1] : 0;
    frame.height = (resp.num_params >= 3) ? resp.params[2] : 0;
    frame.frame_num = (resp.num_params >= 4) ? resp.params[3] : 0;

    return !frame.data.empty();
}

bool PTPClient::execute_script(const std::string& script) {
    // Send script data
    uint32_t params[5] = { CHDK_ExecuteScript, 0, 0, 0, 0 }; // param2=0 for Lua

    // Build data packet
    std::vector<uint8_t> pkt;
    int data_len = PTP_HEADER_SIZE + static_cast<int>(script.size());
    pkt.resize(data_len);

    memcpy(pkt.data() + 0, &data_len, 4);
    uint16_t type = PTP_TYPE_DATA;
    memcpy(pkt.data() + 4, &type, 2);
    uint16_t opcode = PTP_OC_CHDK;
    memcpy(pkt.data() + 6, &opcode, 2);
    uint32_t tid = impl_->transaction_id + 1;
    memcpy(pkt.data() + 8, &tid, 4);
    memcpy(pkt.data() + PTP_HEADER_SIZE, script.data(), script.size());

    // Send command first
    if (!impl_->send_command(PTP_OC_CHDK, params, 2)) return false;

    // Send data
    int transferred = 0;
    int r = libusb_bulk_transfer(impl_->handle, impl_->ep_out,
                                  pkt.data(), data_len, &transferred, USB_TIMEOUT);
    if (r < 0) return false;

    // Get response
    PTPContainer resp{};
    return impl_->receive_response(resp) && resp.code == PTP_RC_OK;
}

std::string PTPClient::get_last_error() const {
    return impl_->last_error;
}

} // namespace ptp
