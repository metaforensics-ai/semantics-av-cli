#pragma once

#include "error_framework.hpp"
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <optional>

namespace semantics_av {

namespace core {
enum class CoreErrorCode;
}

namespace common {

enum class ScanResult {
    CLEAN,
    MALICIOUS,
    UNSUPPORTED,
    ERROR
};

enum class SecurityLevel {
    ROOT,
    PRIVILEGED,
    USER,
    RESTRICTED
};

struct ScanMetadata {
    std::string file_path;
    size_t file_size = 0;
    std::string file_type;
    float confidence = 0.0f;
    ScanResult result = ScanResult::ERROR;
    std::chrono::milliseconds scan_time{0};
    std::optional<std::string> error_message;
    std::optional<std::map<std::string, std::string>> file_hashes;
    std::optional<core::CoreErrorCode> error_code;
    std::optional<ErrorContext> error_context;
};

struct ModelInfo {
    std::string type;
    std::string version;
    std::string etag;
    size_t size = 0;
    std::chrono::system_clock::time_point last_updated;
    std::chrono::system_clock::time_point server_created_at;
};

struct ConnectionInfo {
    std::string remote_address;
    uint16_t remote_port = 0;
    std::chrono::system_clock::time_point connected_at;
    size_t requests_processed = 0;
};

std::string to_string(ScanResult result);
std::string to_string(SecurityLevel level);

}}