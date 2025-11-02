#pragma once

#include <semantics_av/semantics_av.hpp>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <cstdint>

namespace semantics_av {
namespace constants {

namespace version {
    constexpr const char* CLI_VERSION = "1.0.0";
    
    inline std::string getSDKVersion() {
        return semantics_av::SemanticsAV::getVersion();
    }
    
    inline std::string getFullVersion() {
        return std::string("SemanticsAV CLI v") + CLI_VERSION + " (SDK v" + getSDKVersion() + ")";
    }
}

namespace file_types {
    constexpr std::array<const char*, 2> SUPPORTED = {"pe", "elf"};
    
    inline std::vector<std::string> getSupported() {
        return std::vector<std::string>(SUPPORTED.begin(), SUPPORTED.end());
    }
    
    inline bool isSupported(const std::string& type) {
        return std::find(SUPPORTED.begin(), SUPPORTED.end(), type) != SUPPORTED.end();
    }
}

namespace languages {
    constexpr std::array<const char*, 11> SUPPORTED = {
        "en", "ko", "ja", "zh", "es", "fr", "de", "it", "pt", "ru", "ar"
    };
    
    constexpr const char* DEFAULT = "en";
    
    inline bool isSupported(const std::string& language) {
        return std::find(SUPPORTED.begin(), SUPPORTED.end(), language) != SUPPORTED.end();
    }
}

namespace network {
    constexpr const char* DEFAULT_API_URL = "https://api.semanticsav.ai";
    constexpr const char* DEFAULT_CDN_URL = "https://workers.semanticsav.ai";
    constexpr const char* CONSOLE_URL = "https://console.semanticsav.ai";
    constexpr int DEFAULT_TIMEOUT_SECONDS = 120;
}

namespace system {
    constexpr const char* DAEMON_USER = "semantics-av-daemon";
    constexpr const char* DAEMON_GROUP = "semantics-av-daemon";
    constexpr const char* APPLICATION_NAME = "SemanticsAV";
}

namespace protocol {
    constexpr uint32_t MAGIC_NUMBER = 0x53415643;
}

namespace limits {
    constexpr int DEFAULT_MAX_FILE_SIZE_MB = 650;
    constexpr int DEFAULT_SCAN_THREADS = 4;
    constexpr int DEFAULT_MAX_RECURSION_DEPTH = 50;
    constexpr int DEFAULT_SCAN_TIMEOUT_SECONDS = 30;
    constexpr int DEFAULT_NETWORK_TIMEOUT_SECONDS = 120;
    constexpr int DEFAULT_UPDATE_INTERVAL_MINUTES = 60;
    constexpr size_t DEFAULT_SCAN_BATCH_SIZE = 250;
    
    constexpr const char* DEFAULT_HTTP_HOST = "127.0.0.1";
    constexpr uint16_t DEFAULT_HTTP_PORT = 9216;
    
    constexpr int DEFAULT_DAEMON_MAX_CONNECTIONS_SYSTEM = 100;
    constexpr int DEFAULT_DAEMON_MAX_CONNECTIONS_USER = 50;
    constexpr int DEFAULT_DAEMON_MAX_QUEUE_SYSTEM = 200;
    constexpr int DEFAULT_DAEMON_MAX_QUEUE_USER = 100;
    constexpr int DEFAULT_DAEMON_READ_TIMEOUT = 120;
    constexpr size_t DEFAULT_DAEMON_SOCKET_BUFFER_KB = 1024;
    constexpr int DEFAULT_DAEMON_CONNECTION_BACKLOG = 128;
    
    constexpr size_t DEFAULT_LOG_ROTATION_SIZE_MB = 100;
    constexpr size_t DEFAULT_LOG_MAX_FILES = 5;
}

}
}