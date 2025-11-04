#include "semantics_av/common/paths.hpp"
#include "semantics_av/common/logger.hpp"
#include <unistd.h>
#include <filesystem>
#include <cstdlib>
#include <cstring>

namespace semantics_av {
namespace common {

PathManager& PathManager::instance() {
    static PathManager instance;
    return instance;
}

PathManager::PathManager() {
    mode_ = detectMode();
}

InstallMode PathManager::detectMode() {
    std::error_code ec;
    std::string exe_path = std::filesystem::read_symlink("/proc/self/exe", ec).parent_path();
    
    if (ec) {
        auto detected = getuid() == 0 ? InstallMode::SYSTEM : InstallMode::USER;
        Logger::instance().debug("[Paths] Mode detected by uid | mode={}", 
                                detected == InstallMode::SYSTEM ? "SYSTEM" : "USER");
        return detected;
    }
    
    InstallMode detected;
    if (exe_path.find("/usr/") == 0 || exe_path.find("/opt/") == 0) {
        detected = InstallMode::SYSTEM;
    } else {
        const char* home = std::getenv("HOME");
        if (home && exe_path.find(std::string(home)) == 0) {
            detected = InstallMode::USER;
        } else {
            detected = InstallMode::PORTABLE;
        }
    }
    
    Logger::instance().info("[Paths] Mode detected | mode={} | exe_path={}", 
                           detected == InstallMode::SYSTEM ? "SYSTEM" : 
                           detected == InstallMode::USER ? "USER" : "PORTABLE",
                           exe_path);
    
    return detected;
}

std::vector<std::string> PathManager::getConfigSearchPaths() const {
    std::vector<std::string> paths;
    
    if (const char* env = std::getenv("SEMANTICS_AV_CONFIG")) {
        paths.push_back(env);
    }
    
    paths.push_back(getConfigFile());
    
    return paths;
}

std::string PathManager::getConfigDir() const {
    switch (mode_) {
        case InstallMode::SYSTEM:
            return "/etc/semantics-av";
        case InstallMode::USER:
            return getXdgConfigHome() + "/semantics-av";
        case InstallMode::PORTABLE:
            return "./config";
    }
    return "";
}

std::string PathManager::getDataDir() const {
    switch (mode_) {
        case InstallMode::SYSTEM:
            return "/var/lib/semantics-av";
        case InstallMode::USER:
            return getXdgDataHome() + "/semantics-av";
        case InstallMode::PORTABLE:
            return "./data";
    }
    return "";
}

std::string PathManager::getCacheDir() const {
    switch (mode_) {
        case InstallMode::SYSTEM:
            return "/var/cache/semantics-av";
        case InstallMode::USER:
            return getXdgCacheHome() + "/semantics-av";
        case InstallMode::PORTABLE:
            return "./cache";
    }
    return "";
}

std::string PathManager::getLogDir() const {
    switch (mode_) {
        case InstallMode::SYSTEM:
            return "/var/log/semantics-av";
        case InstallMode::USER:
            return getXdgStateHome() + "/semantics-av";
        case InstallMode::PORTABLE:
            return "./logs";
    }
    return "";
}

std::string PathManager::getRuntimeDir() const {
    switch (mode_) {
        case InstallMode::SYSTEM:
            return "/var/run/semantics-av";
        case InstallMode::USER: {
            std::string runtime_dir = getXdgRuntimeDir();
            if (!runtime_dir.empty()) {
                return runtime_dir + "/semantics-av";
            }
            return getXdgStateHome() + "/semantics-av/run";
        }
        case InstallMode::PORTABLE:
            return "./run";
    }
    return "";
}

std::string PathManager::getConfigFile() const {
    return getConfigDir() + "/semantics-av.conf";
}

std::string PathManager::getSocketPath() const {
    return getRuntimeDir() + "/semantics-av.sock";
}

std::string PathManager::getUserCredentialsFile() const {
    if (mode_ == InstallMode::SYSTEM) {
        return "";
    }
    return getConfigDir() + "/credentials";
}

std::string PathManager::getSystemSecretsFile() const {
    if (mode_ != InstallMode::SYSTEM) {
        return "";
    }
    return "/etc/semantics-av/secrets.conf";
}

std::string PathManager::getXdgConfigHome() const {
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    if (xdg && strlen(xdg) > 0) {
        return xdg;
    }
    const char* home = std::getenv("HOME");
    return home ? std::string(home) + "/.config" : "";
}

std::string PathManager::getXdgDataHome() const {
    const char* xdg = std::getenv("XDG_DATA_HOME");
    if (xdg && strlen(xdg) > 0) {
        return xdg;
    }
    const char* home = std::getenv("HOME");
    return home ? std::string(home) + "/.local/share" : "";
}

std::string PathManager::getXdgCacheHome() const {
    const char* xdg = std::getenv("XDG_CACHE_HOME");
    if (xdg && strlen(xdg) > 0) {
        return xdg;
    }
    const char* home = std::getenv("HOME");
    return home ? std::string(home) + "/.cache" : "";
}

std::string PathManager::getXdgStateHome() const {
    const char* xdg = std::getenv("XDG_STATE_HOME");
    if (xdg && strlen(xdg) > 0) {
        return xdg;
    }
    const char* home = std::getenv("HOME");
    return home ? std::string(home) + "/.local/state" : "";
}

std::string PathManager::getXdgRuntimeDir() const {
    const char* xdg = std::getenv("XDG_RUNTIME_DIR");
    return xdg ? xdg : "";
}

}}