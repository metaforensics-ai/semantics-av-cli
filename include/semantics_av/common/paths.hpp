#pragma once

#include <string>
#include <optional>

namespace semantics_av {
namespace common {

enum class InstallMode {
    SYSTEM,
    USER,
    PORTABLE
};

class PathManager {
public:
    static PathManager& instance();
    
    InstallMode detectMode();
    
    std::string getConfigDir() const;
    std::string getDataDir() const;
    std::string getCacheDir() const;
    std::string getLogDir() const;
    std::string getRuntimeDir() const;
    
    std::string getConfigFile() const;
    std::string getSocketPath() const;
    std::string getUserCredentialsFile() const;
    std::string getSystemSecretsFile() const;
    std::string getUserConfigFile() const;
    
    bool isSystemMode() const { return mode_ == InstallMode::SYSTEM; }
    bool isUserMode() const { return mode_ == InstallMode::USER; }
    
private:
    PathManager();
    InstallMode mode_;
    
    std::string getXdgConfigHome() const;
    std::string getXdgDataHome() const;
    std::string getXdgCacheHome() const;
    std::string getXdgStateHome() const;
    std::string getXdgRuntimeDir() const;
};

}}