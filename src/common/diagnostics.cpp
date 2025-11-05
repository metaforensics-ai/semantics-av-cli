#include "semantics_av/common/diagnostics.hpp"
#include "semantics_av/common/constants.hpp"
#include "semantics_av/common/paths.hpp"
#include <filesystem>
#include <iostream>
#include <unistd.h>

namespace semantics_av {
namespace diagnostics {

bool hasModelFiles(const std::string& models_path) {
    if (!std::filesystem::exists(models_path)) {
        return false;
    }
    
    for (const auto& type : constants::file_types::SUPPORTED) {
        std::string model_file = models_path + "/" + std::string(type) + ".sav";
        if (std::filesystem::exists(model_file)) {
            return true;
        }
    }
    
    return false;
}

bool canAccessApiKey() {
    auto& path_manager = ::semantics_av::common::PathManager::instance();
    
    if (path_manager.isSystemMode()) {
        std::string secrets = path_manager.getSystemSecretsFile();
        if (secrets.empty()) {
            return false;
        }
        return access(secrets.c_str(), R_OK) == 0;
    } else {
        std::string credentials = path_manager.getUserCredentialsFile();
        if (credentials.empty()) {
            return false;
        }
        return access(credentials.c_str(), R_OK) == 0;
    }
}

void printUpdateGuide(bool is_system_mode, const std::string& models_path) {
    std::cerr << "\n\033[31mError: Model files not found\033[0m\n\n";
    std::cerr << "Models directory: " << models_path << "\n";
    std::cerr << "No detection models are available.\n\n";
    std::cerr << "\033[1mOptions:\033[0m\n\n";
    
    if (is_system_mode) {
        std::cerr << "  \033[1m1. Start daemon (recommended):\033[0m\n";
        std::cerr << "     sudo systemctl start semantics-av\n";
        std::cerr << "     semantics-av update\n\n";
        std::cerr << "  \033[1m2. Run with sudo:\033[0m\n";
        std::cerr << "     sudo semantics-av update\n\n";
    } else {
        std::cerr << "  \033[1m1. Start daemon (recommended):\033[0m\n";
        std::cerr << "     systemctl --user start semantics-av\n";
        std::cerr << "     semantics-av update\n\n";
        std::cerr << "  \033[1m2. Run directly:\033[0m\n";
        std::cerr << "     semantics-av update\n\n";
    }
    
    std::cerr << "Models will be downloaded automatically.\n";
}

void printApiKeyGuide(bool is_system_mode) {
    std::cerr << "\n\033[31mError: Cannot access API key\033[0m\n\n";
    
    if (is_system_mode) {
        std::cerr << "The API key is stored in a protected system file.\n\n";
        std::cerr << "\033[1mOptions:\033[0m\n\n";
        std::cerr << "  \033[1m1. Start daemon (recommended):\033[0m\n";
        std::cerr << "     sudo systemctl start semantics-av\n";
        std::cerr << "     semantics-av analyze [file]\n\n";
        std::cerr << "  \033[1m2. Run with sudo:\033[0m\n";
        std::cerr << "     sudo semantics-av analyze [file]\n\n";
        std::cerr << "  Daemon handles permissions automatically.\n";
    } else {
        std::cerr << "The credentials file is not accessible.\n";
        std::cerr << "File: " << ::semantics_av::common::PathManager::instance().getUserCredentialsFile() << "\n\n";
        std::cerr << "Configure API key:\n";
        std::cerr << "  semantics-av config set api_key \"YOUR_KEY\"\n\n";
        std::cerr << "Get API key: " << constants::network::CONSOLE_URL << "\n";
    }
}

void printPermissionGuide(const std::string& resource, 
                          const std::string& command,
                          bool is_system_mode) {
    std::cerr << "\n\033[31mError: Permission denied\033[0m\n\n";
    std::cerr << "Resource: " << resource << "\n\n";
    
    if (is_system_mode) {
        std::cerr << "\033[1mSystem-wide resources require root privileges.\033[0m\n\n";
        std::cerr << "Run with sudo:\n";
        std::cerr << "  \033[32msudo " << command << "\033[0m\n";
    } else {
        std::cerr << "Cannot write to this location.\n";
        std::cerr << "Check permissions: ls -ld " << resource << "\n";
    }
}

}}