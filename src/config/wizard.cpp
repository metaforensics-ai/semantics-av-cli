#include "semantics_av/config/wizard.hpp"
#include "semantics_av/common/constants.hpp"
#include "semantics_av/common/paths.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/security.hpp"
#include "semantics_av/config/validator.hpp"
#include "semantics_av/daemon/client.hpp"
#include "semantics_av/daemon/server.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <limits>
#include <filesystem>
#include <pwd.h>
#include <fstream>
#include <sys/stat.h>
#include <thread>
#include <chrono>

namespace semantics_av {
namespace config {

ConfigWizard::ConfigWizard() {
    auto& path_manager = common::PathManager::instance();
    
    if (path_manager.isSystemMode()) {
        install_mode_str_ = "SYSTEM";
    } else if (path_manager.isUserMode()) {
        install_mode_str_ = "USER";
    } else {
        install_mode_str_ = "PORTABLE";
    }
    
    initializeDefaults();
}

void ConfigWizard::initializeDefaults() {
    config_ = common::Config::createDefaultConfig();
    
    auto& path_manager = common::PathManager::instance();
    
    config_.base_path = path_manager.getDataDir();
    config_.models_path = config_.base_path + "/models";
    config_.daemon.socket_path = path_manager.getSocketPath();
    
    if (path_manager.isSystemMode()) {
        config_.log_file = "/var/log/semantics-av/semantics-av.log";
        config_.daemon.user = constants::system::DAEMON_USER;
        config_.daemon.group = constants::system::DAEMON_GROUP;
        config_.daemon.max_connections = constants::config_defaults::DAEMON_MAX_CONNECTIONS_SYSTEM;
        config_.daemon.max_queue = constants::config_defaults::DAEMON_MAX_QUEUE_SYSTEM;
    } else {
        config_.log_file = path_manager.getLogDir() + "/semantics-av.log";
        config_.daemon.user = "";
        config_.daemon.group = "";
        config_.daemon.max_connections = constants::config_defaults::DAEMON_MAX_CONNECTIONS_USER;
        config_.daemon.max_queue = constants::config_defaults::DAEMON_MAX_QUEUE_USER;
    }
}

void ConfigWizard::loadExistingConfig() {
    auto& existing_config = common::Config::instance().global();
    
    config_.base_path = existing_config.base_path;
    config_.models_path = existing_config.models_path;
    config_.log_file = existing_config.log_file;
    config_.log_level = existing_config.log_level;
    config_.api_key = existing_config.api_key;
    config_.network_timeout = existing_config.network_timeout;
    config_.auto_update = existing_config.auto_update;
    config_.update_interval_minutes = existing_config.update_interval_minutes;
    config_.max_scan_size_mb = existing_config.max_scan_size_mb;
    config_.scan_timeout_seconds = existing_config.scan_timeout_seconds;
    config_.max_recursion_depth = existing_config.max_recursion_depth;
    config_.daemon = existing_config.daemon;
    config_.scan = existing_config.scan;
    config_.logging = existing_config.logging;
    
    common::Logger::instance().debug("[Config] Loaded existing | mode={}", install_mode_str_);
}

bool ConfigWizard::validateRequiredDirectories() {
    auto& path_manager = common::PathManager::instance();
    
    if (path_manager.isSystemMode()) {
        struct passwd* pw = getpwnam(constants::system::DAEMON_USER);
        if (!pw) {
            common::Logger::instance().error("[Config] User not found | user={}", 
                                            constants::system::DAEMON_USER);
            
            std::cerr << "\n\033[31mError: System user not created\033[0m\n\n";
            std::cerr << "User '" << constants::system::DAEMON_USER << "' does not exist.\n\n";
            std::cerr << "\033[1mSetup required:\033[0m\n";
            std::cerr << "  sudo /usr/local/share/semantics-av/post_install.sh\n\n";
            
            return false;
        }
        
        std::string config_dir = path_manager.getConfigDir();
        if (!std::filesystem::exists(config_dir)) {
            std::filesystem::create_directories(config_dir);
        }
    } else {
        std::string config_dir = path_manager.getConfigDir();
        if (!std::filesystem::exists(config_dir)) {
            std::filesystem::create_directories(config_dir);
        }
    }
    
    return true;
}

bool ConfigWizard::saveUserCredentials(const std::string& api_key) {
    auto& path_manager = common::PathManager::instance();
    std::string credentials_path = path_manager.getUserCredentialsFile();
    
    if (credentials_path.empty()) {
        return false;
    }
    
    std::filesystem::path cred_dir = std::filesystem::path(credentials_path).parent_path();
    if (!std::filesystem::exists(cred_dir)) {
        std::filesystem::create_directories(cred_dir);
    }
    
    std::ofstream file(credentials_path);
    if (!file) {
        return false;
    }
    
    file << "api_key=\"" << api_key << "\"\n";
    file.close();
    
    chmod(credentials_path.c_str(), 0600);
    
    return true;
}

bool ConfigWizard::saveSystemSecrets(const std::string& api_key) {
    auto& path_manager = common::PathManager::instance();
    std::string secrets_path = path_manager.getSystemSecretsFile();
    
    if (secrets_path.empty()) {
        return false;
    }
    
    std::ofstream file(secrets_path);
    if (!file) {
        return false;
    }
    
    file << "[global]\n";
    file << "api_key = \"" << api_key << "\"\n";
    file.close();
    
    chmod(secrets_path.c_str(), 0640);
    
    struct passwd* pw = getpwnam(constants::system::DAEMON_USER);
    if (pw) {
        if (chown(secrets_path.c_str(), 0, pw->pw_gid) != 0) {
            common::Logger::instance().warn("[Config] Failed to set ownership | path={}", secrets_path);
        }
    }
    
    return true;
}

int ConfigWizard::run(bool use_defaults) {
    auto& path_manager = common::PathManager::instance();
    std::string config_path = path_manager.getConfigFile();
    
    common::Logger::instance().info("[Config] Wizard started | mode={} | defaults={}", 
                                    install_mode_str_, use_defaults);
    
    bool is_system_mode = path_manager.isSystemMode();
    bool is_root = (getuid() == 0);
    
    if (is_system_mode && !is_root) {
        std::cerr << "\n\033[31mPermission denied\033[0m\n\n";
        std::cerr << "System-wide configuration requires root privileges.\n\n";
        std::cerr << "Run: \033[32msudo semantics-av config init";
        if (use_defaults) std::cerr << " --defaults";
        std::cerr << "\033[0m\n\n";
        return 1;
    }
    
    if (!is_system_mode && is_root) {
        std::cerr << "\n\033[33mWarning: Running as root in user mode\033[0m\n\n";
        std::cerr << "This will create configuration files owned by root.\n";
        std::cerr << "You may encounter permission issues later.\n\n";
        std::cerr << "\033[1mRecommended:\033[0m Run without sudo:\n";
        std::cerr << "  semantics-av config init";
        if (use_defaults) std::cerr << " --defaults";
        std::cerr << "\n\n";
        
        if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
            std::cout << "Continue anyway? [y/N]: ";
            std::string response;
            std::getline(std::cin, response);
            if (response.empty() || (response[0] != 'y' && response[0] != 'Y')) {
                std::cout << "Cancelled.\n";
                return 1;
            }
        } else {
            std::cerr << "Non-interactive mode - aborting.\n";
            return 1;
        }
    }
    
    std::string config_dir = std::filesystem::path(config_path).parent_path();
    if (!common::PrivilegeManager::canSafelyWriteConfig(config_dir)) {
        std::cerr << "\n\033[31mCannot write to configuration directory\033[0m\n";
        std::cerr << "Directory: " << config_dir << "\n\n";
        return 1;
    }
    
    if (!validateRequiredDirectories()) {
        return 1;
    }
    
    if (use_defaults) {
        std::cout << "\n\033[1m" << constants::system::APPLICATION_NAME << " Quick Setup (Non-Interactive)\033[0m\n";
        std::cout << "Installation Mode: " << install_mode_str_ << "\n";
        std::cout << "Config Location: " << config_path << "\n\n";
        std::cout << "Using default settings for optimal performance.\n";
        std::cout << "API key can be configured later:\n";
        std::cout << "  semantics-av config set api_key \"YOUR_KEY\"\n";
        std::cout << "\nObtain a key from: " << constants::network::CONSOLE_URL << "\n\n";
        
        common::Config::instance().global() = config_;
        if (common::Config::instance().save()) {
            std::cout << "\033[32m✓ Configuration created successfully\033[0m\n";
            std::cout << "Location: " << config_path << "\n";
            
            triggerDaemonReloadIfRunning();
            return 0;
        }
        std::cerr << "\n\033[31mFailed to save configuration.\033[0m\n";
        return 1;
    }
    
    if (common::Config::instance().exists()) {
        loadExistingConfig();
    }
    
    printHeader();
    
    std::cout << "\n\033[1mConfiguration Mode\033[0m\n";
    std::cout << "1) Quick setup (recommended)\n";
    std::cout << "2) Advanced configuration\n";
    std::cout << "Choice [1]: ";
    
    std::string mode_choice;
    std::getline(std::cin, mode_choice);
    bool advanced_mode = (!mode_choice.empty() && mode_choice[0] == '2');
    
    std::cout << "\n\033[1mAPI Key Configuration\033[0m\n";
    std::cout << "The 'analyze' command requires an API key for cloud intelligence.\n";
    std::cout << "Leave empty to skip (you can set it later).\n";
    std::cout << "API key: ";
    
    std::string api_key;
    std::getline(std::cin, api_key);
    
    if (!api_key.empty()) {
        if (ConfigValidator::validateApiKey(api_key)) {
            config_.api_key = api_key;
            
            if (path_manager.isUserMode()) {
                if (!saveUserCredentials(api_key)) {
                    std::cerr << "\n\033[33mWarning: Failed to save credentials\033[0m\n";
                }
            } else {
                if (!saveSystemSecrets(api_key)) {
                    std::cerr << "\n\033[33mWarning: Failed to save secrets\033[0m\n";
                }
            }
        } else {
            std::cerr << "\n\033[33mWarning: Invalid API key format\033[0m\n";
            std::cerr << "The key was not saved.\n";
        }
    }
    
    if (config_.api_key.empty()) {
        std::cout << "\n\033[36mNote:\033[0m Without an API key, the 'analyze' command will not be available.\n";
        std::cout << "You can configure it later.\n";
    }
    
    if (advanced_mode) {
        std::cout << "\n\033[1mPerformance Settings\033[0m\n";
        
        std::string threads_str = std::to_string(config_.scan.default_threads);
        threads_str = promptString("Default scan threads (1-32)", threads_str);
        try {
            int threads = std::stoi(threads_str);
            if (threads >= 1 && threads <= 32) {
                config_.scan.default_threads = threads;
            }
        } catch (...) {}
        
        std::string worker_threads_str = std::to_string(config_.daemon.worker_threads);
        worker_threads_str = promptString("Daemon worker threads (0=auto, 1-256)", worker_threads_str);
        try {
            int worker_threads = std::stoi(worker_threads_str);
            if (worker_threads >= 0 && worker_threads <= 256) {
                config_.daemon.worker_threads = worker_threads;
            }
        } catch (...) {}
        
        std::cout << "\n\033[1mLogging Settings\033[0m\n";
        
        std::string rotation_str = std::to_string(config_.logging.rotation_size_mb);
        rotation_str = promptString("Log rotation size in MB", rotation_str);
        try {
            size_t rotation = std::stoull(rotation_str);
            if (rotation >= 1) {
                config_.logging.rotation_size_mb = rotation;
            }
        } catch (...) {}
        
        std::string max_files_str = std::to_string(config_.logging.max_files);
        max_files_str = promptString("Keep log files", max_files_str);
        try {
            size_t max_files = std::stoull(max_files_str);
            if (max_files >= 1) {
                config_.logging.max_files = max_files;
            }
        } catch (...) {}
        
        if (path_manager.isSystemMode()) {
            std::cout << "\n\033[1mDaemon Settings\033[0m\n";
            
            std::string port_str = std::to_string(config_.daemon.http_port);
            port_str = promptString("HTTP API port", port_str);
            try {
                int port = std::stoi(port_str);
                if (port >= 1024 && port <= 65535) {
                    config_.daemon.http_port = static_cast<uint16_t>(port);
                }
            } catch (...) {}
        }
    }
    
    printSummary();
    
    common::Config::instance().global() = config_;
    if (common::Config::instance().save()) {
        std::cout << "\n\033[32m✓ Configuration saved successfully\033[0m\n";
        std::cout << "Location: " << config_path << "\n\n";
        std::cout << "Next steps:\n";
        std::cout << "  semantics-av scan /path/to/file\n";
        std::cout << "  semantics-av update\n";
        if (path_manager.isSystemMode()) {
            std::cout << "  sudo systemctl start semantics-av\n";
        } else {
            std::cout << "  systemctl --user start semantics-av\n";
        }
        
        triggerDaemonReloadIfRunning();
        return 0;
    }
    
    std::cerr << "\n\033[31mFailed to save configuration.\033[0m\n";
    return 1;
}

void ConfigWizard::triggerDaemonReloadIfRunning() {
    if (!daemon::DaemonClient::isDaemonRunning()) {
        return;
    }
    
    std::cout << "\nℹ Daemon is running - reloading configuration...\n";
    
    if (daemon::DaemonServer::sendSignalToDaemon(SIGHUP)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::cout << "✓ Daemon reloaded successfully\n";
    } else {
        std::cout << "⚠ Failed to reload daemon - please reload manually\n";
    }
}

void ConfigWizard::printHeader() {
    std::cout << "\n\033[1m" << constants::system::APPLICATION_NAME << " Configuration Setup\033[0m\n";
    std::cout << "================================\n\n";
    std::cout << "Installation Mode: " << install_mode_str_ << "\n";
    std::cout << "Config Location: " << common::PathManager::instance().getConfigFile() << "\n";
}

void ConfigWizard::printSummary() {
    std::cout << "\n\033[1mConfiguration Summary\033[0m\n";
    std::cout << "=====================\n";
    std::cout << "Installation Mode:  " << install_mode_str_ << "\n";
    std::cout << "Config File:        " << common::PathManager::instance().getConfigFile() << "\n";
    std::cout << "Base Directory:     " << config_.base_path << "\n";
    std::cout << "Models Directory:   " << config_.models_path << "\n";
    std::cout << "Log File:           " << config_.log_file << "\n";
    
    if (config_.api_key.empty()) {
        std::cout << "API Key:            Not configured\n";
    } else {
        std::cout << "API Key:            Configured\n";
    }
    
    std::cout << "\nPerformance:\n";
    std::cout << "  Default scan threads: " << config_.scan.default_threads << "\n";
    std::cout << "  Daemon workers:       " << (config_.daemon.worker_threads == 0 ? "auto" : std::to_string(config_.daemon.worker_threads)) << "\n";
    
    std::cout << "\nLogging:\n";
    std::cout << "  Rotation size: " << config_.logging.rotation_size_mb << " MB\n";
    std::cout << "  Keep files:    " << config_.logging.max_files << "\n";
    std::cout << "  Format:        " << (config_.logging.format == common::LogFormat::JSON ? "json" : "text") << "\n";
    
    std::cout << "\n";
}

std::string ConfigWizard::promptString(const std::string& prompt, const std::string& default_value) {
    std::cout << prompt << " [" << default_value << "]: ";
    
    std::string input;
    std::getline(std::cin, input);
    
    if (input.empty()) {
        return default_value;
    }
    
    return input;
}

int ConfigWizard::promptChoice(const std::string& prompt, const std::vector<std::string>& options, int default_idx) {
    std::cout << prompt << ":\n";
    for (size_t i = 0; i < options.size(); ++i) {
        std::cout << "  " << (i + 1) << ") " << options[i];
        if (static_cast<int>(i) == default_idx) {
            std::cout << " (default)";
        }
        std::cout << "\n";
    }
    std::cout << "Choice [" << (default_idx + 1) << "]: ";
    
    std::string input;
    std::getline(std::cin, input);
    
    if (input.empty()) {
        return default_idx;
    }
    
    try {
        int choice = std::stoi(input) - 1;
        if (choice >= 0 && choice < static_cast<int>(options.size())) {
            return choice;
        }
    } catch (...) {
    }
    
    return default_idx;
}

}}