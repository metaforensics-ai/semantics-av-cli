#include "config_command.hpp"
#include "semantics_av/common/config.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/paths.hpp"
#include "semantics_av/config/wizard.hpp"
#include "semantics_av/config/validator.hpp"
#include "semantics_av/daemon/server.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <regex>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <thread>
#include <chrono>

namespace semantics_av {
namespace cli {

ConfigCommand::ConfigCommand() : was_called_(false) {}

void ConfigCommand::setup(CLI::App* subcommand) {
    subcommand_ = subcommand;
    
    init_cmd_ = subcommand->add_subcommand("init", "Initialize configuration");
    init_cmd_->add_flag("-d,--defaults", init_defaults_, "Use default values (non-interactive)");
    init_cmd_->callback([this]() { was_called_ = true; });
    
    set_cmd_ = subcommand->add_subcommand("set", "Set configuration value");
    set_cmd_->add_option("key", set_key_, "Configuration key")->required();
    set_cmd_->add_option("value", set_value_, "Configuration value")->required();
    set_cmd_->callback([this]() { was_called_ = true; });
    
    get_cmd_ = subcommand->add_subcommand("get", "Get configuration value");
    get_cmd_->add_option("key", get_key_, "Configuration key (optional)");
    get_cmd_->add_flag("--reveal-secrets", reveal_secrets_, "Show sensitive information");
    get_cmd_->callback([this]() { was_called_ = true; });
    
    show_cmd_ = subcommand->add_subcommand("show", "Show configuration file");
    show_cmd_->add_flag("--reveal-secrets", reveal_secrets_, "Show sensitive information");
    show_cmd_->callback([this]() { was_called_ = true; });
    
    validate_cmd_ = subcommand->add_subcommand("validate", "Validate configuration");
    validate_cmd_->callback([this]() { was_called_ = true; });
}

bool ConfigCommand::wasCalled() const {
    return was_called_;
}

int ConfigCommand::execute() {
    if (init_cmd_->parsed()) {
        return executeInit();
    } else if (set_cmd_->parsed()) {
        return executeSet();
    } else if (get_cmd_->parsed()) {
        return executeGet();
    } else if (show_cmd_->parsed()) {
        return executeShow();
    } else if (validate_cmd_->parsed()) {
        return executeValidate();
    }
    
    std::cout << subcommand_->help() << std::endl;
    return 0;
}

int ConfigCommand::executeInit() {
    auto& path_manager = common::PathManager::instance();
    std::string config_path = path_manager.getConfigFile();
    std::filesystem::path config_dir = std::filesystem::path(config_path).parent_path();
    
    if (access(config_dir.c_str(), W_OK) != 0) {
        std::cerr << "\033[31mError: Permission denied\033[0m\n\n";
        std::cerr << "Configuration directory: " << config_dir << "\n\n";
        
        if (path_manager.isSystemMode()) {
            std::cerr << "\033[1mSystem-wide configuration requires root privileges.\033[0m\n";
            std::cerr << "Run with sudo:\n";
            std::cerr << "  \033[32msudo semantics-av config init";
            if (init_defaults_) std::cerr << " --defaults";
            std::cerr << "\033[0m\n";
        } else {
            std::cerr << "Cannot write to configuration directory.\n";
            std::cerr << "Check directory permissions: ls -ld " << config_dir << "\n";
        }
        return 1;
    }
    
    config::ConfigWizard wizard;
    int result = wizard.run(init_defaults_);
    return result;
}

int ConfigCommand::executeSet() {
    auto& config = common::Config::instance();
    
    if (!config.exists()) {
        std::cerr << "Configuration file does not exist.\n";
        std::cerr << "Run: semantics-av config init\n";
        return 1;
    }
    
    std::string config_path = config.getConfigPath();
    
    if (!canWriteConfig(config_path)) {
        std::cerr << "\033[31mError: Permission denied\033[0m\n\n";
        std::cerr << "Resource: " << config_path << "\n\n";
        
        auto& path_manager = common::PathManager::instance();
        if (path_manager.isSystemMode()) {
            std::cerr << "\033[1mSystem-wide configuration requires root privileges.\033[0m\n";
            std::cerr << "Run with sudo:\n";
            std::cerr << "  \033[32msudo semantics-av config set " << set_key_ 
                      << " \"" << set_value_ << "\"\033[0m\n";
        } else {
            std::cerr << "Cannot write to configuration file.\n";
            std::cerr << "Check file permissions: ls -l " << config_path << "\n";
        }
        return 1;
    }
    
    if (!config.load()) {
        std::cerr << "Failed to load configuration.\n";
        return 1;
    }
    
    if (set_key_ == "api_key") {
        if (!config::ConfigValidator::validateApiKey(set_value_)) {
            std::cerr << "\033[31mError: Invalid API key format\033[0m\n\n";
            std::cerr << "Expected format: sav_*\n";
            std::cerr << "Get your API key from: https://console.semanticsav.ai\n";
            return 1;
        }
        
        if (!config.updateApiKey(set_value_)) {
            std::cerr << "Failed to update API key.\n";
            return 1;
        }
        
        std::cout << "✓ API key updated successfully\n";
        
        triggerDaemonReloadIfNeeded(set_key_);
        return 0;
    }
    
    config.setValue(set_key_, set_value_);
    
    if (config.save()) {
        std::cout << "✓ Configuration updated: " << set_key_ << " = " << set_value_ << "\n";
        
        triggerDaemonReloadIfNeeded(set_key_);
        return 0;
    }
    
    std::cerr << "Failed to save configuration.\n";
    return 1;
}

void ConfigCommand::triggerDaemonReloadIfNeeded(const std::string& key) {
    static const std::set<std::string> network_keys = {
        "api_key", "api_base_url", "cdn_url", "network_timeout"
    };
    
    if (network_keys.find(key) == network_keys.end()) {
        return;
    }
    
    if (!daemon::DaemonServer::isDaemonRunning()) {
        std::cout << "\nℹ Daemon not running - changes will apply on next start\n";
        return;
    }
    
    if (daemon::DaemonServer::sendSignalToDaemon(SIGHUP)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::cout << "ℹ Daemon reloaded - changes applied\n";
    } else {
        std::cout << "\n⚠ Failed to reload daemon - manual reload may be needed\n";
    }
}

int ConfigCommand::executeGet() {
    auto& config = common::Config::instance();
    
    if (!config.exists()) {
        std::cerr << "Configuration file does not exist.\n";
        std::cerr << "Run: semantics-av config init\n";
        return 1;
    }
    
    if (reveal_secrets_) {
        if (!canRevealSecrets()) {
            return 1;
        }
    }
    
    if (!config.load()) {
        std::cerr << "Failed to load configuration.\n";
        return 1;
    }
    
    if (get_key_.empty()) {
        auto& global = config.global();
        
        std::cout << "Configuration:\n";
        std::cout << "  base_path = " << global.base_path << "\n";
        std::cout << "  models_path = " << global.models_path << "\n";
        std::cout << "  log_file = " << global.log_file << "\n";
        std::cout << "  log_level = ";
        switch (global.log_level) {
            case common::LogLevel::ERROR: std::cout << "ERROR\n"; break;
            case common::LogLevel::WARN: std::cout << "WARN\n"; break;
            case common::LogLevel::INFO: std::cout << "INFO\n"; break;
            case common::LogLevel::DEBUG: std::cout << "DEBUG\n"; break;
        }
        
        bool api_key_exists = checkApiKeyFileExists();
        std::string api_key_display;
        if (reveal_secrets_) {
            api_key_display = global.api_key.empty() ? "(not set)" : global.api_key;
        } else {
            api_key_display = config::ConfigMasker::smartDisplay(
                "api_key", 
                global.api_key.empty() ? std::nullopt : std::optional<std::string>(global.api_key),
                api_key_exists
            );
        }
        std::cout << "  api_key = " << api_key_display << "\n";        
        std::cout << "  network_timeout = " << global.network_timeout << "\n";
        std::cout << "  auto_update = " << (global.auto_update ? "true" : "false") << "\n";
        std::cout << "  scan.default_threads = " << global.scan.default_threads << "\n";
        std::cout << "  daemon.socket_path = " << global.daemon.socket_path << "\n";
        std::cout << "  daemon.http_host = " << global.daemon.http_host << "\n";
        std::cout << "  daemon.http_port = " << global.daemon.http_port << "\n";
        std::cout << "  daemon.worker_threads = " << global.daemon.worker_threads << "\n";
    } else {
        auto value = config.getValue(get_key_);
        bool is_sensitive = config::ConfigMasker::isSensitive(get_key_);
        
        if (value) {
            if (reveal_secrets_ || !is_sensitive) {
                std::cout << *value << "\n";
            } else {
                std::cout << config::ConfigMasker::mask(get_key_, *value) << "\n";
            }
        } else if (get_key_ == "api_key") {
            bool api_key_exists = checkApiKeyFileExists();
            std::string display;
            if (reveal_secrets_) {
                display = "(not set)";
            } else {
                display = config::ConfigMasker::smartDisplay(get_key_, std::nullopt, api_key_exists);
            }
            std::cout << display << "\n";
        } else {
            std::cerr << "Unknown configuration key: " << get_key_ << "\n";
            return 1;
        }
    }
    
    return 0;
}

int ConfigCommand::executeShow() {
    auto& config = common::Config::instance();
    std::string config_path = config.getConfigPath();
    
    if (!std::filesystem::exists(config_path)) {
        std::cerr << "Configuration file does not exist.\n";
        std::cerr << "Expected: " << config_path << "\n";
        std::cerr << "Run: semantics-av config init\n";
        return 1;
    }
    
    if (reveal_secrets_) {
        if (!canRevealSecrets()) {
            return 1;
        }
    }
    
    std::cout << "Configuration file: " << config_path << "\n\n";
    
    std::ifstream file(config_path);
    if (!file) {
        std::cerr << "Failed to read configuration file.\n";
        return 1;
    }
    
    std::string line;
    std::regex api_key_pattern("(api_key\\s*=\\s*)\"([^\"]+)\"");
    
    while (std::getline(file, line)) {
        if (!reveal_secrets_) {
            std::smatch match;
            if (std::regex_search(line, match, api_key_pattern)) {
                std::string key_part = match[1].str();
                std::string value = match[2].str();
                if (value.length() > 13) {
                    std::cout << key_part << "\"" << value.substr(0, 13) << "****\"\n";
                } else {
                    std::cout << key_part << "\"****\"\n";
                }
                continue;
            }
        }
        std::cout << line << "\n";
    }
    
    return 0;
}

int ConfigCommand::executeValidate() {
    auto& config = common::Config::instance();
    std::string config_path = config.getConfigPath();
    
    std::cout << "Validating: " << config_path << "\n\n";
    
    config::ConfigValidator validator;
    auto result = validator.validateFile(config_path);
    
    if (result.errors.empty()) {
        std::cout << "Syntax: Valid\n";
    } else {
        std::cout << "Syntax: Invalid\n";
    }
    
    for (const auto& error : result.errors) {
        std::cout << "  ERROR: " << error << "\n";
    }
    
    for (const auto& warning : result.warnings) {
        std::cout << "  WARNING: " << warning << "\n";
    }
    
    std::cout << "\nErrors: " << result.errors.size() 
              << "  Warnings: " << result.warnings.size() << "\n";
    
    if (result.is_valid) {
        std::cout << "\nConfiguration is valid.\n";
        return 0;
    }
    
    std::cout << "\nConfiguration has errors.\n";
    return 1;
}

bool ConfigCommand::canWriteConfig(const std::string& config_path) {
    if (std::filesystem::exists(config_path)) {
        return access(config_path.c_str(), W_OK) == 0;
    }
    
    std::filesystem::path parent = std::filesystem::path(config_path).parent_path();
    return access(parent.c_str(), W_OK) == 0;
}

bool ConfigCommand::canRevealSecrets() {
    auto& path_manager = common::PathManager::instance();
    
    if (path_manager.isSystemMode()) {
        if (getuid() != 0) {
            std::string secrets_file = path_manager.getSystemSecretsFile();
            std::cerr << "\033[31mError: Permission denied\033[0m\n\n";
            std::cerr << "Resource: " << secrets_file << "\n\n";
            std::cerr << "\033[1mSystem secrets require root privileges.\033[0m\n";
            std::cerr << "Run with sudo:\n";
            std::cerr << "  sudo semantics-av config get";
            if (!get_key_.empty()) std::cerr << " " << get_key_;
            std::cerr << " --reveal-secrets\n";
            return false;
        }
    } else {
        std::string cred_file = path_manager.getUserCredentialsFile();
        if (!cred_file.empty() && std::filesystem::exists(cred_file)) {
            struct stat st;
            if (stat(cred_file.c_str(), &st) == 0) {
                if (st.st_uid != getuid()) {
                    std::cerr << "\033[31mError: Permission denied\033[0m\n\n";
                    std::cerr << "Resource: " << cred_file << "\n\n";
                    std::cerr << "\033[1mCredentials file not owned by current user.\033[0m\n";
                    std::cerr << "File owner UID: " << st.st_uid << "\n";
                    std::cerr << "Current UID: " << getuid() << "\n";
                    return false;
                }
            }
        }
    }
    
    return true;
}

bool ConfigCommand::checkApiKeyFileExists() {
    auto& path_manager = common::PathManager::instance();
    
    if (path_manager.isSystemMode()) {
        std::string secrets = path_manager.getSystemSecretsFile();
        return !secrets.empty() && std::filesystem::exists(secrets);
    } else {
        std::string creds = path_manager.getUserCredentialsFile();
        return !creds.empty() && std::filesystem::exists(creds);
    }
}

}}