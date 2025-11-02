#include "semantics_av/config/validator.hpp"
#include "semantics_av/common/logger.hpp"
#include <filesystem>
#include <regex>
#include <algorithm>

namespace semantics_av {
namespace config {

const std::set<std::string> ConfigMasker::SENSITIVE_KEYS = {"api_key"};

std::string ConfigMasker::mask(const std::string& key, const std::string& value) {
    if (SENSITIVE_KEYS.find(key) != SENSITIVE_KEYS.end() && !value.empty()) {
        if (value.length() <= 13) {
            return "****";
        }
        return value.substr(0, 13) + "****";
    }
    return value;
}

std::string ConfigMasker::smartDisplay(const std::string& key, 
                                       const std::optional<std::string>& value,
                                       bool file_exists) {
    if (value) {
        return mask(key, *value);
    }
    
    if (SENSITIVE_KEYS.find(key) != SENSITIVE_KEYS.end() && file_exists) {
        return "(configured - requires daemon or sudo)";
    }
    
    return "(not set)";
}

bool ConfigMasker::isSensitive(const std::string& key) {
    return SENSITIVE_KEYS.find(key) != SENSITIVE_KEYS.end();
}

ValidationResult ConfigValidator::validate(const common::GlobalConfig& config) {
    ValidationResult result;
    
    common::Logger::instance().debug("[Validator] Starting validation");
    
    if (!validatePath(config.base_path)) {
        result.errors.push_back("base_path: Invalid or inaccessible path");
        result.is_valid = false;
    }
    
    if (!validatePath(config.models_path)) {
        result.errors.push_back("models_path: Invalid or inaccessible path");
        result.is_valid = false;
    }
    
    if (!canCreateDirectory(std::filesystem::path(config.log_file).parent_path())) {
        result.errors.push_back("log_file: Cannot create parent directory");
        result.is_valid = false;
    }
    
    if (config.network_timeout <= 0 || config.network_timeout > 600) {
        result.errors.push_back("network_timeout: Must be between 1-600 seconds");
        result.is_valid = false;
    }
    
    if (!validatePort(config.daemon.http_port)) {
        result.errors.push_back("daemon.http_port: Invalid port number (must be >= 1024)");
        result.is_valid = false;
    }
    
    if (!config.api_key.empty() && !validateApiKey(config.api_key)) {
        result.errors.push_back("api_key: Invalid format (expected: sav_*)");
        result.is_valid = false;
    }
    
    if (config.api_key.empty()) {
        result.warnings.push_back(
            "api_key: Not configured\n"
            "  The 'analyze' command requires an API key for cloud intelligence.\n"
            "  Obtain a key from: https://console.semanticsav.ai\n"
            "  Configure via:\n"
            "    - Interactive wizard: semantics-av config init\n"
            "    - Quick setup: semantics-av config init --defaults\n"
            "    - Direct: semantics-av config set api_key \"YOUR_KEY\""
        );
    }
    
    if (config.scan.default_threads < 1 || config.scan.default_threads > 32) {
        result.errors.push_back("scan.default_threads: Must be between 1-32");
        result.is_valid = false;
    }
    
    if (config.daemon.worker_threads < 0) {
        result.errors.push_back("daemon.worker_threads: Must be >= 0 (0=auto)");
        result.is_valid = false;
    }
    
    if (config.daemon.worker_threads > 256) {
        result.warnings.push_back(
            "daemon.worker_threads: Very high value (256+), may cause resource exhaustion"
        );
    }
    
    if (config.logging.rotation_size_mb < 1) {
        result.errors.push_back("logging.rotation_size_mb: Must be >= 1");
        result.is_valid = false;
    }
    
    if (config.logging.max_files < 1) {
        result.errors.push_back("logging.max_files: Must be >= 1");
        result.is_valid = false;
    }
    
    if (result.is_valid) {
        common::Logger::instance().info("[Validator] Passed | warnings={}", result.warnings.size());
    } else {
        common::Logger::instance().error("[Validator] Failed | errors={}", result.errors.size());
    }
    
    return result;
}

ValidationResult ConfigValidator::validateFile(const std::string& path) {
    ValidationResult result;
    
    if (!std::filesystem::exists(path)) {
        result.errors.push_back("Configuration file does not exist");
        result.is_valid = false;
        common::Logger::instance().error("[Validator] File not found | path={}", path);
        return result;
    }
    
    try {
        auto& config = common::Config::instance();
        if (!config.load(path)) {
            result.errors.push_back("Failed to parse configuration file");
            result.is_valid = false;
            common::Logger::instance().error("[Validator] Parse failed | path={}", path);
            return result;
        }
        
        return validate(config.global());
    } catch (const std::exception& e) {
        result.errors.push_back(std::string("Exception: ") + e.what());
        result.is_valid = false;
        common::Logger::instance().error("[Validator] Exception | path={} | error={}", path, e.what());
        return result;
    }
}

bool ConfigValidator::validatePath(const std::string& path) {
    if (path.empty()) return false;
    
    std::filesystem::path p(path);
    
    if (std::filesystem::exists(p)) {
        return std::filesystem::is_directory(p);
    }
    
    return canCreateDirectory(path);
}

bool ConfigValidator::validatePort(uint16_t port) {
    return port >= 1024;
}

bool ConfigValidator::validateUrl(const std::string& url) {
    std::regex url_pattern(R"(^https?://[a-zA-Z0-9\-\.]+(\:[0-9]+)?(/.*)?$)");
    return std::regex_match(url, url_pattern);
}

bool ConfigValidator::validateApiKey(const std::string& key) {
    if (key.empty()) return true;
    
    if (key.length() < 30) return false;
    
    if (key.substr(0, 4) != "sav_") return false;
    
    std::string token = key.substr(4);
    return std::all_of(token.begin(), token.end(), 
        [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-'; });
}

bool ConfigValidator::canCreateDirectory(const std::string& path) {
    try {
        std::filesystem::path p(path);
        
        if (std::filesystem::exists(p)) {
            return std::filesystem::is_directory(p);
        }
        
        auto parent = p.parent_path();
        if (parent.empty()) return true;
        
        if (std::filesystem::exists(parent)) {
            auto perms = std::filesystem::status(parent).permissions();
            return (perms & std::filesystem::perms::owner_write) != std::filesystem::perms::none;
        }
        
        return canCreateDirectory(parent.string());
    } catch (...) {
        return false;
    }
}

}}