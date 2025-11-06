#include "semantics_av/common/config.hpp"
#include "semantics_av/common/constants.hpp"
#include "semantics_av/common/paths.hpp"
#include "semantics_av/common/logger.hpp"
#include <toml.hpp>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <filesystem>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>

namespace semantics_av {
namespace common {

Config& Config::instance() {
    static Config instance;
    return instance;
}

Config::Config() {
    global_ = createDefaultConfig();
}

GlobalConfig Config::createDefaultConfig() {
    using namespace constants::config_defaults;
    
    GlobalConfig config;
    
    config.log_level = LogLevel::INFO;
    config.network_timeout = NETWORK_TIMEOUT;
    config.auto_update = AUTO_UPDATE;
    config.update_interval_minutes = UPDATE_INTERVAL_MINUTES;
    config.max_scan_size_mb = MAX_SCAN_SIZE_MB;
    config.scan_timeout_seconds = SCAN_TIMEOUT_SECONDS;
    config.max_recursion_depth = MAX_RECURSION_DEPTH;
    config.api_key = "";
    config.base_path = "";
    config.models_path = "";
    config.log_file = "";
    
    config.scan.default_threads = SCAN_DEFAULT_THREADS;
    config.scan.scan_batch_size = SCAN_BATCH_SIZE;
    
    config.logging.rotation_size_mb = LOG_ROTATION_SIZE_MB;
    config.logging.max_files = LOG_MAX_FILES;
    config.logging.format = LogFormat::TEXT;
    
    config.report.enable_storage = REPORT_ENABLE_STORAGE;
    config.report.reports_dir = "";
    config.report.retention_days = REPORT_RETENTION_DAYS;
    config.report.auto_cleanup = REPORT_AUTO_CLEANUP;
    config.report.max_reports = REPORT_MAX_REPORTS;
    
    config.daemon.http_port = DAEMON_HTTP_PORT;
    config.daemon.http_host = DAEMON_HTTP_HOST;
    config.daemon.read_timeout = DAEMON_READ_TIMEOUT;
    config.daemon.worker_threads = DAEMON_WORKER_THREADS;
    config.daemon.socket_buffer_kb = DAEMON_SOCKET_BUFFER_KB;
    config.daemon.connection_backlog = DAEMON_CONNECTION_BACKLOG;
    config.daemon.socket_path = "";
    config.daemon.user = "";
    config.daemon.group = "";
    config.daemon.max_connections = DAEMON_MAX_CONNECTIONS_SYSTEM;
    config.daemon.max_queue = DAEMON_MAX_QUEUE_SYSTEM;
    
    return config;
}

std::optional<std::string> Config::findBestConfig() const {
    auto paths = PathManager::instance().getConfigSearchPaths();
    
    for (const auto& path : paths) {
        if (std::filesystem::exists(path) && access(path.c_str(), R_OK) == 0) {
            return path;
        }
    }
    
    return std::nullopt;
}

bool Config::checkHealth() const {
    if (current_config_path_.empty()) {
        return true;
    }
    
    struct stat st;
    if (stat(current_config_path_.c_str(), &st) != 0) {
        return false;
    }
    
    auto& path_manager = PathManager::instance();
    
    if (path_manager.isUserMode()) {
        uid_t current_uid = getuid();
        if (st.st_uid != current_uid && st.st_uid == 0) {
            return false;
        }
    }
    
    if (path_manager.isSystemMode()) {
        if (st.st_uid != 0) {
            return false;
        }
    }
    
    return true;
}

void Config::suggestFix() const {
    if (current_config_path_.empty()) {
        return;
    }
    
    struct stat st;
    if (stat(current_config_path_.c_str(), &st) != 0) {
        return;
    }
    
    auto& path_manager = PathManager::instance();
    
    if (path_manager.isUserMode() && st.st_uid == 0) {
        std::cerr << "\n\033[33mWarning: Configuration file is owned by root\033[0m\n";
        std::cerr << "File: " << current_config_path_ << "\n\n";
        std::cerr << "This may cause permission issues. To fix:\n";
        std::cerr << "  sudo chown $USER:$USER " << current_config_path_ << "\n";
        
        std::string parent = std::filesystem::path(current_config_path_).parent_path();
        std::cerr << "  sudo chown -R $USER:$USER " << parent << "\n\n";
    }
}

bool Config::load(const std::string& config_file) {
    try {
        global_ = createDefaultConfig();
        
        auto& path_manager = PathManager::instance();
        
        global_.base_path = path_manager.getDataDir();
        global_.models_path = global_.base_path + "/models";
        global_.daemon.socket_path = path_manager.getSocketPath();
        
        if (path_manager.isUserMode()) {
            global_.log_file = path_manager.getLogDir() + "/semantics-av.log";
            global_.daemon.http_host = constants::config_defaults::DAEMON_HTTP_HOST;
            global_.daemon.user = "";
            global_.daemon.group = "";
            global_.daemon.max_connections = constants::config_defaults::DAEMON_MAX_CONNECTIONS_USER;
            global_.daemon.max_queue = constants::config_defaults::DAEMON_MAX_QUEUE_USER;
        } else {
            global_.log_file = "/var/log/semantics-av/semantics-av.log";
            global_.daemon.http_host = constants::config_defaults::DAEMON_HTTP_HOST;
            global_.daemon.user = constants::system::DAEMON_USER;
            global_.daemon.group = constants::system::DAEMON_GROUP;
            global_.daemon.max_connections = constants::config_defaults::DAEMON_MAX_CONNECTIONS_SYSTEM;
            global_.daemon.max_queue = constants::config_defaults::DAEMON_MAX_QUEUE_SYSTEM;
        }
        
        std::string effective_config_file = config_file;
        if (effective_config_file.empty()) {
            auto best = findBestConfig();
            if (best) {
                effective_config_file = *best;
            } else {
                effective_config_file = path_manager.getConfigFile();
            }
        }
        
        current_config_path_ = effective_config_file;
        
        bool has_any_config = false;
        
        if (global_.api_key.empty()) {
            std::string user_credentials = path_manager.getUserCredentialsFile();
            if (!user_credentials.empty() && tryLoadCredentials(user_credentials)) {
                has_any_config = true;
            }
        }
        
        if (global_.api_key.empty()) {
            std::string system_secrets = path_manager.getSystemSecretsFile();
            if (!system_secrets.empty() && tryLoadTomlFile(system_secrets, "system secrets")) {
                has_any_config = true;
            }
        }
        
        if (tryLoadTomlFile(effective_config_file, "main config")) {
            has_any_config = true;
        }
        
        Logger::instance().info("[Config] Loaded | has_api_key={} | sources_loaded={}", 
                               !global_.api_key.empty(), has_any_config);
        
        if (!checkHealth()) {
            suggestFix();
        }
        
        return true;
    } catch (const std::exception& e) {
        Logger::instance().error("[Config] Parse failed | error={}", e.what());
        return false;
    }
}

bool Config::tryLoadCredentials(const std::string& path) {
    if (!std::filesystem::exists(path)) {
        Logger::instance().debug("[Config] Credentials not found | path={}", path);
        return false;
    }
    
    if (access(path.c_str(), R_OK) != 0) {
        Logger::instance().debug("[Config] Credentials not readable | path={}", path);
        return false;
    }
    
    try {
        std::ifstream file(path);
        if (!file) {
            Logger::instance().debug("[Config] Credentials open failed | path={}", path);
            return false;
        }
        
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            
            auto eq_pos = line.find('=');
            if (eq_pos != std::string::npos) {
                std::string key = line.substr(0, eq_pos);
                std::string value = line.substr(eq_pos + 1);
                
                while (!key.empty() && std::isspace(key.back())) key.pop_back();
                while (!value.empty() && std::isspace(value.front())) value.erase(0, 1);
                while (!value.empty() && std::isspace(value.back())) value.pop_back();
                
                if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
                    value = value.substr(1, value.size() - 2);
                }
                
                if (key == "api_key" || key == "SEMANTICS_AV_API_KEY") {
                    global_.api_key = value;
                }
            }
        }
        
        Logger::instance().info("[Config] Credentials loaded | path={} | has_api_key={}", 
                               path, !global_.api_key.empty());
        return true;
    } catch (const std::exception& e) {
        Logger::instance().debug("[Config] Credentials parse failed | path={} | error={}", 
                                path, e.what());
        return false;
    }
}

bool Config::tryLoadTomlFile(const std::string& path, const std::string& description) {
    if (!std::filesystem::exists(path)) {
        Logger::instance().debug("[Config] {} not found | path={}", description, path);
        return false;
    }
    
    if (access(path.c_str(), R_OK) != 0) {
        Logger::instance().debug("[Config] {} not readable | path={}", description, path);
        return false;
    }
    
    try {
        auto data = toml::parse(path);
        
        if (data.contains("global")) {
            auto global_section = data.at("global");
            
            if (global_section.contains("base_path")) {
                global_.base_path = toml::find<std::string>(global_section, "base_path");
            }
            if (global_section.contains("models_path")) {
                global_.models_path = toml::find<std::string>(global_section, "models_path");
            }
            if (global_section.contains("log_file")) {
                global_.log_file = toml::find<std::string>(global_section, "log_file");
            }
            if (global_section.contains("log_level")) {
                std::string level = toml::find<std::string>(global_section, "log_level");
                if (level == "DEBUG") global_.log_level = LogLevel::DEBUG;
                else if (level == "INFO") global_.log_level = LogLevel::INFO;
                else if (level == "WARN") global_.log_level = LogLevel::WARN;
                else if (level == "ERROR") global_.log_level = LogLevel::ERROR;
            }
            if (global_section.contains("api_key") && global_.api_key.empty()) {
                global_.api_key = toml::find<std::string>(global_section, "api_key");
            }
            if (global_section.contains("network_timeout")) {
                global_.network_timeout = toml::find<int>(global_section, "network_timeout");
            }
            if (global_section.contains("auto_update")) {
                global_.auto_update = toml::find<bool>(global_section, "auto_update");
            }
            if (global_section.contains("update_interval_minutes")) {
                global_.update_interval_minutes = toml::find<int>(global_section, "update_interval_minutes");
            }
            if (global_section.contains("max_scan_size_mb")) {
                global_.max_scan_size_mb = toml::find<int>(global_section, "max_scan_size_mb");
            }
            if (global_section.contains("scan_timeout_seconds")) {
                global_.scan_timeout_seconds = toml::find<int>(global_section, "scan_timeout_seconds");
            }
            if (global_section.contains("max_recursion_depth")) {
                global_.max_recursion_depth = toml::find<int>(global_section, "max_recursion_depth");
            }
        }
        
        if (data.contains("scan")) {
            auto scan_section = data.at("scan");
            
            if (scan_section.contains("default_threads")) {
                global_.scan.default_threads = toml::find<int>(scan_section, "default_threads");
            }
            if (scan_section.contains("scan_batch_size")) {
                global_.scan.scan_batch_size = toml::find<size_t>(scan_section, "scan_batch_size");
            }
        }
        
        if (data.contains("daemon")) {
            auto daemon_section = data.at("daemon");
            
            if (daemon_section.contains("socket_path")) {
                global_.daemon.socket_path = toml::find<std::string>(daemon_section, "socket_path");
            }
            if (daemon_section.contains("http_port")) {
                global_.daemon.http_port = static_cast<uint16_t>(toml::find<int>(daemon_section, "http_port"));
            }
            if (daemon_section.contains("http_host")) {
                global_.daemon.http_host = toml::find<std::string>(daemon_section, "http_host");
            }
            if (daemon_section.contains("user")) {
                global_.daemon.user = toml::find<std::string>(daemon_section, "user");
            }
            if (daemon_section.contains("group")) {
                global_.daemon.group = toml::find<std::string>(daemon_section, "group");
            }
            if (daemon_section.contains("max_connections")) {
                global_.daemon.max_connections = toml::find<int>(daemon_section, "max_connections");
            }
            if (daemon_section.contains("max_queue")) {
                global_.daemon.max_queue = toml::find<int>(daemon_section, "max_queue");
            }
            if (daemon_section.contains("read_timeout")) {
                global_.daemon.read_timeout = toml::find<int>(daemon_section, "read_timeout");
            }
            if (daemon_section.contains("worker_threads")) {
                global_.daemon.worker_threads = toml::find<int>(daemon_section, "worker_threads");
            }
            if (daemon_section.contains("socket_buffer_kb")) {
                global_.daemon.socket_buffer_kb = toml::find<size_t>(daemon_section, "socket_buffer_kb");
            }
            if (daemon_section.contains("connection_backlog")) {
                global_.daemon.connection_backlog = toml::find<int>(daemon_section, "connection_backlog");
            }
        }
        
        if (data.contains("logging")) {
            auto logging_section = data.at("logging");
            
            if (logging_section.contains("rotation_size_mb")) {
                global_.logging.rotation_size_mb = toml::find<size_t>(logging_section, "rotation_size_mb");
            }
            if (logging_section.contains("max_files")) {
                global_.logging.max_files = toml::find<size_t>(logging_section, "max_files");
            }
            if (logging_section.contains("format")) {
                std::string format_str = toml::find<std::string>(logging_section, "format");
                if (format_str == "json") {
                    global_.logging.format = LogFormat::JSON;
                } else {
                    global_.logging.format = LogFormat::TEXT;
                }
            }
        }
        
        if (data.contains("report")) {
            auto report_section = data.at("report");
            
            if (report_section.contains("enable_storage")) {
                global_.report.enable_storage = toml::find<bool>(report_section, "enable_storage");
            }
            if (report_section.contains("reports_dir")) {
                global_.report.reports_dir = toml::find<std::string>(report_section, "reports_dir");
            }
            if (report_section.contains("retention_days")) {
                global_.report.retention_days = toml::find<int>(report_section, "retention_days");
            }
            if (report_section.contains("auto_cleanup")) {
                global_.report.auto_cleanup = toml::find<bool>(report_section, "auto_cleanup");
            }
            if (report_section.contains("max_reports")) {
                global_.report.max_reports = toml::find<int>(report_section, "max_reports");
            }
        }
        
        Logger::instance().info("[Config] {} loaded | path={}", description, path);
        return true;
    } catch (const std::exception& e) {
        Logger::instance().debug("[Config] {} parse failed | path={} | error={}", 
                                description, path, e.what());
        return false;
    }
}

bool Config::save(const std::string& config_file) {
    try {
        auto& path_manager = PathManager::instance();
        
        std::string effective_config_file = config_file;
        if (effective_config_file.empty()) {
            effective_config_file = current_config_path_.empty() 
                ? path_manager.getConfigFile() 
                : current_config_path_;
        }
        
        bool is_system_mode = path_manager.isSystemMode();
        
        toml::value data = toml::table{
            {"global", toml::table{
                {"base_path", global_.base_path},
                {"models_path", global_.models_path},
                {"log_file", global_.log_file},
                {"log_level", [this]() {
                    switch (global_.log_level) {
                        case LogLevel::DEBUG: return "DEBUG";
                        case LogLevel::INFO: return "INFO";
                        case LogLevel::WARN: return "WARN";
                        case LogLevel::ERROR: return "ERROR";
                    }
                    return "INFO";
                }()},
                {"network_timeout", global_.network_timeout},
                {"auto_update", global_.auto_update},
                {"update_interval_minutes", global_.update_interval_minutes},
                {"max_scan_size_mb", global_.max_scan_size_mb},
                {"scan_timeout_seconds", global_.scan_timeout_seconds},
                {"max_recursion_depth", global_.max_recursion_depth}
            }},
            {"scan", toml::table{
                {"default_threads", global_.scan.default_threads},
                {"scan_batch_size", global_.scan.scan_batch_size}
            }},
            {"daemon", toml::table{
                {"socket_path", global_.daemon.socket_path},
                {"http_port", global_.daemon.http_port},
                {"http_host", global_.daemon.http_host},
                {"user", global_.daemon.user},
                {"group", global_.daemon.group},
                {"max_connections", global_.daemon.max_connections},
                {"max_queue", global_.daemon.max_queue},
                {"read_timeout", global_.daemon.read_timeout},
                {"worker_threads", global_.daemon.worker_threads},
                {"socket_buffer_kb", global_.daemon.socket_buffer_kb},
                {"connection_backlog", global_.daemon.connection_backlog}
            }},
            {"logging", toml::table{
                {"rotation_size_mb", global_.logging.rotation_size_mb},
                {"max_files", global_.logging.max_files},
                {"format", global_.logging.format == LogFormat::JSON ? "json" : "text"}
            }},
            {"report", toml::table{
                {"enable_storage", global_.report.enable_storage},
                {"reports_dir", global_.report.reports_dir},
                {"retention_days", global_.report.retention_days},
                {"auto_cleanup", global_.report.auto_cleanup},
                {"max_reports", global_.report.max_reports}
            }}
        };
        
        if (!is_system_mode) {
            auto& global_table = data["global"].as_table();
            global_table["api_key"] = global_.api_key;
        }
        
        std::ofstream file(effective_config_file);
        if (!file) {
            Logger::instance().error("[Config] File open failed | path={}", effective_config_file);
            return false;
        }
        
        file << toml::format(data);
        file.close();
        
        chmod(effective_config_file.c_str(), is_system_mode ? 0644 : 0600);
        
        current_config_path_ = effective_config_file;
        
        Logger::instance().info("[Config] Saved | path={}", effective_config_file);
        return true;
    } catch (const std::exception& e) {
        Logger::instance().error("[Config] Save failed | error={}", e.what());
        return false;
    }
}

bool Config::updateApiKey(const std::string& api_key) {
    global_.api_key = api_key;
    raw_values_["api_key"] = api_key;
    
    auto& path_manager = PathManager::instance();
    bool is_system_mode = path_manager.isSystemMode();
    
    bool success = false;
    
    if (is_system_mode) {
        std::string secrets_path = path_manager.getSystemSecretsFile();
        if (!secrets_path.empty()) {
            success = saveApiKeyToFile(api_key, secrets_path, true);
        }
    } else {
        std::string credentials_path = path_manager.getUserCredentialsFile();
        if (!credentials_path.empty()) {
            success = saveApiKeyToFile(api_key, credentials_path, false);
        }
    }
    
    if (success) {
        Logger::instance().info("[Config] API key updated | mode={}", 
                               is_system_mode ? "system" : "user");
    }
    
    return success;
}

bool Config::saveApiKeyToFile(const std::string& api_key, const std::string& file_path, bool is_system) {
    try {
        std::filesystem::path file_dir = std::filesystem::path(file_path).parent_path();
        if (!std::filesystem::exists(file_dir)) {
            std::filesystem::create_directories(file_dir);
        }
        
        if (is_system) {
            std::ofstream file(file_path);
            if (!file) {
                Logger::instance().error("[Config] Failed to open secrets file | path={}", file_path);
                return false;
            }
            
            file << "[global]\n";
            file << "api_key = \"" << api_key << "\"\n";
            file.close();
            
            chmod(file_path.c_str(), 0640);
            
            struct passwd* pw = getpwnam(constants::system::DAEMON_USER);
            if (pw) {
                if (chown(file_path.c_str(), 0, pw->pw_gid) != 0) {
                    Logger::instance().warn("[Config] Failed to set ownership | path={} | error={}", 
                                           file_path, strerror(errno));
                }
            }
        } else {
            std::ofstream file(file_path);
            if (!file) {
                Logger::instance().error("[Config] Failed to open credentials file | path={}", file_path);
                return false;
            }
            
            file << "api_key=\"" << api_key << "\"\n";
            file.close();
            
            chmod(file_path.c_str(), 0600);
        }
        
        Logger::instance().debug("[Config] API key saved | path={} | system={}", file_path, is_system);
        return true;
        
    } catch (const std::exception& e) {
        Logger::instance().error("[Config] Failed to save API key | path={} | error={}", 
                                file_path, e.what());
        return false;
    }
}

bool Config::exists() const {
    auto& path_manager = PathManager::instance();
    std::string config_path = current_config_path_.empty() 
        ? path_manager.getConfigFile() 
        : current_config_path_;
    return std::filesystem::exists(config_path);
}

void Config::setValue(const std::string& key, const std::string& value) {
    raw_values_[key] = value;
    
    if (key == "api_key") global_.api_key = value;
    else if (key == "base_path") global_.base_path = value;
    else if (key == "models_path") global_.models_path = value;
    else if (key == "log_file") global_.log_file = value;
    else if (key == "log_level") {
        if (value == "DEBUG") global_.log_level = LogLevel::DEBUG;
        else if (value == "INFO") global_.log_level = LogLevel::INFO;
        else if (value == "WARN") global_.log_level = LogLevel::WARN;
        else if (value == "ERROR") global_.log_level = LogLevel::ERROR;
    }
    else if (key == "network_timeout") global_.network_timeout = std::stoi(value);
    else if (key == "auto_update") global_.auto_update = (value == "true" || value == "1");
    else if (key == "update_interval_minutes") global_.update_interval_minutes = std::stoi(value);
    else if (key == "max_scan_size_mb") global_.max_scan_size_mb = std::stoi(value);
    else if (key == "scan_timeout_seconds") global_.scan_timeout_seconds = std::stoi(value);
    else if (key == "max_recursion_depth") global_.max_recursion_depth = std::stoi(value);
    else if (key == "scan.default_threads") global_.scan.default_threads = std::stoi(value);
    else if (key == "scan.scan_batch_size") global_.scan.scan_batch_size = std::stoull(value);
    else if (key == "daemon.socket_path") global_.daemon.socket_path = value;
    else if (key == "daemon.http_port") global_.daemon.http_port = std::stoi(value);
    else if (key == "daemon.http_host") global_.daemon.http_host = value;
    else if (key == "daemon.user") global_.daemon.user = value;
    else if (key == "daemon.group") global_.daemon.group = value;
    else if (key == "daemon.worker_threads") global_.daemon.worker_threads = std::stoi(value);
    else if (key == "daemon.socket_buffer_kb") global_.daemon.socket_buffer_kb = std::stoull(value);
    else if (key == "daemon.connection_backlog") global_.daemon.connection_backlog = std::stoi(value);
    else if (key == "logging.rotation_size_mb") global_.logging.rotation_size_mb = std::stoull(value);
    else if (key == "logging.max_files") global_.logging.max_files = std::stoull(value);
    else if (key == "logging.format") {
        global_.logging.format = (value == "json") ? LogFormat::JSON : LogFormat::TEXT;
    }
    else if (key == "report.enable_storage") global_.report.enable_storage = (value == "true" || value == "1");
    else if (key == "report.reports_dir") global_.report.reports_dir = value;
    else if (key == "report.retention_days") global_.report.retention_days = std::stoi(value);
    else if (key == "report.auto_cleanup") global_.report.auto_cleanup = (value == "true" || value == "1");
    else if (key == "report.max_reports") global_.report.max_reports = std::stoi(value);
}

std::optional<std::string> Config::getValue(const std::string& key) const {
    auto it = raw_values_.find(key);
    if (it != raw_values_.end()) {
        return it->second;
    }
    
    if (key == "api_key") {
        return global_.api_key.empty() ? std::nullopt : std::optional<std::string>("****");
    }
    else if (key == "base_path") return global_.base_path;
    else if (key == "models_path") return global_.models_path;
    else if (key == "log_file") return global_.log_file;
    else if (key == "log_level") {
        switch (global_.log_level) {
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::WARN: return "WARN";
            case LogLevel::INFO: return "INFO";
            case LogLevel::DEBUG: return "DEBUG";
        }
        return "INFO";
    }
    else if (key == "network_timeout") return std::to_string(global_.network_timeout);
    else if (key == "auto_update") return global_.auto_update ? "true" : "false";
    else if (key == "update_interval_minutes") return std::to_string(global_.update_interval_minutes);
    else if (key == "max_scan_size_mb") return std::to_string(global_.max_scan_size_mb);
    else if (key == "scan_timeout_seconds") return std::to_string(global_.scan_timeout_seconds);
    else if (key == "max_recursion_depth") return std::to_string(global_.max_recursion_depth);
    else if (key == "scan.default_threads") return std::to_string(global_.scan.default_threads);
    else if (key == "scan.scan_batch_size") return std::to_string(global_.scan.scan_batch_size);
    else if (key == "daemon.socket_path") return global_.daemon.socket_path;
    else if (key == "daemon.http_port") return std::to_string(global_.daemon.http_port);
    else if (key == "daemon.http_host") return global_.daemon.http_host;
    else if (key == "daemon.user") return global_.daemon.user;
    else if (key == "daemon.group") return global_.daemon.group;
    else if (key == "daemon.max_connections") return std::to_string(global_.daemon.max_connections);
    else if (key == "daemon.max_queue") return std::to_string(global_.daemon.max_queue);
    else if (key == "daemon.read_timeout") return std::to_string(global_.daemon.read_timeout);
    else if (key == "daemon.worker_threads") return std::to_string(global_.daemon.worker_threads);
    else if (key == "daemon.socket_buffer_kb") return std::to_string(global_.daemon.socket_buffer_kb);
    else if (key == "daemon.connection_backlog") return std::to_string(global_.daemon.connection_backlog);
    else if (key == "logging.rotation_size_mb") return std::to_string(global_.logging.rotation_size_mb);
    else if (key == "logging.max_files") return std::to_string(global_.logging.max_files);
    else if (key == "logging.format") return global_.logging.format == LogFormat::JSON ? "json" : "text";
    else if (key == "report.enable_storage") return global_.report.enable_storage ? "true" : "false";
    else if (key == "report.reports_dir") return global_.report.reports_dir;
    else if (key == "report.retention_days") return std::to_string(global_.report.retention_days);
    else if (key == "report.auto_cleanup") return global_.report.auto_cleanup ? "true" : "false";
    else if (key == "report.max_reports") return std::to_string(global_.report.max_reports);
    
    return std::nullopt;
}

std::string Config::getConfigPath() const {
    if (!current_config_path_.empty()) {
        return current_config_path_;
    }
    return PathManager::instance().getConfigFile();
}

std::string Config::getPidFilePath() const {
    auto& path_manager = PathManager::instance();
    if (path_manager.isSystemMode()) {
        return "/var/run/semantics-av/semantics-av.pid";
    } else {
        return path_manager.getRuntimeDir() + "/semantics-av.pid";
    }
}

void Config::applyDefaults() {
    global_ = createDefaultConfig();
    
    auto& path_manager = PathManager::instance();
    
    global_.base_path = path_manager.getDataDir();
    global_.models_path = global_.base_path + "/models";
    global_.daemon.socket_path = path_manager.getSocketPath();
    
    if (path_manager.isSystemMode()) {
        global_.log_file = "/var/log/semantics-av/semantics-av.log";
        global_.daemon.http_host = constants::config_defaults::DAEMON_HTTP_HOST;
        global_.daemon.user = constants::system::DAEMON_USER;
        global_.daemon.group = constants::system::DAEMON_GROUP;
        global_.daemon.max_connections = constants::config_defaults::DAEMON_MAX_CONNECTIONS_SYSTEM;
        global_.daemon.max_queue = constants::config_defaults::DAEMON_MAX_QUEUE_SYSTEM;
    } else {
        global_.log_file = path_manager.getLogDir() + "/semantics-av.log";
        global_.daemon.http_host = constants::config_defaults::DAEMON_HTTP_HOST;
        global_.daemon.user = "";
        global_.daemon.group = "";
        global_.daemon.max_connections = constants::config_defaults::DAEMON_MAX_CONNECTIONS_USER;
        global_.daemon.max_queue = constants::config_defaults::DAEMON_MAX_QUEUE_USER;
    }
}

}}