#pragma once

#include <string>
#include <map>
#include <optional>
#include <cstdint>

namespace semantics_av {
namespace common {

enum class LogLevel {
    ERROR = 0,
    WARN = 1,
    INFO = 2,
    DEBUG = 3
};

enum class LogFormat {
    TEXT,
    JSON
};

struct ScanConfig {
    int default_threads;
    size_t scan_batch_size;
};

struct LoggingConfig {
    size_t rotation_size_mb;
    size_t max_files;
    LogFormat format;
};

struct DaemonConfig {
    std::string socket_path;
    uint16_t http_port;
    std::string http_host;
    std::string user;
    std::string group;
    int max_connections;
    int max_queue;
    int read_timeout;
    int worker_threads;
    size_t socket_buffer_kb;
    int connection_backlog;
};

struct ReportConfig {
    bool enable_storage;
    std::string reports_dir;
    int retention_days;
    bool auto_cleanup;
    int max_reports;
};

struct GlobalConfig {
    std::string base_path;
    std::string models_path;
    std::string log_file;
    LogLevel log_level;
    std::string api_key;
    int network_timeout;
    bool auto_update;
    int update_interval_minutes;
    int max_scan_size_mb;
    int scan_timeout_seconds;
    int max_recursion_depth;
    DaemonConfig daemon;
    ScanConfig scan;
    LoggingConfig logging;
    ReportConfig report;
};

class Config {
public:
    static Config& instance();
    
    bool load(const std::string& config_file = "");
    bool save(const std::string& config_file = "");
    bool exists() const;
    
    const GlobalConfig& global() const { return global_; }
    GlobalConfig& global() { return global_; }
    
    void setValue(const std::string& key, const std::string& value);
    std::optional<std::string> getValue(const std::string& key) const;
    
    bool updateApiKey(const std::string& api_key);
    
    std::string getConfigPath() const;
    std::string getPidFilePath() const;

private:
    Config() = default;
    GlobalConfig global_;
    std::map<std::string, std::string> raw_values_;
    std::string current_config_path_;
    
    void applyDefaults();
    bool tryLoadCredentials(const std::string& path);
    bool tryLoadTomlFile(const std::string& path, const std::string& description);
    bool saveApiKeyToFile(const std::string& api_key, const std::string& file_path, bool is_system);
};

}}