#pragma once

#include "config.hpp"
#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>
#include <semantics_av/logging.hpp>
#include <memory>
#include <string>
#include <chrono>

namespace semantics_av {
namespace common {

enum class LogMode {
    CONSOLE_ONLY,
    FILE_ONLY
};

class Logger {
public:
    static Logger& instance();
    
    void initialize(LogMode mode, const std::string& log_file, LogLevel level, const LoggingConfig& logging_config);
    void setLevel(LogLevel level);
    void shutdown();
    
    template<typename... Args>
    void error(const std::string& format, Args&&... args) {
        if (logger_) logger_->error(fmt::runtime(format), std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void warn(const std::string& format, Args&&... args) {
        if (logger_) logger_->warn(fmt::runtime(format), std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void info(const std::string& format, Args&&... args) {
        if (logger_) logger_->info(fmt::runtime(format), std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void debug(const std::string& format, Args&&... args) {
        if (logger_) logger_->debug(fmt::runtime(format), std::forward<Args>(args)...);
    }
    
    void flush();
    
    semantics_av::LogCallback getLibraryCallback();
    
    bool isInitialized() const { return initialized_; }

private:
    Logger() = default;
    std::shared_ptr<spdlog::logger> logger_;
    bool initialized_ = false;
    LogFormat current_format_ = LogFormat::TEXT;
    
    spdlog::level::level_enum toSpdlogLevel(LogLevel level);
    void handleLibraryLog(semantics_av::LogLevel level, const std::string& message, const std::string& context);
    std::string getLogFileWithSuffix(LogFormat format, const std::string& base_path) const;
    
    static void libraryLogCallback(semantics_av::LogLevel level, const std::string& message, const std::string& context);
};

inline std::string formatDuration(std::chrono::milliseconds ms) {
    return std::to_string(ms.count());
}

inline std::string formatBytes(size_t bytes) {
    if (bytes < 1024) return std::to_string(bytes);
    if (bytes < 1024 * 1024) return fmt::format("{:.1f}K", bytes / 1024.0);
    if (bytes < 1024 * 1024 * 1024) return fmt::format("{:.1f}M", bytes / (1024.0 * 1024.0));
    return fmt::format("{:.1f}G", bytes / (1024.0 * 1024.0 * 1024.0));
}

}}