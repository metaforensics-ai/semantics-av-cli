#include "semantics_av/common/logger.hpp"
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <iostream>
#include <filesystem>
#include <cstdlib>

namespace semantics_av {
namespace common {

static bool isRunningInContainer() {
    if (std::getenv("SEMANTICS_AV_CONTAINER")) {
        return true;
    }
    
    if (std::filesystem::exists("/.dockerenv")) {
        return true;
    }
    
    if (std::getenv("KUBERNETES_SERVICE_HOST")) {
        return true;
    }
    
    return false;
}

Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

void Logger::initialize(LogMode mode, const std::string& log_file, LogLevel level, const LoggingConfig& logging_config) {
    if (initialized_) {
        if (logger_) {
            logger_->warn("[Logger] Already initialized, ignoring duplicate initialization");
        }
        return;
    }

    if (logger_) {
        spdlog::drop("semantics-av");
        logger_.reset();
    }

    try {
        auto spdlog_level = toSpdlogLevel(level);
        std::vector<spdlog::sink_ptr> sinks;
        
        LogMode effective_mode = mode;
        if (isRunningInContainer() && mode == LogMode::FILE_ONLY) {
            effective_mode = LogMode::CONSOLE_ONLY;
        }
        
        if (effective_mode == LogMode::FILE_ONLY) {
            if (log_file.empty()) {
                throw std::runtime_error("Log file path required for FILE_ONLY mode");
            }
            
            std::filesystem::path log_path(log_file);
            std::filesystem::path log_dir = log_path.parent_path();
            
            std::error_code ec;
            if (!std::filesystem::exists(log_dir, ec)) {
                if (!std::filesystem::create_directories(log_dir, ec)) {
                    std::cerr << "[Logger] Failed to create log directory: " << log_dir 
                             << " - " << ec.message() << std::endl;
                    std::cerr << "[Logger] Falling back to console output" << std::endl;
                    auto console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
                    console_sink->set_level(spdlog_level);
                    sinks.push_back(console_sink);
                    goto create_logger;
                }
            }
            
            try {
                std::string effective_log_file = getLogFileWithSuffix(logging_config.format, log_file);
                
                size_t max_size = logging_config.rotation_size_mb * 1024 * 1024;
                size_t max_files = logging_config.max_files;
                
                auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                    effective_log_file, max_size, max_files);
                file_sink->set_level(spdlog_level);
                sinks.push_back(file_sink);
                
                current_format_ = logging_config.format;
                
            } catch (const spdlog::spdlog_ex& ex) {
                std::cerr << "[Logger] Failed to open log file: " << log_file 
                         << " - " << ex.what() << std::endl;
                std::cerr << "[Logger] Falling back to console output" << std::endl;
                auto console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
                console_sink->set_level(spdlog_level);
                sinks.push_back(console_sink);
            }
        } else {
            auto console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
            console_sink->set_level(spdlog_level);
            sinks.push_back(console_sink);
        }
        
create_logger:
        logger_ = std::make_shared<spdlog::logger>("semantics-av", sinks.begin(), sinks.end());
        
        if (current_format_ == LogFormat::JSON) {
            logger_->set_pattern(R"({"timestamp":"%Y-%m-%dT%H:%M:%S.%e","level":"%l","message":"%v"})");
        } else {
            logger_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
        }
        
        logger_->set_level(spdlog_level);
        
        if (effective_mode == LogMode::FILE_ONLY) {
            logger_->flush_on(spdlog::level::info);
            spdlog::flush_every(std::chrono::seconds(3));
        }
        
        spdlog::register_logger(logger_);
        initialized_ = true;
        
    } catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "[Logger] Initialization failed: " << ex.what() << std::endl;
        auto console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
        logger_ = std::make_shared<spdlog::logger>("semantics-av", console_sink);
        logger_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
        logger_->set_level(toSpdlogLevel(level));
        spdlog::register_logger(logger_);
        initialized_ = true;
    }
}

void Logger::setLevel(LogLevel level) {
    if (logger_) {
        logger_->set_level(toSpdlogLevel(level));
    }
}

void Logger::shutdown() {
    if (logger_) {
        logger_->flush();
        spdlog::drop("semantics-av");
        logger_.reset();
    }
    spdlog::shutdown();
    initialized_ = false;
}

void Logger::flush() {
    if (logger_) {
        logger_->flush();
    }
}

semantics_av::LogCallback Logger::getLibraryCallback() {
    return &Logger::libraryLogCallback;
}

void Logger::handleLibraryLog(semantics_av::LogLevel level, const std::string& message, const std::string& context) {
    if (!logger_) return;
    
    std::string formatted_message = context.empty() 
        ? fmt::format("[Core] {}", message)
        : fmt::format("[Core:{}] {}", context, message);
    
    switch (level) {
        case semantics_av::LogLevel::ERROR:
            logger_->error(formatted_message);
            break;
        case semantics_av::LogLevel::WARN:
            logger_->warn(formatted_message);
            break;
        case semantics_av::LogLevel::INFO:
            logger_->info(formatted_message);
            break;
        case semantics_av::LogLevel::DEBUG:
            logger_->debug(formatted_message);
            break;
    }
}

void Logger::libraryLogCallback(semantics_av::LogLevel level, const std::string& message, const std::string& context) {
    Logger::instance().handleLibraryLog(level, message, context);
}

spdlog::level::level_enum Logger::toSpdlogLevel(LogLevel level) {
    switch (level) {
        case LogLevel::ERROR: return spdlog::level::err;
        case LogLevel::WARN: return spdlog::level::warn;
        case LogLevel::INFO: return spdlog::level::info;
        case LogLevel::DEBUG: return spdlog::level::debug;
        default: return spdlog::level::info;
    }
}

std::string Logger::getLogFileWithSuffix(LogFormat format, const std::string& base_path) const {
    if (format == LogFormat::JSON) {
        std::filesystem::path p(base_path);
        std::string stem = p.stem().string();
        std::string ext = p.extension().string();
        std::string parent = p.parent_path().string();
        
        if (parent.empty()) {
            return stem + ".json" + ext;
        } else {
            return parent + "/" + stem + ".json" + ext;
        }
    }
    return base_path;
}

}}