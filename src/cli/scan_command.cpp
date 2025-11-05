#include "scan_command.hpp"
#include "semantics_av/common/config.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/paths.hpp"
#include "semantics_av/common/diagnostics.hpp"
#include "semantics_av/core/engine.hpp"
#include "semantics_av/scan/scanner.hpp"
#include "semantics_av/scan/result_formatter.hpp"
#include "semantics_av/daemon/client.hpp"
#include <tbb/parallel_for.h>
#include <tbb/concurrent_queue.h>
#include <iostream>
#include <atomic>
#include <mutex>
#include <unistd.h>
#include <regex>

namespace semantics_av {
namespace cli {

ScanCommand::ScanCommand() : was_called_(false) {}

void ScanCommand::setup(CLI::App* subcommand) {
    subcommand_ = subcommand;
    
    subcommand->add_option("target", target_path_, "File or directory to scan")
               ->required();
    
    subcommand->add_flag("-r,--recursive", recursive_, 
                        "Recursive directory scan");
    subcommand->add_option("-t,--threads", threads_, 
                          "Number of threads")
                          ->check(CLI::Range(1, 32));
    subcommand->add_option("-m,--max-size", max_file_size_, 
                          "Maximum file size in MB (default: from config)")
                          ->check(CLI::Range(1, 2048));
    subcommand->add_flag("-p,--no-progress", no_progress_, 
                        "Disable progress indicator");
    subcommand->add_flag("--json", json_output_,
                        "Output as JSON");
    subcommand->add_flag("-q,--quiet", quiet_, 
                        "Quiet mode");
    subcommand->add_flag("-i,--infected", infected_only_,
                        "Show only infected (malicious) and error files");
    subcommand->add_flag("-n,--no-daemon", no_daemon_,
                        "Force standalone mode");
    subcommand->add_flag("-H,--include-hashes", include_hashes_,
                        "Include file hashes in output");
    
    subcommand->callback([this]() { was_called_ = true; });
}

bool ScanCommand::wasCalled() const {
    return was_called_;
}

bool ScanCommand::canAccessPath(const std::filesystem::path& path) {
    std::error_code ec;
    auto status = std::filesystem::status(path, ec);
    if (ec) {
        return false;
    }
    return access(path.c_str(), R_OK) == 0;
}

int ScanCommand::execute() {
    auto& config = common::Config::instance().global();
    
    if (threads_ <= 0) {
        threads_ = config.scan.default_threads;
    }
    
    if (max_file_size_ <= 0) {
        max_file_size_ = config.max_scan_size_mb;
    }
    
    target_path_ = std::filesystem::absolute(target_path_).string();
    std::filesystem::path target(target_path_);
    
    if (!std::filesystem::exists(target)) {
        std::cerr << "Error: Path not found: " << target_path_ << std::endl;
        return 1;
    }
    
    bool is_directory = std::filesystem::is_directory(target);
    bool use_daemon = !no_daemon_ && daemon::DaemonClient::isDaemonRunning();
    
    if (use_daemon && is_directory) {
        daemon::DaemonClient client;
        if (client.connect()) {
            if (!client.isUnixSocket()) {
                std::cerr << "Directory scan requires Unix socket (file descriptor passing).\n";
                std::cerr << "Falling back to standalone mode.\n\n";
                return executeStandalone(target);
            }
            
            return executeWithDaemon(target);
        }
        return executeStandalone(target);
    }
    
    if (use_daemon) {
        return executeWithDaemon(target);
    }
    
    if (!canAccessPath(target)) {
        std::cerr << "Error: Permission denied: " << target_path_ << std::endl;
        std::cerr << "\n\033[1mOptions:\033[0m\n\n";
        std::cerr << "  \033[1m1. Start daemon (recommended):\033[0m\n";
        std::cerr << "     sudo systemctl start semantics-av\n";
        std::cerr << "     semantics-av scan " << target_path_;
        if (recursive_) std::cerr << " -r";
        std::cerr << "\n\n";
        std::cerr << "  \033[1m2. Run with sudo:\033[0m\n";
        std::cerr << "     sudo semantics-av scan " << target_path_;
        if (recursive_) std::cerr << " -r";
        std::cerr << "\n\n";
        std::cerr << "  Daemon handles permissions automatically.\n";
        return 1;
    }
    
    return executeStandalone(target);
}

int ScanCommand::executeWithDaemon(const std::filesystem::path& path) {
    if (std::filesystem::is_regular_file(path)) {
        return scanFileWithDaemon(path);
    } else if (std::filesystem::is_directory(path)) {
        return scanDirectoryWithDaemon(path);
    }
    
    std::cerr << "Error: Invalid path type: " << target_path_ << std::endl;
    return 1;
}

int ScanCommand::scanFileWithDaemon(const std::filesystem::path& file_path) {
    daemon::DaemonClient client;
    if (!client.connect()) {
        std::cerr << "Error: Failed to connect to daemon\n\n";
        std::cerr << "\033[1mTroubleshooting:\033[0m\n";
        std::cerr << "  1. Check daemon status:\n";
        std::cerr << "     systemctl status semantics-av\n\n";
        std::cerr << "  2. Start daemon:\n";
        std::cerr << "     sudo systemctl start semantics-av\n\n";
        std::cerr << "  3. View daemon logs:\n";
        std::cerr << "     tail -f " << common::Config::instance().global().log_file << "\n";
        return 1;
    }
    
    auto response = client.scan(file_path.string(), include_hashes_);
    
    if (!response) {
        std::cerr << "Error: Daemon scan failed\n\n";
        std::cerr << "\033[1mFor detailed error information:\033[0m\n";
        std::cerr << "  " << common::Config::instance().global().log_file << "\n\n";
        std::cerr << "View in real-time:\n";
        std::cerr << "  tail -f " << common::Config::instance().global().log_file << "\n";
        return 1;
    }
    
    common::ScanMetadata metadata;
    metadata.file_path = file_path.string();
    metadata.result = response->result;
    metadata.confidence = response->confidence;
    metadata.file_type = response->file_type;
    metadata.file_size = response->file_size;
    metadata.scan_time = std::chrono::milliseconds(response->scan_time_ms);
    if (!response->file_hashes.empty()) {
        metadata.file_hashes = response->file_hashes;
    }
    
    if (shouldPrintResult(metadata)) {
        if (json_output_) {
            scan::ResultFormatter formatter(scan::OutputFormat::JSON);
            formatter.formatScanResult(metadata, std::cout);
        } else {
            printScanResultLine(file_path.string(), 
                              response->result, 
                              response->confidence,
                              response->file_type,
                              response->file_size,
                              response->scan_time_ms);
        }
    }
    
    return (response->result == common::ScanResult::MALICIOUS) ? 1 : 0;
}

int ScanCommand::scanDirectoryWithDaemon(const std::filesystem::path& directory) {
    daemon::DaemonClient client;
    if (!client.connect()) {
        std::cerr << "Error: Failed to connect to daemon\n\n";
        std::cerr << "\033[1mTroubleshooting:\033[0m\n";
        std::cerr << "  1. Check daemon status:\n";
        std::cerr << "     systemctl status semantics-av\n\n";
        std::cerr << "  2. Start daemon:\n";
        std::cerr << "     sudo systemctl start semantics-av\n\n";
        std::cerr << "  3. View daemon logs:\n";
        std::cerr << "     tail -f " << common::Config::instance().global().log_file << "\n";
        return 1;
    }
    
    if (!client.isUnixSocket()) {
        std::cerr << "Error: Directory scan requires Unix socket connection\n";
        return 1;
    }
    
    auto& config = common::Config::instance().global();
    
    scan::ScanOptions options;
    options.recursive = recursive_;
    options.follow_symlinks = false;
    options.max_threads = threads_;
    options.max_file_size = max_file_size_ * 1024 * 1024;
    options.max_recursion_depth = config.max_recursion_depth;
    options.show_progress = false;
    
    scan::ScanSummary summary;
    auto files = collectFilesForDaemon(directory, options, summary);
    
    if (files.empty()) {
        if (summary.permission_denied_files > 0) {
            std::cerr << "\nNo accessible files found in: " << directory << "\n\n";
        } else {
            std::cout << "No files found to scan in: " << directory << std::endl;
        }
        
        scan::OutputFormat format = json_output_ ? scan::OutputFormat::JSON : scan::OutputFormat::TEXT;
        scan::ResultFormatter formatter(format);
        formatter.setColorsEnabled(!quiet_ && isatty(STDOUT_FILENO));
        formatter.formatScanSummary(summary, std::cout);
        
        return summary.permission_denied_files > 0 ? 1 : 0;
    }
    
    daemon::ScanDirectoryInit init;
    init.total_files = files.size();
    init.total_batches = (files.size() + config.scan.scan_batch_size - 1) / config.scan.scan_batch_size;
    init.recursive = recursive_;
    init.max_file_size = max_file_size_ * 1024 * 1024;
    init.max_threads = threads_;
    init.infected_only = infected_only_;
    init.include_hashes = include_hashes_;
    
    std::cout.setf(std::ios::unitbuf);
    
    auto response = client.scanDirectoryWithFds(init, files, config.scan.scan_batch_size,
        [this](const daemon::ScanFileComplete& file_result) {
            if (!quiet_ && shouldShowProgress()) {
                updateProgress(file_result.current_file, file_result.total_files);
            }
            
            if (shouldPrintFileResult(file_result)) {
                clearProgress();
                printScanResultLine(file_result.file_path,
                                  file_result.result,
                                  file_result.confidence,
                                  file_result.file_type,
                                  file_result.file_size,
                                  file_result.scan_time_ms,
                                  file_result.current_file,
                                  file_result.total_files);
            }
        });
    
    clearProgress();
    
    if (!response) {
        std::cerr << "Error: Directory scan failed\n\n";
        std::cerr << "\033[1mFor detailed error information:\033[0m\n";
        std::cerr << "  " << common::Config::instance().global().log_file << "\n\n";
        std::cerr << "View in real-time:\n";
        std::cerr << "  tail -f " << common::Config::instance().global().log_file << "\n";
        return 1;
    }
    
    scan::OutputFormat format = json_output_ ? scan::OutputFormat::JSON : scan::OutputFormat::TEXT;
    scan::ResultFormatter formatter(format);
    formatter.setColorsEnabled(!quiet_ && isatty(STDOUT_FILENO));
    
    summary.total_files = response->total_files;
    summary.clean_files = response->clean_files;
    summary.malicious_files = response->malicious_files;
    summary.unsupported_files = response->unsupported_files;
    summary.error_files = response->error_files;
    summary.total_time = std::chrono::milliseconds(response->total_time_ms);
    summary.results = response->results;
    
    formatter.formatScanSummary(summary, std::cout);
    
    return (response->malicious_files > 0) ? 1 : 0;
}

bool ScanCommand::shouldScanFile(const std::filesystem::path& file_path,
                                  const scan::ScanOptions& options,
                                  scan::ScanSummary& summary) {
    std::error_code ec;
    
    if (std::filesystem::is_symlink(file_path, ec)) {
        summary.unsupported_files++;
        return false;
    }
    
    if (!std::filesystem::is_regular_file(file_path, ec)) {
        if (ec && (ec.value() == EACCES || ec.value() == EPERM)) {
            summary.permission_denied_files++;
        }
        return false;
    }
    
    auto file_size = std::filesystem::file_size(file_path, ec);
    if (ec) {
        if (ec.value() == EACCES || ec.value() == EPERM) {
            summary.permission_denied_files++;
        }
        return false;
    }
    
    if (file_size == 0) {
        return false;
    }
    
    if (file_size > options.max_file_size) {
        summary.size_exceeded_files++;
        return false;
    }
    
    if (matchesExcludePattern(file_path, options.exclude_patterns)) {
        return false;
    }
    
    return true;
}

bool ScanCommand::matchesExcludePattern(const std::filesystem::path& file_path,
                                         const std::vector<std::string>& patterns) {
    if (patterns.empty()) {
        return false;
    }
    
    std::string path_str = file_path.string();
    
    for (const auto& pattern : patterns) {
        try {
            std::regex regex_pattern(pattern);
            if (std::regex_search(path_str, regex_pattern)) {
                return true;
            }
        } catch (const std::exception& e) {
            common::Logger::instance().warn("Invalid exclude pattern: {}", pattern);
        }
    }
    
    return false;
}

std::vector<std::filesystem::path> ScanCommand::collectFilesForDaemon(
    const std::filesystem::path& directory,
    const scan::ScanOptions& options,
    scan::ScanSummary& summary)
{
    std::vector<std::filesystem::path> files;
    
    std::function<void(const std::filesystem::path&, int)> collect_recursive;
    collect_recursive = [&](const std::filesystem::path& dir, int depth) {
        if (depth > options.max_recursion_depth) {
            summary.depth_exceeded_files++;
            return;
        }
        
        std::error_code ec;
        for (auto it = std::filesystem::directory_iterator(dir, ec);
             it != std::filesystem::directory_iterator();
             it.increment(ec)) {
            
            if (ec) {
                if (ec.value() == EACCES || ec.value() == EPERM) {
                    summary.permission_denied_files++;
                }
                ec.clear();
                continue;
            }
            
            if (std::filesystem::is_symlink(it->path(), ec)) {
                if (std::filesystem::is_directory(it->path(), ec)) {
                    continue;
                }
                summary.total_files_found++;
                summary.unsupported_files++;
                continue;
            }
            
            if (std::filesystem::is_directory(it->path(), ec) && options.recursive) {
                collect_recursive(it->path(), depth + 1);
            } else if (std::filesystem::is_regular_file(it->path(), ec)) {
                summary.total_files_found++;
                
                if (shouldScanFile(it->path(), options, summary)) {
                    files.push_back(it->path());
                }
            }
        }
    };
    
    collect_recursive(directory, 0);
    std::sort(files.begin(), files.end());
    return files;
}

int ScanCommand::executeStandalone(const std::filesystem::path& path) {
    auto& config = common::Config::instance().global();
    auto& path_manager = common::PathManager::instance();
    
    if (!diagnostics::hasModelFiles(config.models_path)) {
        diagnostics::printUpdateGuide(path_manager.isSystemMode(), config.models_path);
        return 1;
    }
    
    core::SemanticsAVEngine engine;
    if (!engine.initialize(config.base_path, config.api_key)) {
        std::cerr << "Error: Failed to initialize scan engine" << std::endl;
        
        if (!diagnostics::hasModelFiles(config.models_path)) {
            diagnostics::printUpdateGuide(path_manager.isSystemMode(), config.models_path);
        }
        
        return 1;
    }
    
    scan::Scanner scanner(&engine);
    
    scan::OutputFormat format = json_output_ ? scan::OutputFormat::JSON : scan::OutputFormat::TEXT;
    scan::ResultFormatter formatter(format);
    formatter.setColorsEnabled(!quiet_ && isatty(STDOUT_FILENO));
    
    if (std::filesystem::is_regular_file(path)) {
        auto result = scanner.scan(path, include_hashes_);
        
        if (shouldPrintResult(result)) {
            if (json_output_) {
                formatter.formatScanResult(result, std::cout);
            } else {
                printScanResultLine(path.string(),
                                  result.result,
                                  result.confidence,
                                  result.file_type,
                                  result.file_size,
                                  result.scan_time.count());
            }
        }
        
        return (result.result == common::ScanResult::MALICIOUS) ? 1 : 0;
    }
    
    scan::ScanOptions options;
    options.recursive = recursive_;
    options.follow_symlinks = false;
    options.max_threads = threads_;
    options.max_file_size = max_file_size_ * 1024 * 1024;
    options.max_recursion_depth = config.max_recursion_depth;
    options.show_progress = false;
    options.include_hashes = include_hashes_;
    
    std::cout.setf(std::ios::unitbuf);
    
    std::mutex output_mutex;
    
    scanner.setResultCallback([this, &output_mutex](const common::ScanMetadata& result, size_t current, size_t total) {
        std::lock_guard<std::mutex> lock(output_mutex);
        
        if (shouldPrintResult(result)) {
            printScanResultLine(result.file_path,
                              result.result,
                              result.confidence,
                              result.file_type,
                              result.file_size,
                              result.scan_time.count(),
                              current,
                              total);
        } else {
            updateProgress(current, total);
        }
    });
    
    auto summary = scanner.scanDirectory(path, options);
    
    clearProgress();
    
    formatter.formatScanSummary(summary, std::cout);
    
    return (summary.malicious_files > 0) ? 1 : 0;
}

bool ScanCommand::shouldPrintResult(const common::ScanMetadata& result) const {
    if (quiet_) {
        return false;
    }
    
    if (!infected_only_) {
        return true;
    }
    
    return result.result == common::ScanResult::MALICIOUS || 
           result.result == common::ScanResult::ERROR;
}

bool ScanCommand::shouldPrintFileResult(const daemon::ScanFileComplete& result) const {
    if (quiet_) {
        return false;
    }
    
    if (!infected_only_) {
        return true;
    }
    
    return result.result == common::ScanResult::MALICIOUS || 
           result.result == common::ScanResult::ERROR;
}

bool ScanCommand::shouldShowProgress() const {
    if (quiet_ || no_progress_ || json_output_) {
        return false;
    }
    
    return isatty(STDOUT_FILENO);
}

void ScanCommand::updateProgress(size_t current, size_t total) const {
    if (!shouldShowProgress()) {
        return;
    }
    
    std::cout << "\rScanning: " << current << "/" << total << std::flush;
}

void ScanCommand::clearProgress() const {
    if (!shouldShowProgress()) {
        return;
    }
    
    std::cout << "\r\033[K" << std::flush;
}

void ScanCommand::printScanResultLine(const std::string& file_path,
                                     common::ScanResult result,
                                     float confidence,
                                     const std::string& file_type,
                                     size_t file_size,
                                     int64_t scan_time_ms,
                                     size_t current,
                                     size_t total) const {
    if (json_output_) {
        return;
    }
    
    clearProgress();
    
    if (current > 0 && total > 0) {
        std::cout << "(" << current << "/" << total << ") ";
    }
    
    std::cout << file_path << ": ";
    
    std::string color = getResultColor(result);
    std::string result_str = common::to_string(result);
    
    if (!color.empty() && isatty(STDOUT_FILENO)) {
        std::cout << color << result_str << "\033[0m";
    } else {
        std::cout << result_str;
    }
    
    if (result != common::ScanResult::UNSUPPORTED && 
        result != common::ScanResult::ERROR) {
        std::cout << " (confidence: " << std::fixed << std::setprecision(1) 
                 << (confidence * 100) << "%)";
    }
    
    std::cout << " [";
    
    if (result != common::ScanResult::UNSUPPORTED && 
        result != common::ScanResult::ERROR) {
        std::cout << file_type << ", ";
    } else {
        if (!file_type.empty() && file_type != "unknown") {
            std::cout << file_type << ", ";
        }
    }
    
    std::cout << formatBytes(file_size);
    
    if (scan_time_ms > 0) {
        std::cout << ", " << scan_time_ms << "ms";
    }
    
    std::cout << "]" << std::endl;
}

void ScanCommand::updateSummaryCounters(scan::ScanSummary& summary, const common::ScanMetadata& result) {
    switch (result.result) {
        case common::ScanResult::CLEAN:
            summary.clean_files++;
            break;
        case common::ScanResult::MALICIOUS:
            summary.malicious_files++;
            break;
        case common::ScanResult::UNSUPPORTED:
            summary.unsupported_files++;
            break;
        case common::ScanResult::ERROR:
            summary.error_files++;
            break;
    }
}

std::string ScanCommand::formatBytes(size_t bytes) const {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit < 3) {
        size /= 1024.0;
        unit++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << size << units[unit];
    return oss.str();
}

std::string ScanCommand::getResultColor(common::ScanResult result) const {
    switch (result) {
        case common::ScanResult::CLEAN:
            return "\033[32m";
        case common::ScanResult::MALICIOUS:
            return "\033[31m";
        case common::ScanResult::UNSUPPORTED:
            return "\033[36m";
        case common::ScanResult::ERROR:
            return "\033[31m";
        default:
            return "";
    }
}

}}