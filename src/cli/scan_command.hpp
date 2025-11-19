#pragma once

#include "main_command.hpp"
#include "semantics_av/scan/scanner.hpp"
#include "semantics_av/daemon/client_pool.hpp"
#include "semantics_av/daemon/protocol.hpp"
#include <CLI/CLI.hpp>
#include <string>
#include <filesystem>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>

namespace semantics_av {
namespace cli {

class ScanCommand : public MainCommand {
public:
    ScanCommand();
    
    void setup(CLI::App* subcommand);
    bool wasCalled() const;
    int execute();

private:
    bool was_called_;
    std::string target_path_;
    bool recursive_ = false;
    int threads_ = 4;
    int max_file_size_ = 100;
    bool no_progress_ = false;
    bool json_output_ = false;
    bool quiet_ = false;
    bool no_daemon_ = false;
    bool infected_only_ = false;
    bool include_hashes_ = false;
    
    int executeWithDaemon(const std::filesystem::path& path);
    int executeStandalone(const std::filesystem::path& path);
    
    int scanFileWithDaemon(const std::filesystem::path& file_path);
    int scanDirectoryWithDaemon(const std::filesystem::path& directory);
    
    bool canAccessPath(const std::filesystem::path& path);
    std::vector<std::filesystem::path> collectFilesForDaemon(
        const std::filesystem::path& directory,
        const scan::ScanOptions& options,
        scan::ScanSummary& summary);
    
    bool shouldScanFile(const std::filesystem::path& file_path,
                        const scan::ScanOptions& options,
                        scan::ScanSummary& summary);
    bool matchesExcludePattern(const std::filesystem::path& file_path,
                               const std::vector<std::string>& patterns);
    
    void updateSummaryCounters(scan::ScanSummary& summary, const common::ScanMetadata& result);
    bool shouldPrintResult(const common::ScanMetadata& result) const;
    bool shouldPrintFileResult(const daemon::ScanFileComplete& result) const;
    bool shouldShowProgress() const;
    
    void printScanResultLine(const std::string& file_path, 
                            common::ScanResult result,
                            float confidence,
                            const std::string& file_type,
                            size_t file_size,
                            int64_t scan_time_ms,
                            size_t current = 0,
                            size_t total = 0) const;
    
    void updateProgress(size_t current, size_t total) const;
    void clearProgress() const;
    
    std::string formatBytes(size_t bytes) const;
    std::string getResultColor(common::ScanResult result) const;
    
    scan::ScanSummary buildArchiveSummary(
        const daemon::ScanResponse& response) const;
};

}}