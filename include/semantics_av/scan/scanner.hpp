#pragma once

#include "../common/types.hpp"
#include "../core/engine.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <istream>

namespace semantics_av {
namespace scan {

struct ScanOptions {
    bool recursive = false;
    bool follow_symlinks = false;
    int max_threads = 4;
    size_t max_file_size = 100 * 1024 * 1024;
    int max_recursion_depth = 50;
    bool show_progress = false;
    bool include_hashes = false;
    std::vector<std::string> exclude_patterns;
};

struct ScanSummary {
    size_t total_files_found = 0;
    size_t total_files = 0;
    size_t clean_files = 0;
    size_t malicious_files = 0;
    size_t unsupported_files = 0;
    size_t error_files = 0;
    size_t permission_denied_files = 0;
    size_t size_exceeded_files = 0;
    size_t depth_exceeded_files = 0;
    std::chrono::milliseconds total_time{0};
    std::vector<common::ScanMetadata> results;
};

class Scanner {
public:
    explicit Scanner(core::SemanticsAVEngine* engine);
    ~Scanner();
    
    common::ScanMetadata scan(const std::filesystem::path& file_path, bool include_hashes = false);
    common::ScanMetadata scan(const std::vector<uint8_t>& data, bool include_hashes = false);
    common::ScanMetadata scan(std::istream& stream, bool include_hashes = false);
    ScanSummary scanDirectory(const std::filesystem::path& directory, 
                               const ScanOptions& options);
    
    void setProgressCallback(std::function<void(size_t, size_t)> callback);
    void setResultCallback(std::function<void(const common::ScanMetadata&, size_t, size_t)> callback);

private:
    core::SemanticsAVEngine* engine_;
    std::function<void(size_t, size_t)> progress_callback_;
    std::function<void(const common::ScanMetadata&, size_t, size_t)> result_callback_;
    
    bool shouldScanFile(const std::filesystem::path& file_path, 
                        const ScanOptions& options,
                        ScanSummary& summary);
    bool matchesExcludePattern(const std::filesystem::path& file_path,
                               const std::vector<std::string>& patterns);
    std::vector<std::filesystem::path> collectFiles(const std::filesystem::path& directory,
                                                     const ScanOptions& options,
                                                     ScanSummary& summary,
                                                     int current_depth = 0);
    void updateSummaryCounters(ScanSummary& summary, const common::ScanMetadata& result);
};

}}