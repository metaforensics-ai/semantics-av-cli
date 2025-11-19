#pragma once

#include "../common/types.hpp"
#include "../core/engine.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <istream>

struct archive;

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
    
    bool scan_archives = true;
    size_t max_archive_extracted_size = 100 * 1024 * 1024;
    size_t max_archive_file_count = 10000;
    int max_archive_recursion_depth = 3;
    int max_compression_ratio = 250;
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
    size_t archive_errors = 0;
    size_t encrypted_files = 0;
    size_t compression_ratio_exceeded = 0;
    size_t empty_files = 0;
    size_t excluded_by_pattern = 0;
    std::chrono::milliseconds total_time{0};
    std::vector<common::ScanMetadata> results;
};

struct ArchiveVerdict {
    common::ScanResult result;
    float confidence;
};

ArchiveVerdict calculateArchiveVerdict(const std::vector<common::ScanMetadata>& results);

class Scanner {
public:
    explicit Scanner(core::SemanticsAVEngine* engine);
    ~Scanner();
    
    common::ScanMetadata scan(const std::filesystem::path& file_path, bool include_hashes = false);
    common::ScanMetadata scan(const std::vector<uint8_t>& data, bool include_hashes = false);
    common::ScanMetadata scan(std::istream& stream, bool include_hashes = false);
    ScanSummary scanDirectory(const std::filesystem::path& directory, 
                               const ScanOptions& options);
    
    bool isArchive(const std::filesystem::path& path);
    bool isArchive(const std::vector<uint8_t>& data);
    
    ScanSummary scanArchive(const std::filesystem::path& path, 
                           const ScanOptions& options);
    ScanSummary scanArchive(const std::vector<uint8_t>& data,
                           const std::string& archive_name,
                           size_t archive_size,
                           const ScanOptions& options);
    
    void setProgressCallback(std::function<void(size_t, size_t)> callback);
    void setResultCallback(std::function<void(const common::ScanMetadata&, size_t, size_t)> callback);

private:
    core::SemanticsAVEngine* engine_;
    std::function<void(size_t, size_t)> progress_callback_;
    std::function<void(const common::ScanMetadata&, size_t, size_t)> result_callback_;
    
    void configureArchiveFormats(archive* a);
    
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
    
    ScanSummary scanArchiveInternal(struct archive* a,
                                    const std::string& archive_path,
                                    const ScanOptions& options,
                                    int current_depth,
                                    size_t archive_size,
                                    size_t total_expected = 0);
    struct archive* createArchiveFromMemory(const std::vector<uint8_t>& data);
    void mergeSummaries(ScanSummary& target, const ScanSummary& source);
    bool isEncryptionError(const char* error_string);
};

}}