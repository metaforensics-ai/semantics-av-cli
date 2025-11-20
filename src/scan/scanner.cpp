#include "semantics_av/scan/scanner.hpp"
#include "semantics_av/core/error_codes.hpp"
#include "semantics_av/common/error_framework.hpp"
#include "semantics_av/common/logger.hpp"
#include <archive.h>
#include <archive_entry.h>
#include <algorithm>
#include <regex>
#include <tbb/parallel_for.h>
#include <tbb/parallel_invoke.h>
#include <tbb/concurrent_queue.h>
#include <atomic>
#include <unistd.h>
#include <cstring>
#include <fstream>

namespace semantics_av {
namespace scan {

namespace {

constexpr size_t HEADER_CHECK_SIZE = 64;

static bool isELF(const std::vector<uint8_t>& data) {
    return data.size() >= 4 &&
           data[0] == 0x7F &&
           data[1] == 'E' &&
           data[2] == 'L' &&
           data[3] == 'F';
}

static bool isPE(const std::vector<uint8_t>& data) {
    return data.size() >= 2 &&
           data[0] == 'M' &&
           data[1] == 'Z';
}

static bool isKnownExecutableFormat(const std::vector<uint8_t>& data) {
    return isELF(data) || isPE(data);
}

static std::vector<uint8_t> readFileHeader(const std::filesystem::path& path, size_t bytes) {
    std::vector<uint8_t> header;
    
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return header;
    }
    
    header.resize(bytes);
    file.read(reinterpret_cast<char*>(header.data()), bytes);
    
    if (file.gcount() > 0) {
        header.resize(file.gcount());
    } else {
        header.clear();
    }
    
    return header;
}

static bool hasValidArchiveEntry(struct archive* a) {
    struct archive_entry* entry;
    int r = archive_read_next_header(a, &entry);
    return (r == ARCHIVE_OK);
}

}

ArchiveVerdict calculateArchiveVerdict(const std::vector<common::ScanMetadata>& results) {
    if (results.empty()) {
        return {common::ScanResult::ERROR, 0.0f};
    }
    
    float max_malicious = 0.0f;
    bool has_malicious = false;
    
    bool has_unsupported = false;
    
    float min_clean = 1.0f;
    bool has_clean = false;
    
    for (const auto& r : results) {
        if (r.result == common::ScanResult::MALICIOUS) {
            has_malicious = true;
            max_malicious = std::max(max_malicious, r.confidence);
        } else if (r.result == common::ScanResult::UNSUPPORTED) {
            has_unsupported = true;
        } else if (r.result == common::ScanResult::CLEAN) {
            has_clean = true;
            min_clean = std::min(min_clean, r.confidence);
        }
    }
    
    if (has_malicious) {
        return {common::ScanResult::MALICIOUS, max_malicious};
    }
    if (has_unsupported) {
        return {common::ScanResult::UNSUPPORTED, 0.0f};
    }
    if (has_clean) {
        return {common::ScanResult::CLEAN, min_clean};
    }
    
    return {common::ScanResult::ERROR, 0.0f};
}

Scanner::Scanner(core::SemanticsAVEngine* engine) : engine_(engine) {}

Scanner::~Scanner() = default;

void Scanner::configureArchiveFormats(archive* a) {
    archive_read_support_format_zip(a);
    archive_read_support_format_tar(a);
    archive_read_support_format_7zip(a);
    archive_read_support_format_rar(a);
    archive_read_support_format_rar5(a);
    
    archive_read_support_filter_all(a);
}

bool Scanner::isArchive(const std::filesystem::path& path) {
    std::error_code ec;
    auto file_size = std::filesystem::file_size(path, ec);
    if (ec || file_size < 4) {
        return false;
    }
    
    auto header = readFileHeader(path, HEADER_CHECK_SIZE);
    if (header.empty()) {
        return false;
    }
    
    if (isKnownExecutableFormat(header)) {
        common::Logger::instance().debug("[Archive] Known binary format detected | path={} | type={}",
                                        path.string(), isELF(header) ? "ELF" : "PE");
        return false;
    }
    
    struct archive* a = archive_read_new();
    configureArchiveFormats(a);
    
    int r = archive_read_open_filename(a, path.c_str(), 10240);
    if (r != ARCHIVE_OK) {
        archive_read_free(a);
        return false;
    }
    
    bool has_entry = hasValidArchiveEntry(a);
    
    if (!has_entry) {
        common::Logger::instance().debug("[Archive] No valid entries found | path={} | likely_false_positive=true",
                                        path.string());
    }
    
    archive_read_free(a);
    return has_entry;
}

bool Scanner::isArchive(const std::vector<uint8_t>& data) {
    if (data.size() < 4) {
        return false;
    }
    
    if (isKnownExecutableFormat(data)) {
        common::Logger::instance().debug("[Archive] Known binary format detected | type={}",
                                        isELF(data) ? "ELF" : "PE");
        return false;
    }
    
    struct archive* a = archive_read_new();
    configureArchiveFormats(a);
    
    int r = archive_read_open_memory(a, data.data(), data.size());
    if (r != ARCHIVE_OK) {
        archive_read_free(a);
        return false;
    }
    
    bool has_entry = hasValidArchiveEntry(a);
    
    if (!has_entry) {
        common::Logger::instance().debug("[Archive] No valid entries found | size={} | likely_false_positive=true",
                                        data.size());
    }
    
    archive_read_free(a);
    return has_entry;
}

ScanSummary Scanner::scanArchive(const std::filesystem::path& path, const ScanOptions& options) {
    ScanSummary summary;
    auto start_time = std::chrono::steady_clock::now();
    
    struct archive* a = archive_read_new();
    configureArchiveFormats(a);
    
    if (archive_read_open_filename(a, path.c_str(), 10240) != ARCHIVE_OK) {
        common::Logger::instance().error("[Archive] Open failed | path={} | error={}", 
                                        path.string(), archive_error_string(a));
        
        common::ScanMetadata error_result;
        error_result.file_path = path.string();
        error_result.result = common::ScanResult::ERROR;
        error_result.error_message = std::string("Archive open failed: ") + archive_error_string(a);
        error_result.error_code = core::CoreErrorCode::ARCHIVE_OPEN_FAILED;
        
        summary.results.push_back(error_result);
        summary.error_files++;
        summary.archive_errors++;
        summary.total_files_found++;
        
        archive_read_free(a);
        summary.total_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time);
        return summary;
    }
    
    summary = scanArchiveInternal(a, path.string(), options, 0, 
                                  std::filesystem::file_size(path), 0);
    
    archive_read_free(a);
    
    auto end_time = std::chrono::steady_clock::now();
    summary.total_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    
    return summary;
}

ScanSummary Scanner::scanArchive(const std::vector<uint8_t>& data,
                                 const std::string& archive_name,
                                 size_t archive_size,
                                 const ScanOptions& options) {
    ScanSummary summary;
    auto start_time = std::chrono::steady_clock::now();
    
    if (data.empty()) {
        common::Logger::instance().error("[Archive] Empty data | name={}", archive_name);
        
        common::ScanMetadata error_result;
        error_result.file_path = archive_name;
        error_result.result = common::ScanResult::ERROR;
        error_result.error_message = "Archive data is empty";
        error_result.error_code = core::CoreErrorCode::ARCHIVE_OPEN_FAILED;
        
        summary.results.push_back(error_result);
        summary.error_files++;
        summary.archive_errors++;
        summary.total_files_found++;
        
        return summary;
    }
    
    struct archive* a = archive_read_new();
    configureArchiveFormats(a);
    
    if (archive_read_open_memory(a, data.data(), data.size()) != ARCHIVE_OK) {
        common::Logger::instance().error("[Archive] Open from memory failed | name={}", 
                                        archive_name);
        
        common::ScanMetadata error_result;
        error_result.file_path = archive_name;
        error_result.result = common::ScanResult::ERROR;
        error_result.error_message = std::string("Archive open failed: ") + archive_error_string(a);
        error_result.error_code = core::CoreErrorCode::ARCHIVE_OPEN_FAILED;
        
        summary.results.push_back(error_result);
        summary.error_files++;
        summary.archive_errors++;
        summary.total_files_found++;
        
        archive_read_free(a);
        summary.total_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time);
        return summary;
    }
    
    summary = scanArchiveInternal(a, archive_name, options, 0, archive_size, 0);
    
    archive_read_free(a);
    
    auto end_time = std::chrono::steady_clock::now();
    summary.total_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    
    return summary;
}

ScanSummary Scanner::scanArchiveInternal(struct archive* a,
                                        const std::string& archive_path,
                                        const ScanOptions& options,
                                        int current_depth,
                                        size_t archive_size,
                                        size_t total_expected) {
    ScanSummary summary;
    
    if (current_depth >= options.max_archive_recursion_depth) {
        common::Logger::instance().warn("[Archive] Max depth exceeded | path={} | depth={}", 
                                       archive_path, current_depth);
        summary.depth_exceeded_files++;
        return summary;
    }
    
    if (current_depth > 0 && archive_size == 0) {
        archive_size = 1024 * 1024;
    }
    
    size_t total_extracted = 0;
    size_t entry_count = 0;
    
    struct archive_entry* entry;
    int r;
    while ((r = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        summary.total_files_found++;
        
        if (total_extracted > options.max_archive_extracted_size) {
            common::Logger::instance().error(
                "[Archive] BOMB: Size limit exceeded | path={} | extracted={} | limit={}",
                archive_path, total_extracted, options.max_archive_extracted_size);
            summary.archive_errors++;
            break;
        }
        
        if (entry_count >= options.max_archive_file_count) {
            common::Logger::instance().error(
                "[Archive] BOMB: File count exceeded | path={} | count={}",
                archive_path, entry_count);
            summary.archive_errors++;
            break;
        }
        
        if (archive_entry_filetype(entry) != AE_IFREG) {
            continue;
        }
        
        entry_count++;
        
        const char* pathname = archive_entry_pathname(entry);
        if (!pathname || pathname[0] == '\0') {
            common::Logger::instance().warn(
                "[Archive] NULL or empty pathname | archive={} | entry_index={}", 
                archive_path, summary.total_files_found
            );
            
            common::ScanMetadata error_result;
            error_result.file_path = archive_path + ":<unnamed entry " + std::to_string(summary.total_files_found) + ">";
            error_result.result = common::ScanResult::ERROR;
            error_result.error_message = "Archive entry has null or empty pathname";
            error_result.error_code = core::CoreErrorCode::ARCHIVE_CORRUPTED;
            
            summary.results.push_back(error_result);
            summary.error_files++;
            summary.archive_errors++;
            continue;
        }
        
        size_t entry_size = archive_entry_size(entry);
        std::string entry_path(pathname);
        std::string full_path = archive_path + ":" + entry_path;
        
        if (entry_size > archive_size * options.max_compression_ratio) {
            common::Logger::instance().warn(
                "[Archive] BOMB: Ratio exceeded | path={} | ratio={}",
                full_path, entry_size / archive_size);
            summary.compression_ratio_exceeded++;
            continue;
        }
        
        if (entry_size > options.max_file_size) {
            summary.size_exceeded_files++;
            continue;
        }
        
        if (entry_size == 0) {
            summary.empty_files++;
            continue;
        }
        
        std::vector<uint8_t> data(entry_size);
        ssize_t read_size = archive_read_data(a, data.data(), entry_size);
        
        if (read_size < 0) {
            const char* error_msg = archive_error_string(a);
            if (isEncryptionError(error_msg)) {
                common::Logger::instance().warn("[Archive] Encrypted entry | path={}", 
                                               full_path);
                common::ScanMetadata encrypted_result;
                encrypted_result.file_path = full_path;
                encrypted_result.result = common::ScanResult::UNSUPPORTED;
                encrypted_result.error_message = "Encrypted archive entry";
                encrypted_result.error_code = core::CoreErrorCode::ARCHIVE_ENCRYPTED;
                summary.results.push_back(encrypted_result);
                summary.encrypted_files++;
            } else {
                common::Logger::instance().error("[Archive] Extraction failed | path={} | error={}", 
                                                full_path, error_msg);
                
                common::ScanMetadata error_result;
                error_result.file_path = full_path;
                error_result.result = common::ScanResult::ERROR;
                error_result.error_message = std::string("Archive extraction failed: ") + error_msg;
                error_result.error_code = core::CoreErrorCode::ARCHIVE_EXTRACTION_FAILED;
                
                summary.results.push_back(error_result);
                summary.error_files++;
                summary.archive_errors++;
            }
            continue;
        }
        
        if (read_size != static_cast<ssize_t>(entry_size)) {
            common::Logger::instance().warn("[Archive] Partial read | path={} | expected={} | read={}",
                                           full_path, entry_size, read_size);
            data.resize(read_size);
        }
        
        total_extracted += read_size;
        
        if (isArchive(data)) {
            common::Logger::instance().debug("[Archive] Nested archive detected | path={}", 
                                            full_path);
            struct archive* nested_a = createArchiveFromMemory(data);
            if (nested_a) {
                auto nested_summary = scanArchiveInternal(
                    nested_a, full_path, options, current_depth + 1, entry_size, 0);
                mergeSummaries(summary, nested_summary);
                archive_read_free(nested_a);
            }
        } else {
            auto result = engine_->scan(data, options.include_hashes);
            result.file_path = full_path;
            
            if (result.result == common::ScanResult::UNSUPPORTED) {
                summary.unsupported_files++;
                summary.results.push_back(result);
            } else {
                summary.results.push_back(result);
                updateSummaryCounters(summary, result);
            }
            
            common::Logger::instance().debug("[Archive] Entry scanned | path={} | result={}", 
                                            full_path, common::to_string(result.result));
        }
    }
    
    if (r != ARCHIVE_OK && r != ARCHIVE_EOF && entry_count == 0) {
        const char* error_msg = archive_error_string(a);
        if (isEncryptionError(error_msg)) {
            common::Logger::instance().warn("[Archive] Encrypted archive | path={} | error={}", 
                                           archive_path, error_msg);
            summary.encrypted_files++;
            
            common::ScanMetadata encrypted_result;
            encrypted_result.file_path = archive_path;
            encrypted_result.result = common::ScanResult::UNSUPPORTED;
            encrypted_result.error_message = "Encrypted archive";
            encrypted_result.error_code = core::CoreErrorCode::ARCHIVE_ENCRYPTED;
            summary.results.push_back(encrypted_result);
        } else {
            common::Logger::instance().error("[Archive] Failed to read archive | path={} | error={}", 
                                            archive_path, error_msg);
            
            common::ScanMetadata error_result;
            error_result.file_path = archive_path;
            error_result.result = common::ScanResult::ERROR;
            error_result.error_message = std::string("Archive read failed: ") + error_msg;
            error_result.error_code = core::CoreErrorCode::ARCHIVE_CORRUPTED;
            
            summary.results.push_back(error_result);
            summary.error_files++;
            summary.archive_errors++;
        }
    } else if (archive_errno(a) != 0 && entry_count > 0) {
        common::Logger::instance().warn(
            "[Archive] Partially corrupted | path={} | processed={} | error={}",
            archive_path, entry_count, archive_error_string(a));
    }
    
    summary.total_files = entry_count;
    return summary;
}

struct archive* Scanner::createArchiveFromMemory(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return nullptr;
    }
    
    struct archive* a = archive_read_new();
    configureArchiveFormats(a);
    
    if (archive_read_open_memory(a, data.data(), data.size()) != ARCHIVE_OK) {
        archive_read_free(a);
        return nullptr;
    }
    
    return a;
}

void Scanner::mergeSummaries(ScanSummary& target, const ScanSummary& source) {
    target.total_files_found += source.total_files_found;
    target.total_files += source.total_files;
    target.clean_files += source.clean_files;
    target.malicious_files += source.malicious_files;
    target.unsupported_files += source.unsupported_files;
    target.error_files += source.error_files;
    target.archive_errors += source.archive_errors;
    target.encrypted_files += source.encrypted_files;
    target.compression_ratio_exceeded += source.compression_ratio_exceeded;
    target.size_exceeded_files += source.size_exceeded_files;
    target.depth_exceeded_files += source.depth_exceeded_files;
    target.empty_files += source.empty_files;
    
    target.results.insert(target.results.end(), 
                         source.results.begin(), 
                         source.results.end());
}

bool Scanner::isEncryptionError(const char* error_string) {
    if (!error_string) {
        return false;
    }
    
    std::string error(error_string);
    std::transform(error.begin(), error.end(), error.begin(), ::tolower);
    
    return error.find("encrypt") != std::string::npos ||
           error.find("password") != std::string::npos ||
           error.find("passphrase") != std::string::npos ||
           error.find("credential") != std::string::npos;
}

common::ScanMetadata Scanner::scan(const std::filesystem::path& file_path, bool include_hashes) {
    common::ScanMetadata metadata;
    metadata.file_path = file_path.string();
    
    if (!engine_ || !engine_->isInitialized()) {
        metadata.result = common::ScanResult::ERROR;
        metadata.error_code = core::CoreErrorCode::ENGINE_NOT_INITIALIZED;
        metadata.error_message = core::CoreErrorCodeHelper::getMessage(core::CoreErrorCode::ENGINE_NOT_INITIALIZED);
        
        common::ErrorContext ctx;
        ctx.component = "Scanner";
        ctx.details["operation"] = "scan";
        ctx.details["path"] = file_path.string();
        metadata.error_context = ctx;
        
        common::Logger::instance().error("[Scanner] Scan failed | code={} | {}", 
                                        core::CoreErrorCodeHelper::toString(core::CoreErrorCode::ENGINE_NOT_INITIALIZED),
                                        common::formatContext(ctx));
        return metadata;
    }
    
    return engine_->scan(file_path, include_hashes);
}

common::ScanMetadata Scanner::scan(const std::vector<uint8_t>& data, bool include_hashes) {
    common::ScanMetadata metadata;
    metadata.file_path = "<buffer>";
    
    if (!engine_ || !engine_->isInitialized()) {
        metadata.result = common::ScanResult::ERROR;
        metadata.error_code = core::CoreErrorCode::ENGINE_NOT_INITIALIZED;
        metadata.error_message = core::CoreErrorCodeHelper::getMessage(core::CoreErrorCode::ENGINE_NOT_INITIALIZED);
        
        common::ErrorContext ctx;
        ctx.component = "Scanner";
        ctx.details["operation"] = "scan";
        ctx.details["data_size"] = std::to_string(data.size());
        metadata.error_context = ctx;
        
        common::Logger::instance().error("[Scanner] Scan failed | code={} | {}", 
                                        core::CoreErrorCodeHelper::toString(core::CoreErrorCode::ENGINE_NOT_INITIALIZED),
                                        common::formatContext(ctx));
        return metadata;
    }
    
    return engine_->scan(data, include_hashes);
}

common::ScanMetadata Scanner::scan(std::istream& stream, bool include_hashes) {
    common::ScanMetadata metadata;
    metadata.file_path = "<stream>";
    
    if (!engine_ || !engine_->isInitialized()) {
        metadata.result = common::ScanResult::ERROR;
        metadata.error_code = core::CoreErrorCode::ENGINE_NOT_INITIALIZED;
        metadata.error_message = core::CoreErrorCodeHelper::getMessage(core::CoreErrorCode::ENGINE_NOT_INITIALIZED);
        
        common::ErrorContext ctx;
        ctx.component = "Scanner";
        ctx.details["operation"] = "scan";
        metadata.error_context = ctx;
        
        common::Logger::instance().error("[Scanner] Scan failed | code={} | {}", 
                                        core::CoreErrorCodeHelper::toString(core::CoreErrorCode::ENGINE_NOT_INITIALIZED),
                                        common::formatContext(ctx));
        return metadata;
    }
    
    return engine_->scan(stream, include_hashes);
}

ScanSummary Scanner::scanDirectory(const std::filesystem::path& directory, 
                                    const ScanOptions& options) {
    auto start_time = std::chrono::steady_clock::now();
    ScanSummary summary;
    
    if (!std::filesystem::exists(directory) || !std::filesystem::is_directory(directory)) {
        common::Logger::instance().error("[Scanner] Invalid directory | path={}", directory.string());
        return summary;
    }
    
    common::Logger::instance().info("[Scanner] Starting | path={} | recursive={} | threads={} | max_depth={}", 
                                    directory.string(), options.recursive, options.max_threads, 
                                    options.max_recursion_depth);
    
    if (options.max_threads <= 1) {
        auto files = collectFiles(directory, options, summary, 0);
        summary.total_files = files.size();
        
        if (files.empty()) {
            common::Logger::instance().info("[Scanner] No files found | path={}", directory.string());
            auto end_time = std::chrono::steady_clock::now();
            summary.total_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            return summary;
        }
        
        common::Logger::instance().info("[Scanner] Found files | count={}", files.size());
        
        for (size_t i = 0; i < files.size(); ++i) {
            try {
                if (isArchive(files[i])) {
                    common::Logger::instance().debug("[Scanner] Archive detected | path={}", 
                                                     files[i].string());
                    
                    auto archive_summary = scanArchive(files[i], options);
                    
                    auto verdict = calculateArchiveVerdict(archive_summary.results);
                    
                    common::ScanMetadata archive_result;
                    archive_result.file_path = files[i].string();
                    archive_result.result = verdict.result;
                    archive_result.confidence = verdict.confidence;
                    archive_result.file_type = "archive";
                    archive_result.file_size = std::filesystem::file_size(files[i]);
                    archive_result.scan_time = archive_summary.total_time;
                    
                    summary.results.push_back(archive_result);
                    updateSummaryCounters(summary, archive_result);
                    
                    if (result_callback_) {
                        result_callback_(archive_result, i + 1, files.size());
                    }
                } else {
                    auto result = scan(files[i], options.include_hashes);
                    summary.results.push_back(result);
                    updateSummaryCounters(summary, result);
                    
                    if (result_callback_) {
                        result_callback_(result, i + 1, files.size());
                    }
                }
            } catch (const std::exception& e) {
                common::ScanMetadata error_result;
                error_result.file_path = files[i].string();
                error_result.result = common::ScanResult::ERROR;
                error_result.error_message = e.what();
                summary.results.push_back(error_result);
                summary.error_files++;
                
                if (result_callback_) {
                    result_callback_(error_result, i + 1, files.size());
                }
            }
        }
    } else {
        tbb::concurrent_queue<std::filesystem::path> paths_to_scan;
        tbb::concurrent_queue<common::ScanMetadata> results_queue;
        std::atomic<size_t> total_files{0};
        std::atomic<size_t> processed_files{0};
        std::atomic<bool> collection_done{false};
        
        std::atomic<size_t> collection_total_files{0};
        std::atomic<size_t> collection_unsupported{0};
        std::atomic<size_t> collection_permission_denied{0};
        std::atomic<size_t> collection_size_exceeded{0};
        std::atomic<size_t> collection_depth_exceeded{0};
        std::atomic<size_t> collection_empty{0};
        std::atomic<size_t> collection_excluded{0};
        
        common::Logger::instance().debug("[Scanner] Parallel mode | threads={}", options.max_threads);
        
        tbb::parallel_invoke(
            [&] {
                std::function<void(const std::filesystem::path&, int)> collect_recursive;
                collect_recursive = [&](const std::filesystem::path& dir, int depth) {
                    if (depth > options.max_recursion_depth) {
                        collection_depth_exceeded.fetch_add(1);
                        return;
                    }
                    
                    std::error_code ec;
                    for (auto it = std::filesystem::directory_iterator(dir, ec);
                         it != std::filesystem::directory_iterator();
                         it.increment(ec)) {
                        
                        if (ec) {
                            if (ec.value() == EACCES || ec.value() == EPERM) {
                                collection_permission_denied.fetch_add(1);
                            }
                            ec.clear();
                            continue;
                        }
                        
                        if (std::filesystem::is_symlink(it->path(), ec)) {
                            if (std::filesystem::is_directory(it->path(), ec)) {
                                continue;
                            }
                            collection_total_files.fetch_add(1);
                            collection_unsupported.fetch_add(1);
                            continue;
                        }
                        
                        if (std::filesystem::is_directory(it->path(), ec) && options.recursive) {
                            collect_recursive(it->path(), depth + 1);
                        } else if (std::filesystem::is_regular_file(it->path(), ec)) {
                            collection_total_files.fetch_add(1);
                            
                            auto file_size = std::filesystem::file_size(it->path(), ec);
                            if (ec) {
                                if (ec.value() == EACCES || ec.value() == EPERM) {
                                    collection_permission_denied.fetch_add(1);
                                }
                                continue;
                            }
                            
                            if (file_size == 0) {
                                collection_empty.fetch_add(1);
                                continue;
                            }
                            
                            if (file_size > options.max_file_size) {
                                collection_size_exceeded.fetch_add(1);
                                continue;
                            }
                            
                            if (matchesExcludePattern(it->path(), options.exclude_patterns)) {
                                collection_excluded.fetch_add(1);
                                continue;
                            }
                            
                            paths_to_scan.push(it->path());
                            total_files.fetch_add(1);
                        }
                    }
                };
                
                collect_recursive(directory, 0);
                collection_done.store(true);
                
                for (int i = 0; i < options.max_threads; ++i) {
                    paths_to_scan.push(std::filesystem::path());
                }
            },
            
            [&] {
                tbb::parallel_for(0, options.max_threads, [&](int) {
                    while (true) {
                        std::filesystem::path path;
                        
                        while (!paths_to_scan.try_pop(path)) {
                            if (collection_done.load() && paths_to_scan.empty()) {
                                return;
                            }
                            std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        }
                        
                        if (path.empty()) {
                            break;
                        }
                        
                        try {
                            if (isArchive(path)) {
                                common::Logger::instance().debug("[Scanner] Archive detected | path={}", 
                                                                 path.string());
                                
                                auto archive_summary = scanArchive(path, options);
                                auto verdict = calculateArchiveVerdict(archive_summary.results);
                                
                                common::ScanMetadata archive_result;
                                archive_result.file_path = path.string();
                                archive_result.result = verdict.result;
                                archive_result.confidence = verdict.confidence;
                                archive_result.file_type = "archive";
                                archive_result.file_size = std::filesystem::file_size(path);
                                archive_result.scan_time = archive_summary.total_time;
                                
                                results_queue.push(archive_result);
                            } else {
                                auto result = scan(path, options.include_hashes);
                                results_queue.push(result);
                            }
                        } catch (const std::exception& e) {
                            common::ScanMetadata error_result;
                            error_result.file_path = path.string();
                            error_result.result = common::ScanResult::ERROR;
                            error_result.error_message = e.what();
                            results_queue.push(error_result);
                        }
                        
                        processed_files.fetch_add(1);
                    }
                });
                
                common::ScanMetadata poison_pill;
                results_queue.push(poison_pill);
            },
            
            [&] {
                while (true) {
                    common::ScanMetadata result;
                    
                    while (!results_queue.try_pop(result)) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    }
                    
                    if (result.file_path.empty()) {
                        break;
                    }
                    
                    summary.results.push_back(result);
                    updateSummaryCounters(summary, result);
                    
                    if (result_callback_) {
                        size_t current = summary.results.size();
                        size_t total = total_files.load();
                        result_callback_(result, current, total);
                    }
                }
            }
        );
        
        summary.total_files_found = collection_total_files.load();
        summary.unsupported_files += collection_unsupported.load();
        summary.permission_denied_files = collection_permission_denied.load();
        summary.size_exceeded_files = collection_size_exceeded.load();
        summary.depth_exceeded_files = collection_depth_exceeded.load();
        summary.empty_files = collection_empty.load();
        summary.excluded_by_pattern = collection_excluded.load();
        
        summary.total_files = total_files.load();
        
        common::Logger::instance().info("[Scanner] Parallel complete | files={} | threads={}", 
                                        summary.total_files, options.max_threads);
    }
    
    auto end_time = std::chrono::steady_clock::now();
    summary.total_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    common::Logger::instance().info("[Scanner] Complete | files={} | clean={} | malicious={} | duration_ms={}", 
                                    summary.total_files, summary.clean_files, 
                                    summary.malicious_files, summary.total_time.count());
    
    return summary;
}

void Scanner::setProgressCallback(std::function<void(size_t, size_t)> callback) {
    progress_callback_ = std::move(callback);
}

void Scanner::setResultCallback(std::function<void(const common::ScanMetadata&, size_t, size_t)> callback) {
    result_callback_ = std::move(callback);
}

bool Scanner::shouldScanFile(const std::filesystem::path& file_path, 
                              const ScanOptions& options,
                              ScanSummary& summary) {
    std::error_code ec;
    
    if (std::filesystem::is_symlink(file_path, ec)) {
        summary.unsupported_files++;
        return false;
    }
    
    if (!std::filesystem::is_regular_file(file_path, ec)) {
        if (ec && (ec.value() == EACCES || ec.value() == EPERM)) {
            summary.permission_denied_files++;
        } else {
            summary.unsupported_files++;
        }
        return false;
    }
    
    auto file_size = std::filesystem::file_size(file_path, ec);
    if (ec) {
        if (ec.value() == EACCES || ec.value() == EPERM) {
            summary.permission_denied_files++;
        } else {
            summary.unsupported_files++;
        }
        return false;
    }
    
    if (file_size == 0) {
        summary.empty_files++;
        return false;
    }
    
    if (file_size > options.max_file_size) {
        summary.size_exceeded_files++;
        return false;
    }
    
    if (matchesExcludePattern(file_path, options.exclude_patterns)) {
        summary.excluded_by_pattern++;
        return false;
    }
    
    return true;
}

bool Scanner::matchesExcludePattern(const std::filesystem::path& file_path,
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
            common::Logger::instance().warn("[Scanner] Invalid pattern | pattern={}", pattern);
        }
    }
    
    return false;
}

std::vector<std::filesystem::path> Scanner::collectFiles(const std::filesystem::path& directory,
                                                          const ScanOptions& options,
                                                          ScanSummary& summary,
                                                          int current_depth) {
    std::vector<std::filesystem::path> files;
    
    if (current_depth > options.max_recursion_depth) {
        summary.depth_exceeded_files++;
        return files;
    }
    
    try {
        std::error_code ec;
        
        for (auto it = std::filesystem::directory_iterator(directory, ec);
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
                auto subdir_files = collectFiles(it->path(), options, summary, current_depth + 1);
                files.insert(files.end(), subdir_files.begin(), subdir_files.end());
            } else if (std::filesystem::is_regular_file(it->path(), ec)) {
                summary.total_files_found++;
                
                if (shouldScanFile(it->path(), options, summary)) {
                    files.push_back(it->path());
                }
            }
        }
        
    } catch (const std::exception& e) {
        common::Logger::instance().error("[Scanner] Collection failed | path={} | error={}", 
                                        directory.string(), e.what());
    }
    
    std::sort(files.begin(), files.end());
    return files;
}

void Scanner::updateSummaryCounters(ScanSummary& summary, const common::ScanMetadata& result) {
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

}}