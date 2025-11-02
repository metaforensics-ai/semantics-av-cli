#include "semantics_av/scan/scanner.hpp"
#include "semantics_av/core/error_codes.hpp"
#include "semantics_av/common/error_framework.hpp"
#include "semantics_av/common/logger.hpp"
#include <algorithm>
#include <regex>
#include <tbb/parallel_for.h>
#include <tbb/parallel_invoke.h>
#include <tbb/concurrent_queue.h>
#include <atomic>
#include <unistd.h>

namespace semantics_av {
namespace scan {

Scanner::Scanner(core::SemanticsAVEngine* engine) : engine_(engine) {}

Scanner::~Scanner() = default;

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
                auto result = scan(files[i], options.include_hashes);
                summary.results.push_back(result);
                updateSummaryCounters(summary, result);
                
                if (result_callback_) {
                    result_callback_(result, i + 1, files.size());
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
        
        common::Logger::instance().debug("[Scanner] Parallel mode | threads={}", options.max_threads);
        
        tbb::parallel_invoke(
            [&] {
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
                                paths_to_scan.push(it->path());
                                total_files.fetch_add(1);
                            }
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
                            auto result = scan(path, options.include_hashes);
                            results_queue.push(result);
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