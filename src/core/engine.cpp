#include "semantics_av/core/engine.hpp"
#include "semantics_av/core/error_codes.hpp"
#include "semantics_av/common/error_framework.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/config.hpp"
#include "semantics_av/common/constants.hpp"
#include <semantics_av/semantics_av.hpp>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#include <future>

namespace semantics_av {
namespace core {

CoreErrorCode mapSdkResult(semantics_av::Result sdk_result) {
    using R = semantics_av::Result;
    
    switch (sdk_result) {
        case R::OK:
            return CoreErrorCode::ENGINE_NOT_INITIALIZED;
            
        case R::UNSUPPORTED_FORMAT:
            return CoreErrorCode::SCAN_UNSUPPORTED_FORMAT;
            
        case R::FILE_NOT_FOUND:
            return CoreErrorCode::SCAN_FILE_NOT_FOUND;
            
        case R::FILE_READ_ERROR:
            return CoreErrorCode::SCAN_FILE_NOT_ACCESSIBLE;
            
        case R::MODEL_NOT_FOUND:
            return CoreErrorCode::MODEL_NOT_FOUND;
            
        case R::MODEL_LOAD_ERROR:
            return CoreErrorCode::MODEL_LOAD_FAILED;
            
        case R::MODEL_CORRUPTED:
            return CoreErrorCode::MODEL_CORRUPTED;
            
        case R::CORRUPTED_DATA:
        case R::INVALID_FORMAT:
            return CoreErrorCode::ANALYSIS_PAYLOAD_INVALID;
            
        case R::INFERENCE_ERROR:
            return CoreErrorCode::SDK_INFERENCE_FAILED;
            
        default:
            return CoreErrorCode::SDK_INTERNAL_ERROR;
    }
}

SemanticsAVEngine::SemanticsAVEngine() = default;

SemanticsAVEngine::~SemanticsAVEngine() {
    cleanup();
}

bool SemanticsAVEngine::initialize(const std::string& base_path, const std::string& api_key) {
    if (initialized_) {
        common::Logger::instance().warn("[Engine] Already initialized");
        return true;
    }
    
    try {
        semantics_av::InitOptions options;
        options.base_path = base_path;
        options.log_level = semantics_av::LogLevel::INFO;
        options.log_callback = common::Logger::instance().getLibraryCallback();
        
        core_engine_ = std::make_unique<semantics_av::SemanticsAV>(options);
        
        auto result = core_engine_->initialize();
        if (result != semantics_av::Result::OK) {
            CoreErrorCode error_code = mapSdkResult(result);
            common::ErrorContext ctx;
            ctx.component = "Engine";
            ctx.details["base_path"] = base_path;
            ctx.details["sdk_result"] = std::to_string(static_cast<int>(result));
            
            common::Logger::instance().error("[Engine] Initialization failed | code={} | {}", 
                                            CoreErrorCodeHelper::toString(error_code),
                                            common::formatContext(ctx));
            core_engine_.reset();
            return false;
        }
        
        base_path_ = base_path;
        initialized_ = true;
        
        common::Logger::instance().info("[Engine] Initialized | base_path={} | has_api_key={}", 
                                       base_path, !api_key.empty());
        return true;
        
    } catch (const std::exception& e) {
        common::ErrorContext ctx;
        ctx.component = "Engine";
        ctx.details["base_path"] = base_path;
        ctx.details["exception"] = e.what();
        
        common::Logger::instance().error("[Engine] Exception during init | code={} | {}", 
                                        CoreErrorCodeHelper::toString(CoreErrorCode::ENGINE_INITIALIZATION_FAILED),
                                        common::formatContext(ctx));
        core_engine_.reset();
        return false;
    }
}

void SemanticsAVEngine::cleanup() {
    if (core_engine_) {
        core_engine_.reset();
        initialized_ = false;
        common::Logger::instance().debug("[Engine] Cleaned up");
    }
}

common::ScanMetadata SemanticsAVEngine::scan(const std::filesystem::path& file_path, bool include_hashes) {
    common::ScanMetadata metadata;
    metadata.file_path = file_path.string();
    
    if (!initialized_) {
        metadata.result = common::ScanResult::ERROR;
        metadata.error_code = CoreErrorCode::ENGINE_NOT_INITIALIZED;
        metadata.error_message = CoreErrorCodeHelper::getMessage(CoreErrorCode::ENGINE_NOT_INITIALIZED);
        
        common::ErrorContext ctx;
        ctx.component = "Engine";
        ctx.details["operation"] = "scan";
        metadata.error_context = ctx;
        
        return metadata;
    }
    
    if (!std::filesystem::exists(file_path)) {
        metadata.result = common::ScanResult::ERROR;
        metadata.error_code = CoreErrorCode::SCAN_FILE_NOT_FOUND;
        metadata.error_message = CoreErrorCodeHelper::getMessage(CoreErrorCode::SCAN_FILE_NOT_FOUND);
        
        common::ErrorContext ctx;
        ctx.component = "Engine";
        ctx.details["path"] = file_path.string();
        metadata.error_context = ctx;
        
        common::Logger::instance().error("[Engine] Scan failed | code={} | {}", 
                                        CoreErrorCodeHelper::toString(CoreErrorCode::SCAN_FILE_NOT_FOUND),
                                        common::formatContext(ctx));
        return metadata;
    }
    
    auto& config = common::Config::instance().global();
    int timeout_seconds = config.scan_timeout_seconds;
    
    auto scan_future = std::async(std::launch::async, [this, &file_path, &metadata, include_hashes]() {
        auto start_time = std::chrono::steady_clock::now();
        
        try {
            std::error_code ec;
            metadata.file_size = std::filesystem::file_size(file_path, ec);
            if (ec) {
                metadata.file_size = 0;
            }
            
            semantics_av::ScanResult scan_result;
            semantics_av::ScanOptions scan_options(include_hashes);
            auto result = core_engine_->scan(file_path.string(), scan_result, &scan_options);
            
            if (result == semantics_av::Result::UNSUPPORTED_FORMAT) {
                metadata.result = common::ScanResult::UNSUPPORTED;
                metadata.confidence = 0.0f;
                metadata.error_code = CoreErrorCode::SCAN_UNSUPPORTED_FORMAT;
                
                common::ErrorContext ctx;
                ctx.component = "Engine";
                ctx.details["path"] = file_path.string();
                ctx.details["detected_type"] = scan_result.file_type;
                metadata.error_context = ctx;
                
            } else if (result != semantics_av::Result::OK) {
                metadata.result = common::ScanResult::ERROR;
                CoreErrorCode error_code = mapSdkResult(result);
                metadata.error_code = error_code;
                metadata.error_message = CoreErrorCodeHelper::getMessage(error_code);
                
                common::ErrorContext ctx;
                ctx.component = "Engine";
                ctx.details["path"] = file_path.string();
                ctx.details["sdk_result"] = std::to_string(static_cast<int>(result));
                metadata.error_context = ctx;
                
                common::Logger::instance().error("[Engine] Scan failed | code={} | {}", 
                                                CoreErrorCodeHelper::toString(error_code),
                                                common::formatContext(ctx));
            } else {
                metadata.file_type = scan_result.file_type;
                metadata.result = scan_result.is_malware ? 
                    common::ScanResult::MALICIOUS : 
                    common::ScanResult::CLEAN;
                
                metadata.confidence = scan_result.is_malware ?
                    scan_result.malware_probability :
                    (1.0f - scan_result.malware_probability);
                
                if (scan_result.file_hashes && !scan_result.file_hashes->empty()) {
                    metadata.file_hashes = scan_result.file_hashes;
                }
            }
            
        } catch (const std::exception& e) {
            metadata.result = common::ScanResult::ERROR;
            metadata.error_code = CoreErrorCode::SDK_INTERNAL_ERROR;
            metadata.error_message = e.what();
            
            common::ErrorContext ctx;
            ctx.component = "Engine";
            ctx.details["path"] = file_path.string();
            ctx.details["exception"] = e.what();
            metadata.error_context = ctx;
            
            common::Logger::instance().error("[Engine] Scan exception | code={} | {}", 
                                            CoreErrorCodeHelper::toString(CoreErrorCode::SDK_INTERNAL_ERROR),
                                            common::formatContext(ctx));
        }
        
        auto end_time = std::chrono::steady_clock::now();
        metadata.scan_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        return metadata;
    });
    
    auto status = scan_future.wait_for(std::chrono::seconds(timeout_seconds));
    
    if (status == std::future_status::timeout) {
        metadata.result = common::ScanResult::ERROR;
        metadata.error_code = CoreErrorCode::SCAN_TIMEOUT;
        metadata.error_message = CoreErrorCodeHelper::getMessage(CoreErrorCode::SCAN_TIMEOUT);
        
        common::ErrorContext ctx;
        ctx.component = "Engine";
        ctx.details["path"] = file_path.string();
        ctx.details["timeout_seconds"] = std::to_string(timeout_seconds);
        metadata.error_context = ctx;
        
        common::Logger::instance().warn("[Engine] Scan timeout | code={} | {}", 
                                       CoreErrorCodeHelper::toString(CoreErrorCode::SCAN_TIMEOUT),
                                       common::formatContext(ctx));
        return metadata;
    }
    
    return scan_future.get();
}

common::ScanMetadata SemanticsAVEngine::scanFromFd(int fd, bool include_hashes) {
    common::ScanMetadata metadata;
    metadata.file_path = "<fd:" + std::to_string(fd) + ">";
    
    if (!initialized_) {
        metadata.result = common::ScanResult::ERROR;
        metadata.error_code = CoreErrorCode::ENGINE_NOT_INITIALIZED;
        metadata.error_message = CoreErrorCodeHelper::getMessage(CoreErrorCode::ENGINE_NOT_INITIALIZED);
        
        common::ErrorContext ctx;
        ctx.component = "Engine";
        ctx.details["operation"] = "scanFromFd";
        metadata.error_context = ctx;
        
        return metadata;
    }
    
    if (fd < 0) {
        metadata.result = common::ScanResult::ERROR;
        metadata.error_code = CoreErrorCode::SCAN_FILE_NOT_ACCESSIBLE;
        metadata.error_message = "Invalid file descriptor";
        
        common::ErrorContext ctx;
        ctx.component = "Engine";
        ctx.details["fd"] = std::to_string(fd);
        metadata.error_context = ctx;
        
        common::Logger::instance().error("[Engine] Scan failed | code={} | {}", 
                                        CoreErrorCodeHelper::toString(CoreErrorCode::SCAN_FILE_NOT_ACCESSIBLE),
                                        common::formatContext(ctx));
        return metadata;
    }
    
    auto& config = common::Config::instance().global();
    int timeout_seconds = config.scan_timeout_seconds;
    
    auto scan_future = std::async(std::launch::async, [this, fd, &metadata, include_hashes]() {
        auto start_time = std::chrono::steady_clock::now();
        
        try {
            off_t current_pos = lseek(fd, 0, SEEK_CUR);
            if (current_pos == -1) {
                metadata.result = common::ScanResult::ERROR;
                metadata.error_code = CoreErrorCode::SCAN_FILE_NOT_ACCESSIBLE;
                metadata.error_message = "Cannot seek file descriptor";
                
                common::ErrorContext ctx;
                ctx.component = "Engine";
                ctx.details["fd"] = std::to_string(fd);
                ctx.details["reason"] = "seek_failed";
                metadata.error_context = ctx;
                
                return metadata;
            }
            
            off_t file_size = lseek(fd, 0, SEEK_END);
            lseek(fd, 0, SEEK_SET);
            
            metadata.file_size = file_size;
            
            std::vector<uint8_t> buffer(file_size);
            ssize_t bytes_read = read(fd, buffer.data(), file_size);
            
            if (bytes_read != file_size) {
                metadata.result = common::ScanResult::ERROR;
                metadata.error_code = CoreErrorCode::SCAN_FILE_NOT_ACCESSIBLE;
                metadata.error_message = "Failed to read file descriptor";
                
                common::ErrorContext ctx;
                ctx.component = "Engine";
                ctx.details["fd"] = std::to_string(fd);
                ctx.details["expected_bytes"] = std::to_string(file_size);
                ctx.details["read_bytes"] = std::to_string(bytes_read);
                metadata.error_context = ctx;
                
                return metadata;
            }
            
            lseek(fd, current_pos, SEEK_SET);
            
            semantics_av::ScanResult scan_result;
            semantics_av::ScanOptions scan_options(include_hashes);
            auto result = core_engine_->scan(buffer.data(), buffer.size(), scan_result, &scan_options);
            
            if (result == semantics_av::Result::UNSUPPORTED_FORMAT) {
                metadata.result = common::ScanResult::UNSUPPORTED;
                metadata.confidence = 0.0f;
                metadata.error_code = CoreErrorCode::SCAN_UNSUPPORTED_FORMAT;
                
            } else if (result != semantics_av::Result::OK) {
                metadata.result = common::ScanResult::ERROR;
                CoreErrorCode error_code = mapSdkResult(result);
                metadata.error_code = error_code;
                metadata.error_message = CoreErrorCodeHelper::getMessage(error_code);
                
                common::ErrorContext ctx;
                ctx.component = "Engine";
                ctx.details["fd"] = std::to_string(fd);
                ctx.details["sdk_result"] = std::to_string(static_cast<int>(result));
                metadata.error_context = ctx;
                
            } else {
                metadata.file_type = scan_result.file_type;
                metadata.result = scan_result.is_malware ? 
                    common::ScanResult::MALICIOUS : 
                    common::ScanResult::CLEAN;
                
                metadata.confidence = scan_result.is_malware ?
                    scan_result.malware_probability :
                    (1.0f - scan_result.malware_probability);
                
                if (scan_result.file_hashes && !scan_result.file_hashes->empty()) {
                    metadata.file_hashes = scan_result.file_hashes;
                }
            }
            
        } catch (const std::exception& e) {
            metadata.result = common::ScanResult::ERROR;
            metadata.error_code = CoreErrorCode::SDK_INTERNAL_ERROR;
            metadata.error_message = e.what();
            
            common::ErrorContext ctx;
            ctx.component = "Engine";
            ctx.details["fd"] = std::to_string(fd);
            ctx.details["exception"] = e.what();
            metadata.error_context = ctx;
        }
        
        auto end_time = std::chrono::steady_clock::now();
        metadata.scan_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        return metadata;
    });
    
    auto status = scan_future.wait_for(std::chrono::seconds(timeout_seconds));
    
    if (status == std::future_status::timeout) {
        metadata.result = common::ScanResult::ERROR;
        metadata.error_code = CoreErrorCode::SCAN_TIMEOUT;
        metadata.error_message = CoreErrorCodeHelper::getMessage(CoreErrorCode::SCAN_TIMEOUT);
        
        common::ErrorContext ctx;
        ctx.component = "Engine";
        ctx.details["fd"] = std::to_string(fd);
        ctx.details["timeout_seconds"] = std::to_string(timeout_seconds);
        metadata.error_context = ctx;
        
        common::Logger::instance().warn("[Engine] Scan timeout | code={} | {}", 
                                       CoreErrorCodeHelper::toString(CoreErrorCode::SCAN_TIMEOUT),
                                       common::formatContext(ctx));
        return metadata;
    }
    
    return scan_future.get();
}

common::ScanMetadata SemanticsAVEngine::scan(const std::vector<uint8_t>& data, bool include_hashes) {
    common::ScanMetadata metadata;
    metadata.file_path = "<buffer>";
    metadata.file_size = data.size();
    
    if (!initialized_) {
        metadata.result = common::ScanResult::ERROR;
        metadata.error_code = CoreErrorCode::ENGINE_NOT_INITIALIZED;
        metadata.error_message = CoreErrorCodeHelper::getMessage(CoreErrorCode::ENGINE_NOT_INITIALIZED);
        
        common::ErrorContext ctx;
        ctx.component = "Engine";
        ctx.details["operation"] = "scan";
        metadata.error_context = ctx;
        
        return metadata;
    }
    
    if (data.empty()) {
        metadata.result = common::ScanResult::ERROR;
        metadata.error_code = CoreErrorCode::SCAN_FILE_EMPTY;
        metadata.error_message = CoreErrorCodeHelper::getMessage(CoreErrorCode::SCAN_FILE_EMPTY);
        
        common::ErrorContext ctx;
        ctx.component = "Engine";
        ctx.details["size"] = "0";
        metadata.error_context = ctx;
        
        common::Logger::instance().error("[Engine] Scan failed | code={} | {}", 
                                        CoreErrorCodeHelper::toString(CoreErrorCode::SCAN_FILE_EMPTY),
                                        common::formatContext(ctx));
        return metadata;
    }
    
    auto& config = common::Config::instance().global();
    int timeout_seconds = config.scan_timeout_seconds;
    
    auto scan_future = std::async(std::launch::async, [this, &data, &metadata, include_hashes]() {
        auto start_time = std::chrono::steady_clock::now();
        
        try {
            semantics_av::ScanResult scan_result;
            semantics_av::ScanOptions scan_options(include_hashes);
            auto result = core_engine_->scan(data.data(), data.size(), scan_result, &scan_options);
            
            if (result == semantics_av::Result::UNSUPPORTED_FORMAT) {
                metadata.result = common::ScanResult::UNSUPPORTED;
                metadata.confidence = 0.0f;
                metadata.error_code = CoreErrorCode::SCAN_UNSUPPORTED_FORMAT;
                
            } else if (result != semantics_av::Result::OK) {
                metadata.result = common::ScanResult::ERROR;
                CoreErrorCode error_code = mapSdkResult(result);
                metadata.error_code = error_code;
                metadata.error_message = CoreErrorCodeHelper::getMessage(error_code);
                
                common::ErrorContext ctx;
                ctx.component = "Engine";
                ctx.details["size"] = std::to_string(data.size());
                ctx.details["sdk_result"] = std::to_string(static_cast<int>(result));
                metadata.error_context = ctx;
                
            } else {
                metadata.file_type = scan_result.file_type;
                metadata.result = scan_result.is_malware ? 
                    common::ScanResult::MALICIOUS : 
                    common::ScanResult::CLEAN;
                
                metadata.confidence = scan_result.is_malware ?
                    scan_result.malware_probability :
                    (1.0f - scan_result.malware_probability);
                
                if (scan_result.file_hashes && !scan_result.file_hashes->empty()) {
                    metadata.file_hashes = scan_result.file_hashes;
                }
            }
            
        } catch (const std::exception& e) {
            metadata.result = common::ScanResult::ERROR;
            metadata.error_code = CoreErrorCode::SDK_INTERNAL_ERROR;
            metadata.error_message = e.what();
            
            common::ErrorContext ctx;
            ctx.component = "Engine";
            ctx.details["size"] = std::to_string(data.size());
            ctx.details["exception"] = e.what();
            metadata.error_context = ctx;
        }
        
        auto end_time = std::chrono::steady_clock::now();
        metadata.scan_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        return metadata;
    });
    
    auto status = scan_future.wait_for(std::chrono::seconds(timeout_seconds));
    
    if (status == std::future_status::timeout) {
        metadata.result = common::ScanResult::ERROR;
        metadata.error_code = CoreErrorCode::SCAN_TIMEOUT;
        metadata.error_message = CoreErrorCodeHelper::getMessage(CoreErrorCode::SCAN_TIMEOUT);
        
        common::ErrorContext ctx;
        ctx.component = "Engine";
        ctx.details["size"] = std::to_string(data.size());
        ctx.details["timeout_seconds"] = std::to_string(timeout_seconds);
        metadata.error_context = ctx;
        
        common::Logger::instance().warn("[Engine] Scan timeout | code={} | {}", 
                                       CoreErrorCodeHelper::toString(CoreErrorCode::SCAN_TIMEOUT),
                                       common::formatContext(ctx));
        return metadata;
    }
    
    return scan_future.get();
}

common::ScanMetadata SemanticsAVEngine::scan(std::istream& stream, bool include_hashes) {
    std::vector<uint8_t> buffer;
    
    stream.seekg(0, std::ios::end);
    size_t size = stream.tellg();
    stream.seekg(0, std::ios::beg);
    
    buffer.resize(size);
    stream.read(reinterpret_cast<char*>(buffer.data()), size);
    
    auto metadata = scan(buffer, include_hashes);
    metadata.file_path = "<stream>";
    return metadata;
}

bool SemanticsAVEngine::registerModel(const std::string& type, const ModelData& data) {
    if (!initialized_) {
        common::ErrorContext ctx;
        ctx.component = "Model";
        ctx.details["type"] = type;
        
        common::Logger::instance().error("[Model] Registration failed | code={} | {}", 
                                        CoreErrorCodeHelper::toString(CoreErrorCode::ENGINE_NOT_INITIALIZED),
                                        common::formatContext(ctx));
        return false;
    }
    
    try {
        auto result = core_engine_->registerModel(type, data.data.data(), data.data.size(),
                                                  data.signature.data(), data.signature.size(),
                                                  data.etag, data.server_created_at);
        
        if (result != semantics_av::Result::OK) {
            CoreErrorCode error_code = mapSdkResult(result);
            common::ErrorContext ctx;
            ctx.component = "Model";
            ctx.details["type"] = type;
            ctx.details["sdk_result"] = std::to_string(static_cast<int>(result));
            
            common::Logger::instance().error("[Model] Registration failed | code={} | {}", 
                                            CoreErrorCodeHelper::toString(error_code),
                                            common::formatContext(ctx));
            return false;
        }
        
        common::Logger::instance().info("[Model] Registered | type={} | size={}", 
                                       type, common::formatBytes(data.data.size()));
        return true;
        
    } catch (const std::exception& e) {
        common::ErrorContext ctx;
        ctx.component = "Model";
        ctx.details["type"] = type;
        ctx.details["exception"] = e.what();
        
        common::Logger::instance().error("[Model] Exception | code={} | {}", 
                                        CoreErrorCodeHelper::toString(CoreErrorCode::SDK_INTERNAL_ERROR),
                                        common::formatContext(ctx));
        return false;
    }
}

common::ModelInfo SemanticsAVEngine::getModelInfo(const std::string& type) {
    common::ModelInfo info;
    info.type = type;
    
    if (!initialized_) {
        return info;
    }
    
    try {
        semantics_av::ModelMetadata metadata;
        auto result = core_engine_->getModelMetadata(type, metadata);
        
        if (result == semantics_av::Result::OK) {
            info.version = metadata.etag;
            info.etag = metadata.etag;
            info.size = metadata.model_size;
            info.last_updated = std::chrono::system_clock::from_time_t(metadata.last_updated);
            info.server_created_at = std::chrono::system_clock::from_time_t(metadata.server_created_at);
        }
        
    } catch (const std::exception& e) {
        common::Logger::instance().debug("[Model] Info unavailable | type={}", type);
    }
    
    return info;
}

AnalysisPayload SemanticsAVEngine::extractAnalysisPayload(const std::filesystem::path& file_path, 
                                                        const std::string& language) {
    AnalysisPayload payload;
    
    if (!initialized_) {
        return payload;
    }
    
    try {
        semantics_av::AnalysisPayload core_payload;
        semantics_av::ReportOptions* report_options_ptr = nullptr;
        semantics_av::ReportOptions report_options;
        
        if (!language.empty()) {
            report_options = semantics_av::ReportOptions(language);
            report_options_ptr = &report_options;
        }
        
        auto result = core_engine_->extractAnalysisPayload(file_path.string(), core_payload, report_options_ptr);
        
        payload.sdk_result = result;
        
        if (result == semantics_av::Result::OK) {
            payload.file_type = core_payload.file_type;
            payload.file_hashes = core_payload.file_hashes;
            payload.analysis_blob = core_payload.analysis_blob;
            payload.report_options_json = core_payload.report_options_json;
            
            common::Logger::instance().debug("[Payload] Extracted | file={} | type={} | size={}", 
                                            file_path.string(), payload.file_type, 
                                            common::formatBytes(payload.analysis_blob.size()));
        } else {
            CoreErrorCode error_code = mapSdkResult(result);
            common::ErrorContext ctx;
            ctx.component = "Payload";
            ctx.details["path"] = file_path.string();
            ctx.details["sdk_result"] = std::to_string(static_cast<int>(result));
            
            common::Logger::instance().debug("[Payload] Extraction failed | code={} | {}", 
                                            CoreErrorCodeHelper::toString(error_code),
                                            common::formatContext(ctx));
        }
        
    } catch (const std::exception& e) {
        common::ErrorContext ctx;
        ctx.component = "Payload";
        ctx.details["path"] = file_path.string();
        ctx.details["exception"] = e.what();
        
        common::Logger::instance().error("[Payload] Extraction failed | code={} | {}", 
                                        CoreErrorCodeHelper::toString(CoreErrorCode::ANALYSIS_EXTRACTION_FAILED),
                                        common::formatContext(ctx));
    }
    
    return payload;
}

AnalysisPayload SemanticsAVEngine::extractAnalysisPayloadFromFd(int fd, const std::string& language) {
    AnalysisPayload payload;
    
    if (!initialized_) {
        return payload;
    }
    
    if (fd < 0) {
        return payload;
    }
    
    try {
        off_t current_pos = lseek(fd, 0, SEEK_CUR);
        if (current_pos == -1) {
            return payload;
        }
        
        off_t file_size = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        
        std::vector<uint8_t> buffer(file_size);
        ssize_t bytes_read = read(fd, buffer.data(), file_size);
        
        if (bytes_read != file_size) {
            lseek(fd, current_pos, SEEK_SET);
            return payload;
        }
        
        lseek(fd, current_pos, SEEK_SET);
        
        semantics_av::AnalysisPayload core_payload;
        semantics_av::ReportOptions* report_options_ptr = nullptr;
        semantics_av::ReportOptions report_options;
        
        if (!language.empty()) {
            report_options = semantics_av::ReportOptions(language);
            report_options_ptr = &report_options;
        }
        
        auto result = core_engine_->extractAnalysisPayload(buffer.data(), buffer.size(), core_payload, report_options_ptr);
        
        payload.sdk_result = result;
        
        if (result == semantics_av::Result::OK) {
            payload.file_type = core_payload.file_type;
            payload.file_hashes = core_payload.file_hashes;
            payload.analysis_blob = core_payload.analysis_blob;
            payload.report_options_json = core_payload.report_options_json;
        }
        
    } catch (const std::exception& e) {
        common::Logger::instance().error("[Payload] Extraction from FD failed | fd={} | error={}", fd, e.what());
    }
    
    return payload;
}

AnalysisPayload SemanticsAVEngine::extractAnalysisPayload(const std::vector<uint8_t>& data, 
                                                        const std::string& language) {
    AnalysisPayload payload;
    
    if (!initialized_) {
        return payload;
    }
    
    try {
        semantics_av::AnalysisPayload core_payload;
        semantics_av::ReportOptions* report_options_ptr = nullptr;
        semantics_av::ReportOptions report_options;
        
        if (!language.empty()) {
            report_options = semantics_av::ReportOptions(language);
            report_options_ptr = &report_options;
        }
        
        auto result = core_engine_->extractAnalysisPayload(data.data(), data.size(), core_payload, report_options_ptr);
        
        payload.sdk_result = result;
        
        if (result == semantics_av::Result::OK) {
            payload.file_type = core_payload.file_type;
            payload.file_hashes = core_payload.file_hashes;
            payload.analysis_blob = core_payload.analysis_blob;
            payload.report_options_json = core_payload.report_options_json;
        }
        
    } catch (const std::exception& e) {
        common::Logger::instance().error("[Payload] Extraction from buffer failed | size={} | error={}", 
                                        data.size(), e.what());
    }
    
    return payload;
}

AnalysisPayload SemanticsAVEngine::extractAnalysisPayload(std::istream& stream,
                                                        const std::string& language) {
    std::vector<uint8_t> buffer;
    
    stream.seekg(0, std::ios::end);
    size_t size = stream.tellg();
    stream.seekg(0, std::ios::beg);
    
    buffer.resize(size);
    stream.read(reinterpret_cast<char*>(buffer.data()), size);
    
    return extractAnalysisPayload(buffer, language);
}

std::vector<std::string> SemanticsAVEngine::getSupportedTypes() const {
    return constants::file_types::getSupported();
}

}}