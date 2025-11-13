#include "semantics_av/update/updater.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/constants.hpp"
#include <algorithm>

namespace semantics_av {
namespace update {

ModelUpdater::ModelUpdater(core::SemanticsAVEngine* engine,
                           network::ModelDownloader* downloader)
    : engine_(engine), downloader_(downloader) {}

ModelUpdater::~ModelUpdater() = default;

std::future<UpdateSummary> ModelUpdater::updateModelsAsync(const UpdateOptions& options) {
    return std::async(std::launch::async, [this, options]() {
        return updateModelsSync(options);
    });
}

UpdateSummary ModelUpdater::updateModelsSync(const UpdateOptions& options) {
    auto start_time = std::chrono::steady_clock::now();
    
    UpdateSummary summary;
    
    std::vector<std::string> model_types = options.model_types;
    if (model_types.empty()) {
        model_types = getDefaultModelTypes();
    }
    
    summary.total_models = model_types.size();
    
    common::Logger::instance().info("[Updater] Starting | models={} | check_only={} | force={}", 
                                    summary.total_models, options.check_only, options.force_update);
    
    if (options.check_only) {
        for (const auto& type : model_types) {
            ModelVersionInfo version_info;
            version_info.model_type = type;
            
            try {
                auto local_info = engine_->getModelInfo(type);
                
                if (!local_info.etag.empty()) {
                    version_info.has_local_version = true;
                    version_info.current_timestamp = std::chrono::system_clock::to_time_t(
                        local_info.server_created_at);
                }
                
                auto metadata_future = downloader_->checkModelMetadataAsync(type, local_info.etag);
                auto metadata = metadata_future.get();
                
                if (metadata.success) {
                    version_info.server_timestamp = metadata.server_timestamp;
                    version_info.update_available = metadata.is_newer;
                    
                    common::Logger::instance().debug("[Updater] Metadata check | type={} | local={} | server={} | update_available={}", 
                                                     type, version_info.current_timestamp, 
                                                     version_info.server_timestamp, version_info.update_available);
                } else {
                    common::Logger::instance().error("[Updater] Metadata check failed | type={} | error={}", 
                                                      type, metadata.error_message);
                }
                
            } catch (const std::exception& e) {
                common::Logger::instance().error("[Updater] Exception during check | type={} | error={}", 
                                                  type, e.what());
            }
            
            summary.version_info.push_back(version_info);
        }
        
        auto end_time = std::chrono::steady_clock::now();
        summary.total_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        common::Logger::instance().info("[Updater] Check complete | duration_ms={}", summary.total_time.count());
        return summary;
    }
    
    std::map<std::string, std::string> current_etags;
    std::map<std::string, int64_t> current_timestamps;
    
    if (!options.force_update) {
        current_etags = getCurrentModelEtags(model_types);
        current_timestamps = getCurrentModelTimestamps(model_types);
    }
    
    if (progress_callback_) {
        downloader_->setProgressCallback([this](const std::string& type, size_t current, size_t total) {
            if (progress_callback_) {
                progress_callback_(type, current, total);
            }
        });
    }
    
    try {
        auto download_future = downloader_->downloadModelsAsync(model_types, current_etags);
        auto download_results = download_future.get();
        
        for (const auto& result : download_results) {
            ModelVersionInfo version_info;
            version_info.model_type = result.file_type;
            
            auto ts_it = current_timestamps.find(result.file_type);
            if (ts_it != current_timestamps.end()) {
                version_info.current_timestamp = ts_it->second;
                version_info.has_local_version = true;
            }
            
            if (!result.success) {
                summary.failed_models++;
                summary.failed_types.push_back(result.file_type);
                common::Logger::instance().error("[Updater] Download failed | type={} | error={}", 
                                                  result.file_type, result.error_message);
                
                version_info.update_available = false;
                summary.version_info.push_back(version_info);
                continue;
            }
            
            if (!result.updated) {
                common::Logger::instance().debug("[Updater] Up to date | type={}", result.file_type);
                
                version_info.server_timestamp = version_info.current_timestamp;
                version_info.update_available = false;
                summary.version_info.push_back(version_info);
                continue;
            }
            
            if (result.data) {
                version_info.server_timestamp = result.data->server_created_at;
                version_info.update_available = true;
                
                if (engine_->registerModel(result.file_type, *result.data)) {
                    summary.updated_models++;
                    summary.updated_types.push_back(result.file_type);
                    common::Logger::instance().info("[Updater] Model updated | type={} | timestamp={}", 
                                                     result.file_type, result.data->server_created_at);
                } else {
                    summary.failed_models++;
                    summary.failed_types.push_back(result.file_type);
                    common::Logger::instance().error("[Updater] Registration failed | type={}", result.file_type);
                }
            }
            
            summary.version_info.push_back(version_info);
        }
        
    } catch (const std::exception& e) {
        common::Logger::instance().error("[Updater] Exception | error={}", e.what());
        summary.failed_models = summary.total_models;
        
        for (const auto& type : model_types) {
            summary.failed_types.push_back(type);
        }
    }
    
    auto end_time = std::chrono::steady_clock::now();
    summary.total_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    common::Logger::instance().info("[Updater] Complete | updated={} | failed={} | duration_ms={}",
                                     summary.updated_models, summary.failed_models, 
                                     summary.total_time.count());
    
    return summary;
}

std::vector<std::string> ModelUpdater::checkForUpdates(const std::vector<std::string>& model_types) {
    std::vector<std::string> updates_needed;
    
    for (const auto& type : model_types) {
        if (needsUpdate(type)) {
            updates_needed.push_back(type);
        }
    }
    
    common::Logger::instance().info("[Updater] Check complete | updates_needed={}", updates_needed.size());
    return updates_needed;
}

bool ModelUpdater::needsUpdate(const std::string& model_type) {
    if (!validateModelType(model_type)) {
        return false;
    }
    
    try {
        auto local_info = engine_->getModelInfo(model_type);
        
        if (local_info.etag.empty()) {
            return true;
        }
        
        auto now = std::chrono::system_clock::now();
        auto time_since_update = now - local_info.server_created_at;
        auto hours_since_update = std::chrono::duration_cast<std::chrono::hours>(time_since_update);
        
        return hours_since_update.count() >= 24;
        
    } catch (const std::exception& e) {
        common::Logger::instance().debug("[Updater] Info unavailable | type={}", model_type);
        return true;
    }
}

void ModelUpdater::setProgressCallback(std::function<void(const std::string&, size_t, size_t)> callback) {
    progress_callback_ = std::move(callback);
}

std::vector<std::string> ModelUpdater::getDefaultModelTypes() {
    return constants::file_types::getSupported();
}

bool ModelUpdater::validateModelType(const std::string& type) {
    return constants::file_types::isSupported(type);
}

std::map<std::string, std::string> ModelUpdater::getCurrentModelEtags(const std::vector<std::string>& model_types) {
    std::map<std::string, std::string> etags;
    
    for (const auto& type : model_types) {
        try {
            auto info = engine_->getModelInfo(type);
            if (!info.etag.empty()) {
                etags[type] = info.etag;
            }
        } catch (const std::exception&) {
        }
    }
    
    common::Logger::instance().debug("[Updater] Current etags | count={}", etags.size());
    return etags;
}

std::map<std::string, int64_t> ModelUpdater::getCurrentModelTimestamps(const std::vector<std::string>& model_types) {
    std::map<std::string, int64_t> timestamps;
    
    for (const auto& type : model_types) {
        try {
            auto info = engine_->getModelInfo(type);
            auto time_t_val = std::chrono::system_clock::to_time_t(info.server_created_at);
            timestamps[type] = static_cast<int64_t>(time_t_val);
        } catch (const std::exception&) {
        }
    }
    
    common::Logger::instance().debug("[Updater] Current timestamps | count={}", timestamps.size());
    return timestamps;
}

}}