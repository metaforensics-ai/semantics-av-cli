#include "semantics_av/network/analysis_service.hpp"
#include "semantics_av/update/updater.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/constants.hpp"

namespace semantics_av {
namespace network {

AnalysisService::AnalysisService(
    core::SemanticsAVEngine* engine,
    const std::string& api_key,
    int network_timeout)
    : engine_(engine)
    , network_timeout_(network_timeout) {
    
    client_ = std::make_shared<NetworkClient>(api_key, network_timeout);
    downloader_ = std::make_shared<ModelDownloader>(network_timeout);
}

AnalysisService::~AnalysisService() = default;

void AnalysisService::updateConfig(const std::string& api_key, int network_timeout) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    network_timeout_ = network_timeout;
    
    if (client_) {
        client_->updateConfig(api_key, network_timeout);
    }
    
    if (downloader_) {
        downloader_->updateConfig(network_timeout);
    }
    
    common::Logger::instance().info("[AnalysisService] Config updated | timeout={}", network_timeout);
}

AnalysisResult AnalysisService::analyze(const core::AnalysisPayload& payload) {
    std::shared_ptr<NetworkClient> local_client;
    std::shared_ptr<ModelDownloader> local_downloader;
    
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        local_client = client_;
        local_downloader = downloader_;
    }
    
    auto analysis_future = local_client->analyzeAsync(payload);
    auto result = analysis_future.get();
    
    if (result.verdict == "model_incompatible") {
        common::Logger::instance().warn("[CloudAnalysis] Model incompatible (409) | type={}", 
                                        payload.file_type);
        
        if (tryUpdateModel(payload.file_type, local_downloader)) {
            common::Logger::instance().info("[CloudAnalysis] Retrying after model update | type={}", 
                                           payload.file_type);
            
            auto retry_future = local_client->analyzeAsync(payload);
            result = retry_future.get();
            
            if (result.verdict == "model_incompatible") {
                common::Logger::instance().error("[CloudAnalysis] Still incompatible after update | type={}", 
                                                 payload.file_type);
                result.verdict = "error";
            }
        } else {
            common::Logger::instance().error("[CloudAnalysis] Model update failed | type={}", 
                                            payload.file_type);
            result.verdict = "error";
        }
    }
    
    return result;
}

bool AnalysisService::tryUpdateModel(const std::string& file_type,
                                     const std::shared_ptr<ModelDownloader>& downloader) {
    common::Logger::instance().info("[CloudAnalysis] Auto-updating model | type={}", file_type);
    
    try {
        update::ModelUpdater updater(engine_, downloader.get());
        
        update::UpdateOptions options;
        options.model_types = {file_type};
        options.force_update = true;
        options.check_only = false;
        options.quiet = true;
        
        auto summary = updater.updateModelsSync(options);
        
        if (summary.updated_models > 0) {
            common::Logger::instance().info("[CloudAnalysis] Model updated successfully | type={}", 
                                           file_type);
            return true;
        } else {
            common::Logger::instance().error("[CloudAnalysis] Model update failed | type={} | failed={}", 
                                            file_type, summary.failed_models);
            return false;
        }
        
    } catch (const std::exception& e) {
        common::Logger::instance().error("[CloudAnalysis] Update exception | type={} | error={}", 
                                        file_type, e.what());
        return false;
    }
}

}}