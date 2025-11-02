#pragma once

#include "../core/engine.hpp"
#include "client.hpp"
#include "downloader.hpp"
#include <string>
#include <memory>
#include <mutex>

namespace semantics_av {
namespace network {

class AnalysisService {
public:
    AnalysisService(
        core::SemanticsAVEngine* engine,
        const std::string& api_key,
        int network_timeout
    );
    
    ~AnalysisService();
    
    AnalysisResult analyze(const core::AnalysisPayload& payload);
    
    void updateConfig(const std::string& api_key, int network_timeout);

private:
    core::SemanticsAVEngine* engine_;
    std::shared_ptr<NetworkClient> client_;
    std::shared_ptr<ModelDownloader> downloader_;
    int network_timeout_;
    mutable std::mutex config_mutex_;
    
    bool tryUpdateModel(const std::string& file_type, 
                       const std::shared_ptr<ModelDownloader>& downloader);
};

}}