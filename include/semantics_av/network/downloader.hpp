#pragma once

#include "../core/engine.hpp"
#include <string>
#include <vector>
#include <future>
#include <map>
#include <functional>

namespace semantics_av {
namespace network {

struct ModelDownloadResult {
    std::string file_type;
    bool success = false;
    bool updated = false;
    std::optional<core::ModelData> data;
    std::string error_message;
};

using DownloadProgressCallback = std::function<void(
    const std::string& model_type,
    size_t current_bytes,
    size_t total_bytes
)>;

class ModelDownloader {
public:
    ModelDownloader(int timeout_seconds = 120);
    ~ModelDownloader();
    
    std::future<std::vector<ModelDownloadResult>> downloadModelsAsync(
        const std::vector<std::string>& model_types,
        const std::map<std::string, std::string>& current_etags = {});
    
    std::future<ModelDownloadResult> downloadSingleModelAsync(
        const std::string& model_type,
        const std::string& current_etag = "");
    
    void updateConfig(int timeout_seconds);
    
    void setProgressCallback(DownloadProgressCallback callback);

private:
    int timeout_seconds_;
    
    class Impl;
    std::unique_ptr<Impl> pimpl_;
    
    std::string buildModelUrl(const std::string& model_type) const;
    bool validateModelSignature(const std::vector<uint8_t>& data, 
                                  const std::vector<uint8_t>& signature);
};

}}