#pragma once

#include "../common/types.hpp"
#include "../core/engine.hpp"
#include "../network/downloader.hpp"
#include <string>
#include <vector>
#include <future>

namespace semantics_av {
namespace update {

struct UpdateOptions {
    std::vector<std::string> model_types;
    bool force_update = false;
    bool check_only = false;
    bool quiet = false;
};

struct ModelVersionInfo {
    std::string model_type;
    int64_t current_timestamp = 0;
    int64_t server_timestamp = 0;
    bool update_available = false;
    bool has_local_version = false;
};

struct UpdateSummary {
    size_t total_models = 0;
    size_t updated_models = 0;
    size_t failed_models = 0;
    std::vector<std::string> updated_types;
    std::vector<std::string> failed_types;
    std::vector<ModelVersionInfo> version_info;
    std::chrono::milliseconds total_time{0};
};

class ModelUpdater {
public:
    ModelUpdater(core::SemanticsAVEngine* engine,
                 network::ModelDownloader* downloader);
    ~ModelUpdater();
    
    std::future<UpdateSummary> updateModelsAsync(const UpdateOptions& options);
    UpdateSummary updateModelsSync(const UpdateOptions& options);
    
    std::vector<std::string> checkForUpdates(const std::vector<std::string>& model_types);
    bool needsUpdate(const std::string& model_type);
    
    void setProgressCallback(std::function<void(const std::string&, size_t, size_t)> callback);

private:
    core::SemanticsAVEngine* engine_;
    network::ModelDownloader* downloader_;
    std::function<void(const std::string&, size_t, size_t)> progress_callback_;
    
    std::vector<std::string> getDefaultModelTypes();
    bool validateModelType(const std::string& type);
    std::map<std::string, std::string> getCurrentModelEtags(const std::vector<std::string>& model_types);
    std::map<std::string, int64_t> getCurrentModelTimestamps(const std::vector<std::string>& model_types);
};

}}