#pragma once

#include "../common/types.hpp"
#include <semantics_av/semantics_av.hpp>
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <istream>

namespace semantics_av {
namespace core {

struct ModelData {
    std::vector<uint8_t> data;
    std::vector<uint8_t> signature;
    std::string etag;
    int64_t server_created_at = 0;
};

struct AnalysisPayload {
    std::string file_type;
    std::map<std::string, std::string> file_hashes;
    std::vector<uint8_t> analysis_blob;
    std::string report_options_json;
    std::optional<semantics_av::Result> sdk_result;
    
    bool isValid() const {
        return sdk_result && *sdk_result == semantics_av::Result::OK;
    }
};

class SemanticsAVEngine {
public:
    SemanticsAVEngine();
    ~SemanticsAVEngine();
    
    bool initialize(const std::string& base_path, const std::string& api_key = "");
    void cleanup();
    
    common::ScanMetadata scan(const std::filesystem::path& file_path, bool include_hashes = false);
    common::ScanMetadata scan(const std::vector<uint8_t>& data, bool include_hashes = false);
    common::ScanMetadata scan(std::istream& stream, bool include_hashes = false);
    common::ScanMetadata scanFromFd(int fd, bool include_hashes = false);
    
    bool registerModel(const std::string& type, const ModelData& data);
    common::ModelInfo getModelInfo(const std::string& type);
    
    AnalysisPayload extractAnalysisPayload(const std::filesystem::path& file_path, 
                                           const std::string& language = "");
    AnalysisPayload extractAnalysisPayload(const std::vector<uint8_t>& data, 
                                           const std::string& language = "");
    AnalysisPayload extractAnalysisPayload(std::istream& stream,
                                           const std::string& language = "");
    AnalysisPayload extractAnalysisPayloadFromFd(int fd, const std::string& language = "");
    
    std::vector<std::string> getSupportedTypes() const;
    bool isInitialized() const { return initialized_; }

private:
    std::unique_ptr<semantics_av::SemanticsAV> core_engine_;
    bool initialized_ = false;
    std::string base_path_;
};

}}