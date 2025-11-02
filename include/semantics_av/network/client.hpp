#pragma once

#include "../core/engine.hpp"
#include <string>
#include <future>
#include <optional>

namespace semantics_av {
namespace network {

struct LabelStatistics {
    int count = 0;
    std::optional<float> max_similarity;
    std::optional<float> avg_similarity;
};

struct SignatureStatistics {
    int count = 0;
    float max_similarity = 0.0f;
    float avg_similarity = 0.0f;
};

struct Statistics {
    int processed_samples = 0;
    LabelStatistics malicious;
    LabelStatistics suspicious;
    LabelStatistics clean;
    LabelStatistics unknown;
    std::map<std::string, SignatureStatistics> by_signature;
};

struct SimilarSample {
    std::map<std::string, std::string> file_hashes;
    float similarity_score = 0.0f;
    std::vector<std::string> tags;
    std::optional<std::string> signature;
    std::optional<std::string> static_attributes_json;
};

struct Intelligence {
    std::vector<SimilarSample> similar_samples;
    Statistics statistics;
};

struct AnalysisResult {
    std::string verdict;
    float confidence = 0.0f;
    std::vector<std::string> tags;
    std::optional<std::string> signature;
    std::optional<std::string> static_attributes_json;
    std::string natural_language_report;
    std::map<std::string, std::string> file_hashes;
    std::string file_type;
    std::string analysis_timestamp;
    std::string sdk_version;
    Intelligence intelligence;
};

class NetworkClient {
public:
    NetworkClient(const std::string& api_key, 
                  int timeout_seconds = 120);
    ~NetworkClient();
    
    std::future<AnalysisResult> analyzeAsync(const core::AnalysisPayload& data);
    std::future<bool> checkApiHealthAsync();
    
    void updateConfig(const std::string& api_key, int timeout_seconds);
    
    bool isAvailable() const { return !api_key_.empty(); }

private:
    std::string api_key_;
    int timeout_seconds_;
    
    class Impl;
    std::unique_ptr<Impl> pimpl_;
    
    std::string buildAnalysisUrl() const;
    std::string buildHealthUrl() const;
};

}}