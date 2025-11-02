#include "semantics_av/network/client.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/constants.hpp"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <future>
#include <mutex>

namespace semantics_av {
namespace network {

class NetworkClient::Impl {
public:
    Impl(const std::string& api_key, int timeout_seconds)
        : api_key_(api_key), timeout_(timeout_seconds) {
        
        std::string base_url = constants::network::DEFAULT_API_URL;
        
        size_t scheme_pos = base_url.find("://");
        if (scheme_pos != std::string::npos) {
            std::string scheme = base_url.substr(0, scheme_pos);
            std::string host_and_port = base_url.substr(scheme_pos + 3);
            
            size_t port_pos = host_and_port.find(':');
            if (port_pos != std::string::npos) {
                host_ = host_and_port.substr(0, port_pos);
                port_ = std::stoi(host_and_port.substr(port_pos + 1));
            } else {
                host_ = host_and_port;
                port_ = (scheme == "https") ? 443 : 80;
            }
            
            is_https_ = (scheme == "https");
        } else {
            host_ = base_url;
            port_ = 80;
            is_https_ = false;
        }
        
        if (is_https_) {
            https_client_ = std::make_unique<httplib::SSLClient>(host_, port_);
            https_client_->set_connection_timeout(timeout_seconds, 0);
            https_client_->set_read_timeout(timeout_seconds, 0);
            https_client_->set_write_timeout(timeout_seconds, 0);
            https_client_->enable_server_certificate_verification(true);
        } else {
            http_client_ = std::make_unique<httplib::Client>(host_, port_);
            http_client_->set_connection_timeout(timeout_seconds, 0);
            http_client_->set_read_timeout(timeout_seconds, 0);
            http_client_->set_write_timeout(timeout_seconds, 0);
        }
        
        common::Logger::instance().debug("[API] Client initialized | host={} | port={} | https={}", 
                                         host_, port_, is_https_);
    }
    
    void updateConfig(const std::string& api_key, int timeout_seconds) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        api_key_ = api_key;
        timeout_ = timeout_seconds;
        
        if (is_https_) {
            https_client_->set_connection_timeout(timeout_seconds, 0);
            https_client_->set_read_timeout(timeout_seconds, 0);
            https_client_->set_write_timeout(timeout_seconds, 0);
        } else {
            http_client_->set_connection_timeout(timeout_seconds, 0);
            http_client_->set_read_timeout(timeout_seconds, 0);
            http_client_->set_write_timeout(timeout_seconds, 0);
        }
        
        common::Logger::instance().info("[API] Config updated | timeout={}", timeout_seconds);
    }
    
    std::future<AnalysisResult> analyzeAsync(const core::AnalysisPayload& data) {
        return std::async(std::launch::async, [this, data]() {
            try {
                std::lock_guard<std::mutex> lock(mutex_);
                
                common::Logger::instance().info("[API] Analysis request | type={} | size={}", 
                                                data.file_type, data.analysis_blob.size());
                
                nlohmann::json json_data;
                json_data["file_type"] = data.file_type;
                json_data["file_hashes"] = data.file_hashes;
                
                std::string analysis_blob_b64;
                if (!data.analysis_blob.empty()) {
                    analysis_blob_b64 = encodeBase64(data.analysis_blob);
                }
                json_data["analysis_payload"] = analysis_blob_b64;
                
                if (!data.report_options_json.empty() && data.report_options_json != "{}") {
                    try {
                        auto report_json = nlohmann::json::parse(data.report_options_json);
                        if (!report_json.empty()) {
                            json_data["report_options"] = report_json;
                        }
                    } catch (const std::exception& e) {
                        common::Logger::instance().warn("[API] Report options parse failed | error={}", e.what());
                    }
                }
                
                httplib::Headers headers = {
                    {"X-API-Key", api_key_},
                    {"User-Agent", "SemanticsAV-CLI/1.0"}
                };
                
                std::string json_str = json_data.dump();
                
                httplib::Result result;
                if (is_https_) {
                    result = https_client_->Post("/v1/analyses", headers, json_str, "application/json");
                } else {
                    result = http_client_->Post("/v1/analyses", headers, json_str, "application/json");
                }
                
                return parseAnalysisResponse(result);
                
            } catch (const std::exception& e) {
                common::Logger::instance().error("[API] Request exception | error={}", e.what());
                AnalysisResult error_result;
                error_result.verdict = "error";
                return error_result;
            }
        });
    }
    
    std::future<bool> checkApiHealthAsync() {
        return std::async(std::launch::async, [this]() {
            try {
                std::lock_guard<std::mutex> lock(mutex_);
                
                httplib::Headers headers = {
                    {"X-API-Key", api_key_},
                    {"User-Agent", "SemanticsAV-CLI/1.0"}
                };
                
                httplib::Result result;
                if (is_https_) {
                    result = https_client_->Get("/v1/health", headers);
                } else {
                    result = http_client_->Get("/v1/health", headers);
                }
                
                bool healthy = result && result->status == 200;
                common::Logger::instance().debug("[API] Health check | healthy={}", healthy);
                return healthy;
                
            } catch (const std::exception& e) {
                common::Logger::instance().error("[API] Health check failed | error={}", e.what());
                return false;
            }
        });
    }

private:
    std::string api_key_;
    std::string host_;
    int port_;
    int timeout_;
    bool is_https_;
    std::unique_ptr<httplib::Client> http_client_;
    std::unique_ptr<httplib::SSLClient> https_client_;
    std::mutex mutex_;
    
    LabelStatistics parseLabelStatistics(const nlohmann::json& label_json) {
        LabelStatistics stats;
        stats.count = label_json.value("count", 0);
        if (label_json.contains("max_similarity") && !label_json["max_similarity"].is_null()) {
            stats.max_similarity = label_json["max_similarity"];
        }
        if (label_json.contains("avg_similarity") && !label_json["avg_similarity"].is_null()) {
            stats.avg_similarity = label_json["avg_similarity"];
        }
        return stats;
    }
    
    AnalysisResult parseAnalysisResponse(const httplib::Result& result) {
        AnalysisResult analysis_result;
        
        try {
            if (!result) {
                common::Logger::instance().error("[API] Network error");
                analysis_result.verdict = "error";
                return analysis_result;
            }
            
            if (result->status == 409) {
                common::Logger::instance().warn("[API] Model incompatible (409)");
                analysis_result.verdict = "model_incompatible";
                return analysis_result;
            }
            
            if (result->status < 200 || result->status >= 300) {
                common::Logger::instance().error("[API] HTTP error | status={}", result->status);
                if (!result->body.empty()) {
                    common::Logger::instance().debug("[API] Response body | body={}", result->body);
                }
                analysis_result.verdict = "error";
                return analysis_result;
            }
            
            auto json_data = nlohmann::json::parse(result->body);
            
            if (json_data.contains("file_type")) {
                analysis_result.file_type = json_data["file_type"];
            }
            
            if (json_data.contains("file_hashes")) {
                auto hashes = json_data["file_hashes"];
                if (hashes.is_object()) {
                    for (auto it = hashes.begin(); it != hashes.end(); ++it) {
                        analysis_result.file_hashes[it.key()] = it.value();
                    }
                }
            }
            
            if (json_data.contains("analysis_timestamp")) {
                analysis_result.analysis_timestamp = json_data["analysis_timestamp"];
            }
            
            if (json_data.contains("detection")) {
                auto detection = json_data["detection"];
                
                if (detection.contains("verdict")) {
                    analysis_result.verdict = detection["verdict"];
                }
                if (detection.contains("confidence")) {
                    analysis_result.confidence = detection["confidence"];
                }
                if (detection.contains("tags") && detection["tags"].is_array()) {
                    for (const auto& tag : detection["tags"]) {
                        analysis_result.tags.push_back(tag);
                    }
                }
                if (detection.contains("signature") && !detection["signature"].is_null()) {
                    analysis_result.signature = detection["signature"];
                }
                if (detection.contains("static_attributes") && !detection["static_attributes"].is_null()) {
                    analysis_result.static_attributes_json = detection["static_attributes"].dump();
                }
            }
            
            if (json_data.contains("intelligence")) {
                auto intelligence = json_data["intelligence"];
                
                if (intelligence.contains("similar_samples") && intelligence["similar_samples"].is_array()) {
                    for (const auto& sample : intelligence["similar_samples"]) {
                        SimilarSample similar;
                        
                        if (sample.contains("file_hashes") && sample["file_hashes"].is_object()) {
                            for (auto it = sample["file_hashes"].begin(); it != sample["file_hashes"].end(); ++it) {
                                similar.file_hashes[it.key()] = it.value();
                            }
                        }
                        
                        if (sample.contains("similarity_score")) {
                            similar.similarity_score = sample["similarity_score"];
                        }
                        
                        if (sample.contains("tags") && sample["tags"].is_array()) {
                            for (const auto& tag : sample["tags"]) {
                                similar.tags.push_back(tag);
                            }
                        }
                        
                        if (sample.contains("signature") && !sample["signature"].is_null()) {
                            similar.signature = sample["signature"];
                        }
                        
                        if (sample.contains("static_attributes") && !sample["static_attributes"].is_null()) {
                            similar.static_attributes_json = sample["static_attributes"].dump();
                        }
                        
                        analysis_result.intelligence.similar_samples.push_back(similar);
                    }
                }
                
                if (intelligence.contains("statistics")) {
                    auto stats = intelligence["statistics"];
                    
                    if (stats.contains("processed_samples")) {
                        analysis_result.intelligence.statistics.processed_samples = stats["processed_samples"];
                    }
                    
                    if (stats.contains("by_label")) {
                        auto by_label = stats["by_label"];
                        
                        if (by_label.contains("malicious")) {
                            analysis_result.intelligence.statistics.malicious = parseLabelStatistics(by_label["malicious"]);
                        }
                        
                        if (by_label.contains("suspicious")) {
                            analysis_result.intelligence.statistics.suspicious = parseLabelStatistics(by_label["suspicious"]);
                        }
                        
                        if (by_label.contains("clean")) {
                            analysis_result.intelligence.statistics.clean = parseLabelStatistics(by_label["clean"]);
                        }
                        
                        if (by_label.contains("unknown")) {
                            analysis_result.intelligence.statistics.unknown = parseLabelStatistics(by_label["unknown"]);
                        }
                    }
                    
                    if (stats.contains("by_signature") && stats["by_signature"].is_object()) {
                        for (auto it = stats["by_signature"].begin(); it != stats["by_signature"].end(); ++it) {
                            SignatureStatistics sig_stat;
                            sig_stat.count = it.value().value("count", 0);
                            sig_stat.max_similarity = it.value().value("max_similarity", 0.0f);
                            sig_stat.avg_similarity = it.value().value("avg_similarity", 0.0f);
                            analysis_result.intelligence.statistics.by_signature[it.key()] = sig_stat;
                        }
                    }
                }
            }
            
            if (json_data.contains("natural_language_report") && !json_data["natural_language_report"].is_null()) {
                analysis_result.natural_language_report = json_data["natural_language_report"];
            }
            
            common::Logger::instance().info("[API] Analysis complete | verdict={} | confidence={:.1f}", 
                                           analysis_result.verdict, analysis_result.confidence * 100);
            
        } catch (const std::exception& e) {
            common::Logger::instance().error("[API] Parse failed | error={}", e.what());
            analysis_result.verdict = "error";
        }
        
        return analysis_result;
    }
    
    std::string encodeBase64(const std::vector<uint8_t>& data) {
        const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string encoded;
        encoded.reserve(((data.size() + 2) / 3) * 4);
        
        size_t i = 0;
        while (i < data.size()) {
            uint32_t tmp = 0;
            int count = 0;
            
            for (int j = 0; j < 3 && i < data.size(); ++j, ++i) {
                tmp = (tmp << 8) | data[i];
                count++;
            }
            
            tmp <<= (3 - count) * 8;
            
            for (int j = 0; j < 4; ++j) {
                if (j <= count) {
                    encoded += chars[(tmp >> (18 - j * 6)) & 0x3F];
                } else {
                    encoded += '=';
                }
            }
        }
        
        return encoded;
    }
};

NetworkClient::NetworkClient(const std::string& api_key, int timeout_seconds)
    : api_key_(api_key), timeout_seconds_(timeout_seconds) {
    pimpl_ = std::make_unique<Impl>(api_key, timeout_seconds);
}

NetworkClient::~NetworkClient() = default;

std::future<AnalysisResult> NetworkClient::analyzeAsync(const core::AnalysisPayload& data) {
    return pimpl_->analyzeAsync(data);
}

std::future<bool> NetworkClient::checkApiHealthAsync() {
    return pimpl_->checkApiHealthAsync();
}

void NetworkClient::updateConfig(const std::string& api_key, int timeout_seconds) {
    api_key_ = api_key;
    timeout_seconds_ = timeout_seconds;
    pimpl_->updateConfig(api_key, timeout_seconds);
}

std::string NetworkClient::buildAnalysisUrl() const {
    return std::string(constants::network::DEFAULT_API_URL) + "/v1/analyses";
}

std::string NetworkClient::buildHealthUrl() const {
    return std::string(constants::network::DEFAULT_API_URL) + "/v1/health";
}

}}