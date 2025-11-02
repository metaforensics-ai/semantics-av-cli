#include "semantics_av/network/downloader.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/constants.hpp"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <future>
#include <algorithm>
#include <cctype>
#include <atomic>
#include <mutex>

namespace semantics_av {
namespace network {

class ModelDownloader::Impl {
public:
    Impl(int timeout_seconds)
        : timeout_(timeout_seconds) {
        
        std::string cdn_url = constants::network::DEFAULT_CDN_URL;
        
        size_t scheme_pos = cdn_url.find("://");
        if (scheme_pos != std::string::npos) {
            std::string scheme = cdn_url.substr(0, scheme_pos);
            std::string host_and_port = cdn_url.substr(scheme_pos + 3);
            
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
            host_ = cdn_url;
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
        
        common::Logger::instance().debug("[CDN] Client initialized | host={} | port={} | https={}", 
                                         host_, port_, is_https_);
    }
    
    ~Impl() {
        try {
            if (https_client_) {
                https_client_->stop();
                https_client_.release();
            }
            
            if (http_client_) {
                http_client_->stop();
                http_client_.release();
            }
        } catch (...) {
        }
    }
    
    void updateConfig(int timeout_seconds) {
        std::lock_guard<std::mutex> lock(mutex_);
        
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
        
        common::Logger::instance().info("[CDN] Config updated | timeout={}", timeout_seconds);
    }
    
    void setProgressCallback(DownloadProgressCallback callback) {
        progress_callback_ = std::move(callback);
    }
    
    std::future<std::vector<ModelDownloadResult>> downloadModelsAsync(
            const std::vector<std::string>& model_types,
            const std::map<std::string, std::string>& current_etags) {
        
        return std::async(std::launch::async, [this, model_types, current_etags]() {
            common::Logger::instance().info("[Download] Starting | models={}", model_types.size());
            
            std::vector<std::future<ModelDownloadResult>> futures;
            
            for (const auto& type : model_types) {
                auto etag_it = current_etags.find(type);
                std::string current_etag = (etag_it != current_etags.end()) ? etag_it->second : "";
                
                futures.push_back(downloadSingleModelAsyncImpl(type, current_etag));
            }
            
            std::vector<ModelDownloadResult> results;
            for (auto& future : futures) {
                results.push_back(future.get());
            }
            
            size_t success_count = std::count_if(results.begin(), results.end(),
                                                 [](const auto& r) { return r.success; });
            common::Logger::instance().info("[Download] Complete | success={} | total={}", 
                                           success_count, results.size());
            
            return results;
        });
    }
    
    std::future<ModelDownloadResult> downloadSingleModelAsyncImpl(
            const std::string& model_type, const std::string& current_etag) {
        
        return std::async(std::launch::async, [this, model_type, current_etag]() {
            ModelDownloadResult result;
            result.file_type = model_type;
            
            try {
                std::lock_guard<std::mutex> lock(mutex_);
                
                std::string uri_path = "/model-distribution/" + model_type + "/latest";
                
                httplib::Headers headers = {
                    {"User-Agent", "SemanticsAV-CLI/1.0"}
                };
                
                if (!current_etag.empty()) {
                    headers.emplace("If-None-Match", "\"" + current_etag + "\"");
                    common::Logger::instance().debug("[Download] Request | type={} | etag={}", 
                                                     model_type, current_etag);
                }
                
                std::atomic<size_t> downloaded_bytes{0};
                std::atomic<size_t> total_bytes{0};
                std::chrono::steady_clock::time_point last_callback_time;
                bool first_callback = true;
                
                auto progress_lambda = [&](size_t current, size_t total) -> bool {
                    downloaded_bytes.store(current);
                    total_bytes.store(total);
                    
                    auto now = std::chrono::steady_clock::now();
                    
                    if (first_callback) {
                        last_callback_time = now;
                        first_callback = false;
                    }
                    
                    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - last_callback_time);
                    
                    if (elapsed.count() >= 100 || current == total) {
                        if (progress_callback_) {
                            progress_callback_(model_type, current, total);
                        }
                        last_callback_time = now;
                    }
                    
                    return true;
                };
                
                httplib::Result response;
                if (is_https_) {
                    response = https_client_->Get(uri_path, headers, progress_lambda);
                } else {
                    response = http_client_->Get(uri_path, headers, progress_lambda);
                }
                
                return processDownloadResponse(response, model_type, current_etag);
                
            } catch (const std::exception& e) {
                common::Logger::instance().error("[Download] Request failed | type={} | error={}", 
                                                  model_type, e.what());
                result.success = false;
                result.error_message = e.what();
                return result;
            }
        });
    }

private:
    std::mutex mutex_;
    DownloadProgressCallback progress_callback_;
    int timeout_;
    std::string host_;
    int port_;
    bool is_https_;
    std::unique_ptr<httplib::Client> http_client_;
    std::unique_ptr<httplib::SSLClient> https_client_;
    
    ModelDownloadResult processDownloadResponse(const httplib::Result& response,
                                                  const std::string& model_type,
                                                  const std::string& current_etag) {
        ModelDownloadResult result;
        result.file_type = model_type;
        
        try {
            if (!response) {
                result.success = false;
                result.error_message = "Network error";
                common::Logger::instance().error("[Download] Network error | type={}", model_type);
                return result;
            }
            
            if (response->status == 304) {
                result.success = true;
                result.updated = false;
                common::Logger::instance().debug("[Download] Not modified | type={}", model_type);
                return result;
            }
            
            if (response->status != 200) {
                result.success = false;
                result.error_message = "HTTP " + std::to_string(response->status);
                common::Logger::instance().error("[Download] HTTP error | type={} | status={}", 
                                                  model_type, response->status);
                return result;
            }
            
            std::string etag;
            if (response->has_header("ETag")) {
                etag = response->get_header_value("ETag");
                if (etag.front() == '"' && etag.back() == '"') {
                    etag = etag.substr(1, etag.length() - 2);
                }
            }
            
            std::string signature_b64;
            if (response->has_header("X-Signature")) {
                signature_b64 = response->get_header_value("X-Signature");
            }
            
            if (signature_b64.empty()) {
                result.success = false;
                result.error_message = "Missing signature for model";
                common::Logger::instance().error("[Download] No signature | type={}", model_type);
                return result;
            }
            
            int64_t server_created_at = 0;
            if (response->has_header("X-Model-Timestamp")) {
                try {
                    server_created_at = std::stoll(response->get_header_value("X-Model-Timestamp"));
                } catch (...) {
                    server_created_at = 0;
                }
            }
            
            const std::string& body_data = response->body;
            
            if (body_data.empty()) {
                result.success = false;
                result.error_message = "Empty response body";
                common::Logger::instance().error("[Download] Empty body | type={}", model_type);
                return result;
            }
            
            std::vector<uint8_t> signature;
            try {
                signature = decodeBase64(signature_b64);
            } catch (const std::exception& e) {
                result.success = false;
                result.error_message = "Invalid signature format";
                common::Logger::instance().error("[Download] Signature decode failed | type={} | error={}", 
                                                 model_type, e.what());
                return result;
            }
            
            if (signature.empty()) {
                result.success = false;
                result.error_message = "Empty signature after decoding";
                common::Logger::instance().error("[Download] Empty signature | type={}", model_type);
                return result;
            }
            
            core::ModelData model_data;
            model_data.data = std::vector<uint8_t>(body_data.begin(), body_data.end());
            model_data.signature = signature;
            model_data.etag = etag;
            model_data.server_created_at = server_created_at;
            
            result.success = true;
            result.updated = true;
            result.data = std::move(model_data);
            
            common::Logger::instance().info("[Download] Success | type={} | size={} | etag={} | timestamp={}", 
                                           model_type, body_data.size(), etag, server_created_at);
            
        } catch (const std::exception& e) {
            result.success = false;
            result.error_message = e.what();
            common::Logger::instance().error("[Download] Processing failed | type={} | error={}", 
                                            model_type, e.what());
        }
        
        return result;
    }
    
    std::vector<uint8_t> decodeBase64(const std::string& encoded) {
        const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string clean_encoded = encoded;
        clean_encoded.erase(std::remove_if(clean_encoded.begin(), clean_encoded.end(), 
                                          [](char c) { return std::isspace(c); }), 
                           clean_encoded.end());
        
        if (clean_encoded.empty()) {
            throw std::runtime_error("Empty base64 string");
        }
        
        while (clean_encoded.length() % 4 != 0) {
            clean_encoded += '=';
        }
        
        std::vector<uint8_t> decoded;
        decoded.reserve(clean_encoded.length() * 3 / 4);
        
        for (size_t i = 0; i < clean_encoded.length(); i += 4) {
            uint32_t tmp = 0;
            int padding = 0;
            
            for (int j = 0; j < 4; ++j) {
                tmp <<= 6;
                char c = clean_encoded[i + j];
                if (c == '=') {
                    padding++;
                } else {
                    size_t pos = chars.find(c);
                    if (pos == std::string::npos) {
                        throw std::runtime_error("Invalid base64 character");
                    }
                    tmp |= pos;
                }
            }
            
            decoded.push_back((tmp >> 16) & 0xFF);
            if (padding < 2) decoded.push_back((tmp >> 8) & 0xFF);
            if (padding < 1) decoded.push_back(tmp & 0xFF);
        }
        
        return decoded;
    }
};

ModelDownloader::ModelDownloader(int timeout_seconds)
    : timeout_seconds_(timeout_seconds) {
    pimpl_ = std::make_unique<Impl>(timeout_seconds);
}

ModelDownloader::~ModelDownloader() = default;

std::future<std::vector<ModelDownloadResult>> ModelDownloader::downloadModelsAsync(
        const std::vector<std::string>& model_types,
        const std::map<std::string, std::string>& current_etags) {
    return pimpl_->downloadModelsAsync(model_types, current_etags);
}

std::future<ModelDownloadResult> ModelDownloader::downloadSingleModelAsync(
        const std::string& model_type,
        const std::string& current_etag) {
    return pimpl_->downloadSingleModelAsyncImpl(model_type, current_etag);
}

void ModelDownloader::updateConfig(int timeout_seconds) {
    timeout_seconds_ = timeout_seconds;
    pimpl_->updateConfig(timeout_seconds);
}

void ModelDownloader::setProgressCallback(DownloadProgressCallback callback) {
    pimpl_->setProgressCallback(std::move(callback));
}

std::string ModelDownloader::buildModelUrl(const std::string& model_type) const {
    return std::string(constants::network::DEFAULT_CDN_URL) + "/model-distribution/" + model_type + "/latest";
}

bool ModelDownloader::validateModelSignature(const std::vector<uint8_t>& data, 
                                             const std::vector<uint8_t>& signature) {
    return !data.empty() && !signature.empty();
}

}}