#pragma once

#include "../common/config.hpp"
#include "../core/engine.hpp"
#include "../network/analysis_service.hpp"
#include "../network/downloader.hpp"
#include "handler.hpp"
#include "reloadable_config.hpp"
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <memory>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>

namespace semantics_av {
namespace daemon {

class HttpApiServer {
public:
    HttpApiServer(const std::string& host, uint16_t port, 
                  core::SemanticsAVEngine* engine, const std::string& api_key);
    ~HttpApiServer();
    
    bool start();
    void stop();
    bool isRunning() const { return running_; }
    void updateNetworkConfig(const ReloadableConfig& config);

private:
    std::string host_;
    uint16_t port_;
    core::SemanticsAVEngine* engine_;
    std::string api_key_;
    std::unique_ptr<httplib::Server> server_;
    std::shared_ptr<network::AnalysisService> analysis_service_;
    std::shared_ptr<network::ModelDownloader> downloader_;
    mutable std::mutex analysis_service_mutex_;
    mutable std::mutex downloader_mutex_;
    std::thread server_thread_;
    std::atomic<bool> running_{false};
    
    void setupRoutes();
    void handleScanFile(const httplib::Request& req, httplib::Response& res);
    void handleAnalyzeFile(const httplib::Request& req, httplib::Response& res);
    void handleUpdateModels(const httplib::Request& req, httplib::Response& res);
    void handleStatus(const httplib::Request& req, httplib::Response& res);
    void handleHealth(const httplib::Request& req, httplib::Response& res);
    void handleListReports(const httplib::Request& req, httplib::Response& res);
    void handleShowReport(const httplib::Request& req, httplib::Response& res);
    
    std::string saveTempFile(const httplib::FormData& file);
    bool validateFileSize(size_t size);
    bool validateLanguage(const std::string& language);
    bool validateFormat(const std::string& format);
    
    void sendJsonResponse(httplib::Response& res, const nlohmann::json& data, int status = 200);
    void sendCsvResponse(httplib::Response& res, const std::string& csv_data);
    void sendJsonError(httplib::Response& res, int status, const std::string& message);
    
    nlohmann::json scanResultToJson(const common::ScanMetadata& result);
    std::string scanResultToCsv(const common::ScanMetadata& result);
    nlohmann::json analysisResultToJson(const network::AnalysisResult& result);
};

}}