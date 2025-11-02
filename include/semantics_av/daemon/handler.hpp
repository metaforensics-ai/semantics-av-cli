#pragma once

#include "../common/types.hpp"
#include "../core/engine.hpp"
#include "../network/client.hpp"
#include "../network/analysis_service.hpp"
#include "../network/downloader.hpp"
#include "protocol.hpp"
#include "reloadable_config.hpp"
#include <memory>
#include <string>
#include <vector>
#include <filesystem>
#include <map>
#include <mutex>
#include <atomic>

namespace semantics_av {
namespace daemon {

class Connection;

struct DirectoryScanSession {
    size_t total_files;
    size_t total_batches;
    int max_threads = 4;
    bool infected_only = false;
    bool verbose = false;
    
    std::atomic<size_t> scanned_files{0};
    ScanDirectoryResponse accumulated_results;
    std::mutex results_mutex;
    std::chrono::steady_clock::time_point start_time;
};

class RequestHandler {
public:
    explicit RequestHandler(core::SemanticsAVEngine* engine, const std::string& api_key);
    ~RequestHandler();
    
    void handleConnection(std::shared_ptr<Connection> conn);
    void updateNetworkConfig(const ReloadableConfig& config);
    
private:
    core::SemanticsAVEngine* engine_;
    std::string api_key_;
    std::unique_ptr<Protocol> protocol_;
    std::shared_ptr<network::AnalysisService> analysis_service_;
    std::shared_ptr<network::ModelDownloader> downloader_;
    mutable std::mutex analysis_service_mutex_;
    mutable std::mutex downloader_mutex_;
    std::map<Connection*, std::shared_ptr<DirectoryScanSession>> connection_sessions_;
    std::mutex sessions_mutex_;
    
    void handleScanRequest(Connection* conn, const ScanRequest& request);
    void handleScanFdRequest(Connection* conn, const ScanRequest& request, int fd);
    void handleScanDirectoryInit(Connection* conn, const ScanDirectoryInit& init);
    void handleScanBatchFds(Connection* conn, const ScanBatchFds& batch, const std::vector<int>& fds);
    void handleScanDirectoryComplete(Connection* conn);
    void handleAnalyzeRequest(Connection* conn, const AnalyzeRequest& request);
    void handleAnalyzeFdRequest(Connection* conn, const AnalyzeRequest& request, int fd);
    void handleStatusRequest(Connection* conn, const StatusRequest& request);
    void handlePingRequest(Connection* conn, const PingRequest& request);
    void handleShutdownRequest(Connection* conn, const ShutdownRequest& request);
    void handleUpdateModelsRequest(Connection* conn, const UpdateModelsRequest& request);
    void handleConfigGetRequest(Connection* conn, const ConfigGetRequest& request);
    void handleDeleteReportRequest(Connection* conn, const DeleteReportRequest& request);
    void handleListReportsRequest(Connection* conn, const ListReportsRequest& request);
    void handleShowReportRequest(Connection* conn, const ShowReportRequest& request);
    
    void sendScanResponse(Connection* conn, const common::ScanMetadata& result);
    void sendScanDirectoryResponse(Connection* conn, const ScanDirectoryResponse& response);
    void sendAnalyzeResponse(Connection* conn, const network::AnalysisResult& result, const std::string& report_id);
    void sendStatusResponse(Connection* conn);
    void sendErrorResponse(Connection* conn, const std::string& error);
    void sendAck(Connection* conn);
    void sendUpdateModelsResponse(Connection* conn, const UpdateModelsResponse& response);
    void sendDeleteReportResponse(Connection* conn, const DeleteReportResponse& response);
    
    void updateSummaryCounters(ScanDirectoryResponse& summary, const common::ScanMetadata& result);
};

}}