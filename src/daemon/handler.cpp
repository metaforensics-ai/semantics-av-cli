#include "semantics_av/daemon/handler.hpp"
#include "semantics_av/core/error_codes.hpp"
#include "semantics_av/common/error_framework.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/config.hpp"
#include "semantics_av/config/validator.hpp"
#include "semantics_av/update/updater.hpp"
#include "semantics_av/report/storage.hpp"
#include "semantics_av/format/json_formatter.hpp"
#include <semantics_av/semantics_av.hpp>
#include <thread>
#include <nlohmann/json.hpp>
#include <unistd.h>
#include <tbb/parallel_for.h>
#include <tbb/task_arena.h>
#include <tbb/concurrent_queue.h>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>

namespace semantics_av {
namespace daemon {

RequestHandler::RequestHandler(core::SemanticsAVEngine* engine, const std::string& api_key) 
    : engine_(engine), api_key_(api_key) {
    protocol_ = std::make_unique<Protocol>();
    
    auto& global_config = common::Config::instance().global();
    std::string effective_api_key = api_key_.empty() ? global_config.api_key : api_key_;
    
    downloader_ = std::make_shared<network::ModelDownloader>(global_config.network_timeout);
    
    if (!effective_api_key.empty()) {
        analysis_service_ = std::make_shared<network::AnalysisService>(
            engine_, effective_api_key, global_config.network_timeout);
    }
}

RequestHandler::~RequestHandler() = default;

void RequestHandler::updateNetworkConfig(const ReloadableConfig& config) {
    common::Logger::instance().info("[Handler] Network config update | has_api_key={}", 
                                    !config.api_key.empty());
    
    std::lock_guard<std::mutex> analysis_lock(analysis_service_mutex_);
    std::lock_guard<std::mutex> downloader_lock(downloader_mutex_);
    
    api_key_ = config.api_key;
    
    if (downloader_) {
        downloader_->updateConfig(config.network_timeout);
    }
    
    if (analysis_service_) {
        analysis_service_->updateConfig(config.api_key, config.network_timeout);
    } else if (!config.api_key.empty()) {
        analysis_service_ = std::make_shared<network::AnalysisService>(
            engine_, config.api_key, config.network_timeout);
        common::Logger::instance().info("[Handler] AnalysisService created");
    }
    
    common::Logger::instance().info("[Handler] Config updated | active={}", 
                                    analysis_service_ != nullptr);
}

void RequestHandler::handleConnection(std::shared_ptr<Connection> conn) {
    if (!conn || !conn->isConnected()) {
        return;
    }
    
    common::Logger::instance().debug("[Connection] Handling | source={}", conn->getRemoteAddress());
    
    try {
        while (conn->isConnected()) {
            MessageHeader header;
            std::vector<uint8_t> data;
            std::vector<int> received_fds;
            
            bool message_received = conn->readMessageWithFds(header, data, received_fds);
            
            if (!message_received) {
                break;
            }
            
            int received_fd = -1;
            if (received_fds.size() == 1) {
                received_fd = received_fds[0];
            }
            
            switch (header.type) {
                case MessageType::SCAN_REQUEST: {
                    ScanRequest request;
                    if (!protocol_->parseScanRequest(data, request)) {
                        common::ErrorContext ctx;
                        ctx.component = "Handler";
                        ctx.details["message_type"] = "SCAN_REQUEST";
                        ctx.details["data_size"] = std::to_string(data.size());
                        
                        common::Logger::instance().warn("[Request] Parse failed | type=scan | {}", 
                                                       common::formatContext(ctx));
                        sendErrorResponse(conn.get(), "Invalid scan request format");
                        break;
                    }
                    if (received_fd >= 0) {
                        handleScanFdRequest(conn.get(), request, received_fd);
                    } else {
                        sendErrorResponse(conn.get(), "File descriptor required for scan");
                    }
                    break;
                }
                
                case MessageType::SCAN_DIRECTORY_INIT: {
                    ScanDirectoryInit init;
                    if (!protocol_->parseScanDirectoryInit(data, init)) {
                        sendErrorResponse(conn.get(), "Invalid scan directory init format");
                        break;
                    }
                    handleScanDirectoryInit(conn.get(), init);
                    break;
                }
                
                case MessageType::SCAN_BATCH_FDS: {
                    ScanBatchFds batch;
                    if (!protocol_->parseScanBatchFds(data, batch)) {
                        sendErrorResponse(conn.get(), "Invalid scan batch fds format");
                        break;
                    }
                    if (received_fds.empty()) {
                        sendErrorResponse(conn.get(), "File descriptors required for batch scan");
                        break;
                    }
                    handleScanBatchFds(conn.get(), batch, received_fds);
                    break;
                }
                
                case MessageType::SCAN_DIRECTORY_COMPLETE: {
                    handleScanDirectoryComplete(conn.get());
                    break;
                }
                
                case MessageType::ANALYZE_REQUEST: {
                    AnalyzeRequest request;
                    if (!protocol_->parseAnalyzeRequest(data, request)) {
                        sendErrorResponse(conn.get(), "Invalid analyze request format");
                        break;
                    }
                    if (received_fd >= 0) {
                        handleAnalyzeFdRequest(conn.get(), request, received_fd);
                    } else {
                        sendErrorResponse(conn.get(), "File descriptor required for analysis");
                    }
                    break;
                }
                
                case MessageType::STATUS_REQUEST: {
                    StatusRequest request;
                    if (!protocol_->parseStatusRequest(data, request)) {
                        sendErrorResponse(conn.get(), "Invalid status request format");
                        break;
                    }
                    handleStatusRequest(conn.get(), request);
                    break;
                }
                
                case MessageType::PING_REQUEST: {
                    PingRequest request;
                    if (!protocol_->parsePingRequest(data, request)) {
                        sendErrorResponse(conn.get(), "Invalid ping request format");
                        break;
                    }
                    handlePingRequest(conn.get(), request);
                    break;
                }
                
                case MessageType::SHUTDOWN_REQUEST: {
                    ShutdownRequest request;
                    if (!protocol_->parseShutdownRequest(data, request)) {
                        sendErrorResponse(conn.get(), "Invalid shutdown request format");
                        break;
                    }
                    handleShutdownRequest(conn.get(), request);
                    break;
                }
                
                case MessageType::UPDATE_MODELS_REQUEST: {
                    UpdateModelsRequest request;
                    if (!protocol_->parseUpdateModelsRequest(data, request)) {
                        sendErrorResponse(conn.get(), "Invalid update models request format");
                        break;
                    }
                    handleUpdateModelsRequest(conn.get(), request);
                    break;
                }
                
                case MessageType::CONFIG_GET_REQUEST: {
                    ConfigGetRequest request;
                    if (!protocol_->parseConfigGetRequest(data, request)) {
                        sendErrorResponse(conn.get(), "Invalid config get request format");
                        break;
                    }
                    handleConfigGetRequest(conn.get(), request);
                    break;
                }
                
                case MessageType::DELETE_REPORT_REQUEST: {
                    DeleteReportRequest request;
                    if (!protocol_->parseDeleteReportRequest(data, request)) {
                        sendErrorResponse(conn.get(), "Invalid delete report request format");
                        break;
                    }
                    handleDeleteReportRequest(conn.get(), request);
                    break;
                }
                
                case MessageType::LIST_REPORTS_REQUEST: {
                    ListReportsRequest request;
                    if (!protocol_->parseListReportsRequest(data, request)) {
                        sendErrorResponse(conn.get(), "Invalid list reports request format");
                        break;
                    }
                    handleListReportsRequest(conn.get(), request);
                    break;
                }
                
                case MessageType::SHOW_REPORT_REQUEST: {
                    ShowReportRequest request;
                    if (!protocol_->parseShowReportRequest(data, request)) {
                        sendErrorResponse(conn.get(), "Invalid show report request format");
                        break;
                    }
                    handleShowReportRequest(conn.get(), request);
                    break;
                }
                
                default:
                    common::ErrorContext ctx;
                    ctx.component = "Handler";
                    ctx.details["message_type"] = std::to_string(static_cast<int>(header.type));
                    
                    common::Logger::instance().warn("[Request] Unknown type | {}", 
                                                   common::formatContext(ctx));
                    sendErrorResponse(conn.get(), "Unknown message type");
                    break;
            }
            
            if (received_fd >= 0) {
                ::close(received_fd);
            }
            
            for (int fd : received_fds) {
                ::close(fd);
            }
        }
        
    } catch (const std::exception& e) {
        common::ErrorContext ctx;
        ctx.component = "Handler";
        ctx.details["exception"] = e.what();
        ctx.details["source"] = conn->getRemoteAddress();
        
        common::Logger::instance().error("[Connection] Handler exception | {}", 
                                        common::formatContext(ctx));
        sendErrorResponse(conn.get(), e.what());
    }
    
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        connection_sessions_.erase(conn.get());
    }
    
    conn->close();
    common::Logger::instance().debug("[Connection] Closed | source={}", conn->getRemoteAddress());
}

void RequestHandler::handleListReportsRequest(Connection* conn, const ListReportsRequest& request) {
    common::Logger::instance().debug("[Report] List request | limit={}", request.limit);
    
    try {
        report::ReportStorage storage;
        report::ListOptions options;
        options.sort_by = request.sort_by;
        options.filter_verdict = request.filter_verdict;
        options.filter_date = request.filter_date;
        options.filter_file_type = request.filter_file_type;
        options.limit = request.limit;
        
        auto reports = storage.list(options);
        
        ListReportsResponse response;
        response.reports = reports;
        
        auto data = protocol_->serializeListReportsResponse(response);
        conn->writeMessage(MessageType::LIST_REPORTS_RESPONSE, 0, data);
        
        common::Logger::instance().info("[Report] List sent | count={}", reports.size());
        
    } catch (const std::exception& e) {
        common::Logger::instance().error("[Report] List failed | error={}", e.what());
        sendErrorResponse(conn, "Failed to list reports");
    }
}

void RequestHandler::handleShowReportRequest(Connection* conn, const ShowReportRequest& request) {
    common::Logger::instance().debug("[Report] Show request | id={}", request.report_id);
    
    try {
        report::ReportStorage storage;
        auto result = storage.load(request.report_id);
        
        ShowReportResponse response;
        
        if (result) {
            response.success = true;
            auto json = format::JsonFormatter::format(*result);
            response.report_json = json.dump();
            
            common::Logger::instance().info("[Report] Show sent | id={}", request.report_id);
        } else {
            response.success = false;
            response.error_message = "Report not found";
            
            common::Logger::instance().warn("[Report] Not found | id={}", request.report_id);
        }
        
        auto data = protocol_->serializeShowReportResponse(response);
        conn->writeMessage(MessageType::SHOW_REPORT_RESPONSE, 0, data);
        
    } catch (const std::exception& e) {
        common::Logger::instance().error("[Report] Show failed | id={} | error={}", 
                                        request.report_id, e.what());
        ShowReportResponse response;
        response.success = false;
        response.error_message = e.what();
        auto data = protocol_->serializeShowReportResponse(response);
        conn->writeMessage(MessageType::SHOW_REPORT_RESPONSE, 0, data);
    }
}

void RequestHandler::handleConfigGetRequest(Connection* conn, const ConfigGetRequest& request) {
    common::Logger::instance().debug("[Config] Get request | keys={}", request.keys.size());
    
    auto& config = common::Config::instance();
    ConfigGetResponse response;
    
    std::vector<std::string> keys = request.keys;
    if (keys.empty()) {
        keys = {"base_path", "models_path", "log_file", "log_level", "api_key", 
                "network_timeout", "auto_update",
                "scan.default_threads", "daemon.socket_path", "daemon.http_host",
                "daemon.http_port", "daemon.worker_threads"};
    }
    
    for (const auto& key : keys) {
        auto value = config.getValue(key);
        if (value) {
            response.values[key] = config::ConfigMasker::mask(key, *value);
        } else {
            response.values[key] = "";
        }
    }
    
    auto data = protocol_->serializeConfigGetResponse(response);
    conn->writeMessage(MessageType::CONFIG_GET_RESPONSE, 0, data);
    
    common::Logger::instance().debug("[Config] Response sent | keys={}", response.values.size());
}

void RequestHandler::handleScanDirectoryInit(Connection* conn, const ScanDirectoryInit& init) {
    common::Logger::instance().info("[DirScan] Init | files={} | batches={} | threads={} | infected_only={} | include_hashes={}", 
                                    init.total_files, init.total_batches, init.max_threads, init.infected_only, init.include_hashes);
    
    auto session = std::make_shared<DirectoryScanSession>();
    session->total_files = init.total_files;
    session->total_batches = init.total_batches;
    session->max_threads = init.max_threads;
    session->infected_only = init.infected_only;
    session->verbose = init.verbose;
    session->start_time = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        connection_sessions_[conn] = session;
    }
    
    sendAck(conn);
}

void RequestHandler::handleScanBatchFds(Connection* conn, const ScanBatchFds& batch, 
                                        const std::vector<int>& fds) {
    auto batch_start = std::chrono::steady_clock::now();
    
    std::shared_ptr<DirectoryScanSession> session;
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = connection_sessions_.find(conn);
        if (it == connection_sessions_.end()) {
            common::ErrorContext ctx;
            ctx.component = "DirScan";
            ctx.details["batch_index"] = std::to_string(batch.batch_index);
            
            common::Logger::instance().warn("[DirScan] No session | {}", common::formatContext(ctx));
            sendErrorResponse(conn, "No active scan session");
            return;
        }
        session = it->second;
    }
    
    if (fds.size() != batch.file_paths.size()) {
        common::ErrorContext ctx;
        ctx.component = "DirScan";
        ctx.details["batch_index"] = std::to_string(batch.batch_index);
        ctx.details["fd_count"] = std::to_string(fds.size());
        ctx.details["path_count"] = std::to_string(batch.file_paths.size());
        
        common::Logger::instance().error("[DirScan] FD mismatch | {}", common::formatContext(ctx));
        sendErrorResponse(conn, "FD count mismatch with file paths");
        return;
    }
    
    common::Logger::instance().debug("[DirScan] Processing batch | batch={} | files={} | progress={}/{}", 
                                     batch.batch_index, fds.size(), 
                                     session->scanned_files.load(), session->total_files);
    
    tbb::concurrent_queue<std::optional<ScanFileComplete>> results_queue;
    
    std::thread sender_thread([this, conn, &results_queue, session]() {
        while (true) {
            std::optional<ScanFileComplete> result;
            
            if (results_queue.try_pop(result)) {
                if (!result.has_value()) {
                    break;
                }
                
                auto data = protocol_->serializeScanFileComplete(*result);
                conn->writeMessage(MessageType::SCAN_FILE_COMPLETE, 0, data);
                
                {
                    std::lock_guard<std::mutex> lock(session->results_mutex);
                    common::ScanMetadata metadata;
                    metadata.file_path = result->file_path;
                    metadata.result = result->result;
                    metadata.confidence = result->confidence;
                    metadata.file_type = result->file_type;
                    metadata.file_size = result->file_size;
                    if (!result->error_message.empty()) {
                        metadata.error_message = result->error_message;
                    }
                    if (!result->file_hashes.empty()) {
                        metadata.file_hashes = result->file_hashes;
                    }
                    
                    if (!session->infected_only || 
                        result->result == common::ScanResult::MALICIOUS) {
                        session->accumulated_results.results.push_back(metadata);
                    }
                    updateSummaryCounters(session->accumulated_results, metadata);
                }
            } else {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
    });
    
    std::atomic<size_t> files_processed{0};
    size_t batch_start_index = session->scanned_files.load();
    
    tbb::task_arena arena(session->max_threads);
    arena.execute([&] {
        tbb::parallel_for(size_t(0), fds.size(), [&](size_t i) {
            ScanFileComplete result;
            result.file_path = batch.file_paths[i];
            
            try {
                auto scan_result = engine_->scanFromFd(fds[i], true);
                
                result.result = scan_result.result;
                result.confidence = scan_result.confidence;
                result.file_type = scan_result.file_type;
                result.file_size = scan_result.file_size;
                result.scan_time_ms = scan_result.scan_time.count();
                
                if (scan_result.error_message) {
                    result.error_message = *scan_result.error_message;
                }
                
                if (scan_result.error_code) {
                    common::ErrorContext ctx;
                    if (scan_result.error_context) {
                        ctx = *scan_result.error_context;
                    }
                    ctx.details["file"] = result.file_path;
                    ctx.details["error_code"] = core::CoreErrorCodeHelper::toString(*scan_result.error_code);
                    
                    if (session->verbose) {
                        common::Logger::instance().debug("[Scan] Error detail | {}", 
                                                        common::formatContext(ctx));
                    }
                }
                
                if (scan_result.file_hashes && !scan_result.file_hashes->empty()) {
                    result.file_hashes = *scan_result.file_hashes;
                }
                
            } catch (const std::exception& e) {
                result.result = common::ScanResult::ERROR;
                result.error_message = e.what();
                result.scan_time_ms = 0;
                
                common::ErrorContext ctx;
                ctx.component = "Scan";
                ctx.details["file"] = result.file_path;
                ctx.details["exception"] = e.what();
                
                common::Logger::instance().error("[Scan] Exception | {}", common::formatContext(ctx));
            }
            
            size_t current = batch_start_index + files_processed.fetch_add(1) + 1;
            result.current_file = current;
            result.total_files = session->total_files;
            
            results_queue.push(result);
            
            session->scanned_files.fetch_add(1);
        });
    });
    
    results_queue.push(std::nullopt);
    
    if (sender_thread.joinable()) {
        sender_thread.join();
    }
    
    auto batch_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - batch_start
    );
    
    common::Logger::instance().debug("[DirScan] Batch complete | batch={} | files={} | duration_ms={}", 
                                     batch.batch_index, fds.size(), batch_duration.count());
}

void RequestHandler::handleScanDirectoryComplete(Connection* conn) {
    std::shared_ptr<DirectoryScanSession> session;
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = connection_sessions_.find(conn);
        if (it == connection_sessions_.end()) {
            sendErrorResponse(conn, "No active scan session");
            return;
        }
        session = it->second;
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - session->start_time);
    
    session->accumulated_results.total_files = session->scanned_files.load();
    session->accumulated_results.total_time_ms = duration.count();
    
    common::Logger::instance().info("[DirScan] Complete | files={} | clean={} | malicious={} | errors={} | duration_ms={}", 
                                    session->accumulated_results.total_files,
                                    session->accumulated_results.clean_files,
                                    session->accumulated_results.malicious_files,
                                    session->accumulated_results.error_files,
                                    session->accumulated_results.total_time_ms);
    
    sendScanDirectoryResponse(conn, session->accumulated_results);
    
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        connection_sessions_.erase(conn);
    }
}

void RequestHandler::handleScanFdRequest(Connection* conn, const ScanRequest& request, int fd) {
    auto start_time = std::chrono::steady_clock::now();
    
    auto result = engine_->scanFromFd(fd, request.include_hashes);
    result.file_path = request.file_path;
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time
    );
    result.scan_time = duration;
    
    if (result.error_code) {
        common::ErrorContext ctx;
        if (result.error_context) {
            ctx = *result.error_context;
        }
        ctx.details["file"] = request.file_path;
        
        common::Logger::instance().info("[Scan] Complete with error | code={} | {}", 
                                       core::CoreErrorCodeHelper::toString(*result.error_code),
                                       common::formatContext(ctx));
    } else {
        common::Logger::instance().info("[Scan] Complete | file={} | result={} | confidence={:.1f} | size={} | duration_ms={}", 
                                        request.file_path, common::to_string(result.result), 
                                        result.confidence * 100, result.file_size, duration.count());
    }
    
    sendScanResponse(conn, result);
}

void RequestHandler::handleDeleteReportRequest(Connection* conn, const DeleteReportRequest& request) {
    common::Logger::instance().debug("[Report] Delete request | id={}", request.report_id);
    
    DeleteReportResponse response;
    
    try {
        report::ReportStorage storage;
        bool success = storage.deleteReport(request.report_id);
        
        response.success = success;
        if (!success) {
            response.error_message = "Failed to delete report";
        }
        
        if (success) {
            common::Logger::instance().info("[Report] Deleted | id={}", request.report_id);
        } else {
            common::Logger::instance().warn("[Report] Delete failed | id={}", request.report_id);
        }
        
    } catch (const std::exception& e) {
        response.success = false;
        response.error_message = e.what();
        common::Logger::instance().error("[Report] Delete exception | id={} | error={}", 
                                        request.report_id, e.what());
    }
    
    sendDeleteReportResponse(conn, response);
}

void RequestHandler::handleAnalyzeFdRequest(Connection* conn, const AnalyzeRequest& request, int fd) {
    auto start_time = std::chrono::steady_clock::now();
    
    std::shared_ptr<network::AnalysisService> service;
    {
        std::lock_guard<std::mutex> lock(analysis_service_mutex_);
        service = analysis_service_;
    }
    
    if (!service) {
        common::ErrorContext ctx;
        ctx.component = "Analysis";
        ctx.details["file"] = request.file_path;
        ctx.details["reason"] = "no_api_key";
        
        common::Logger::instance().error("[Analysis] Failed | {}", common::formatContext(ctx));
        sendErrorResponse(conn, "API key required for cloud analysis");
        return;
    }
    
    struct stat file_stat;
    size_t file_size = 0;
    if (fstat(fd, &file_stat) == 0) {
        file_size = file_stat.st_size;
    }
    
    auto analysis_payload = engine_->extractAnalysisPayloadFromFd(fd, request.language);
    
    if (!analysis_payload.isValid()) {
        std::string error_msg = "Analysis payload extraction failed";
        core::CoreErrorCode error_code = core::CoreErrorCode::ANALYSIS_EXTRACTION_FAILED;
        
        if (analysis_payload.sdk_result) {
            error_code = core::mapSdkResult(*analysis_payload.sdk_result);
            error_msg += " (SDK result: " + std::to_string(static_cast<int>(*analysis_payload.sdk_result)) + ")";
        }
        
        common::ErrorContext ctx;
        ctx.component = "Analysis";
        ctx.details["file"] = request.file_path;
        ctx.details["error_code"] = core::CoreErrorCodeHelper::toString(error_code);
        if (analysis_payload.sdk_result) {
            ctx.details["sdk_result"] = std::to_string(static_cast<int>(*analysis_payload.sdk_result));
        }
        
        common::Logger::instance().error("[Analysis] SDK extraction failed | {}", 
                                        common::formatContext(ctx));
        sendErrorResponse(conn, error_msg);
        return;
    }
    
    if (analysis_payload.analysis_blob.empty()) {
        common::ErrorContext ctx;
        ctx.component = "Analysis";
        ctx.details["file"] = request.file_path;
        ctx.details["error_code"] = core::CoreErrorCodeHelper::toString(core::CoreErrorCode::ANALYSIS_PAYLOAD_EMPTY);
        ctx.details["reason"] = "blob_empty_despite_ok_result";
        
        common::Logger::instance().error("[Analysis] Defensive check failed | {}", 
                                        common::formatContext(ctx));
        sendErrorResponse(conn, "Analysis payload is empty");
        return;
    }
    
    auto result = service->analyze(analysis_payload);
    
    if (result.verdict == "error") {
        common::ErrorContext ctx;
        ctx.component = "Analysis";
        ctx.details["file"] = request.file_path;
        ctx.details["verdict"] = "error";
        
        common::Logger::instance().error("[Analysis] Cloud analysis failed | {}", 
                                        common::formatContext(ctx));
        sendErrorResponse(conn, "Cloud analysis failed");
        return;
    }
    
    std::string report_id;
    auto& config = common::Config::instance().global();
    if (config.report.enable_storage) {
        try {
            report::ReportStorage storage;
            report_id = storage.save(result, request.file_path, request.language, file_size);
            
            if (!report_id.empty()) {
                common::Logger::instance().debug(
                    "[Analysis] Report saved | id={} | verdict={}", 
                    report_id, result.verdict
                );
            }
        } catch (const std::exception& e) {
            common::Logger::instance().warn(
                "[Analysis] Report save failed | error={}", 
                e.what()
            );
        }
    }
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time
    );
    
    common::Logger::instance().info("[Analysis] Complete | file={} | verdict={} | confidence={:.1f} | payload_size={} | duration_ms={}", 
                                    request.file_path, result.verdict, 
                                    result.confidence * 100, analysis_payload.analysis_blob.size(), duration.count());
    
    sendAnalyzeResponse(conn, result, report_id);
}

void RequestHandler::handleStatusRequest(Connection* conn, const StatusRequest& request) {
    common::Logger::instance().debug("[Status] Request");
    sendStatusResponse(conn);
}

void RequestHandler::handlePingRequest(Connection* conn, const PingRequest& request) {
    common::Logger::instance().debug("[Ping] Request");
    
    PingResponse response;
    response.payload = request.payload;
    
    auto data = protocol_->serializePingResponse(response);
    conn->writeMessage(MessageType::PING_RESPONSE, 0, data);
}

void RequestHandler::handleShutdownRequest(Connection* conn, const ShutdownRequest& request) {
    common::Logger::instance().info("[Shutdown] Requested | force={}", request.force);
    
    auto data = protocol_->serializeErrorResponse("Shutdown acknowledged");
    conn->writeMessage(MessageType::ERROR_RESPONSE, 0, data);
    
    std::thread([request]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::exit(0);
    }).detach();
}

void RequestHandler::handleUpdateModelsRequest(Connection* conn, const UpdateModelsRequest& request) {
    common::Logger::instance().info("[Update] Starting | types={} | force={}", 
                                    request.model_types.size(), request.force_update);
    
    std::shared_ptr<network::ModelDownloader> local_downloader;
    {
        std::lock_guard<std::mutex> lock(downloader_mutex_);
        local_downloader = downloader_;
    }
    
    update::ModelUpdater updater(engine_, local_downloader.get());
    
    update::UpdateOptions options;
    options.model_types = request.model_types;
    options.force_update = request.force_update;
    options.check_only = request.check_only;
    options.quiet = false;
    
    auto summary = updater.updateModelsSync(options);
    
    UpdateModelsResponse response;
    response.total_models = summary.total_models;
    response.updated_models = summary.updated_models;
    response.failed_models = summary.failed_models;
    response.updated_types = summary.updated_types;
    response.failed_types = summary.failed_types;
    response.total_time_ms = summary.total_time.count();
    
    for (const auto& ver_info : summary.version_info) {
        ModelVersionUpdate ver_update;
        ver_update.model_type = ver_info.model_type;
        ver_update.old_timestamp = ver_info.current_timestamp;
        ver_update.new_timestamp = ver_info.server_timestamp;
        ver_update.was_updated = ver_info.update_available && 
                                 (std::find(summary.updated_types.begin(), 
                                           summary.updated_types.end(), 
                                           ver_info.model_type) != summary.updated_types.end());
        ver_update.had_previous_version = ver_info.has_local_version;
        response.version_updates.push_back(ver_update);
    }
    
    common::Logger::instance().info("[Update] Complete | updated={} | failed={} | duration_ms={}",
                                    response.updated_models, response.failed_models, 
                                    response.total_time_ms);
    
    sendUpdateModelsResponse(conn, response);
}

void RequestHandler::sendScanResponse(Connection* conn, const common::ScanMetadata& result) {
    ScanResponse response;
    response.result = result.result;
    response.confidence = result.confidence;
    response.file_type = result.file_type;
    response.file_path = result.file_path;
    response.file_size = result.file_size;
    response.scan_time_ms = result.scan_time.count();
    
    auto now = std::chrono::system_clock::now();
    auto time_t_val = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::gmtime(&time_t_val);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    response.scan_timestamp = oss.str();
    
    response.sdk_version = semantics_av::SemanticsAV::getVersion();
    
    if (!result.file_type.empty() && result.file_type != "unknown") {
        auto model_info = engine_->getModelInfo(result.file_type);
        auto model_time = std::chrono::system_clock::to_time_t(model_info.server_created_at);
        std::tm model_tm = *std::gmtime(&model_time);
        std::ostringstream model_oss;
        model_oss << std::put_time(&model_tm, "%Y-%m-%dT%H:%M:%SZ");
        response.model_version = model_oss.str();
    }
    
    if (result.error_message) {
        response.error_message = *result.error_message;
    }
    
    if (result.file_hashes && !result.file_hashes->empty()) {
        response.file_hashes = *result.file_hashes;
    }
    
    auto data = protocol_->serializeScanResponse(response);
    conn->writeMessage(MessageType::SCAN_RESPONSE, 0, data);
}

void RequestHandler::sendScanDirectoryResponse(Connection* conn, const ScanDirectoryResponse& response) {
    auto data = protocol_->serializeScanDirectoryResponse(response);
    conn->writeMessage(MessageType::SCAN_DIRECTORY_RESPONSE, 0, data);
}

void RequestHandler::sendAnalyzeResponse(Connection* conn, const network::AnalysisResult& result, const std::string& report_id) {
    AnalyzeResponse response;
    response.verdict = result.verdict;
    response.confidence = result.confidence;
    response.tags = result.tags;
    response.natural_language_report = result.natural_language_report;
    response.analysis_timestamp = result.analysis_timestamp;
    response.file_type = result.file_type;
    response.sdk_version = semantics_av::SemanticsAV::getVersion();
    response.saved_report_id = report_id;
    
    if (result.signature) {
        response.signature = *result.signature;
    }
    
    if (result.static_attributes_json) {
        response.static_attributes_json = *result.static_attributes_json;
    }
    
    if (!result.file_hashes.empty()) {
        nlohmann::json hashes_json;
        for (const auto& [key, value] : result.file_hashes) {
            hashes_json[key] = value;
        }
        response.file_hashes_json = hashes_json.dump();
    }
    
    nlohmann::json intelligence_json;
    
    nlohmann::json samples_array = nlohmann::json::array();
    for (const auto& sample : result.intelligence.similar_samples) {
        nlohmann::json sample_json;
        sample_json["file_hashes"] = sample.file_hashes;
        sample_json["similarity_score"] = sample.similarity_score;
        sample_json["tags"] = sample.tags;
        
        if (sample.signature) {
            sample_json["signature"] = *sample.signature;
        } else {
            sample_json["signature"] = nullptr;
        }
        
        if (sample.static_attributes_json) {
            sample_json["static_attributes"] = nlohmann::json::parse(*sample.static_attributes_json);
        } else {
            sample_json["static_attributes"] = nullptr;
        }
        
        samples_array.push_back(sample_json);
    }
    intelligence_json["similar_samples"] = samples_array;
    
    auto serialize_label_stats = [](const network::LabelStatistics& stats) -> nlohmann::json {
        nlohmann::json json;
        json["count"] = stats.count;
        if (stats.max_similarity) {
            json["max_similarity"] = *stats.max_similarity;
        } else {
            json["max_similarity"] = nullptr;
        }
        if (stats.avg_similarity) {
            json["avg_similarity"] = *stats.avg_similarity;
        } else {
            json["avg_similarity"] = nullptr;
        }
        return json;
    };
    
    nlohmann::json stats_json;
    stats_json["processed_samples"] = result.intelligence.statistics.processed_samples;
    
    nlohmann::json by_label_json;
    by_label_json["malicious"] = serialize_label_stats(result.intelligence.statistics.malicious);
    by_label_json["suspicious"] = serialize_label_stats(result.intelligence.statistics.suspicious);
    by_label_json["clean"] = serialize_label_stats(result.intelligence.statistics.clean);
    by_label_json["unknown"] = serialize_label_stats(result.intelligence.statistics.unknown);
    
    stats_json["by_label"] = by_label_json;
    
    nlohmann::json by_sig_json;
    for (const auto& [sig_name, sig_stat] : result.intelligence.statistics.by_signature) {
        nlohmann::json sig_json;
        sig_json["count"] = sig_stat.count;
        sig_json["max_similarity"] = sig_stat.max_similarity;
        sig_json["avg_similarity"] = sig_stat.avg_similarity;
        by_sig_json[sig_name] = sig_json;
    }
    stats_json["by_signature"] = by_sig_json;
    
    intelligence_json["statistics"] = stats_json;
    response.intelligence_json = intelligence_json.dump();
    
    auto data = protocol_->serializeAnalyzeResponse(response);
    conn->writeMessage(MessageType::ANALYZE_RESPONSE, 0, data);
}

void RequestHandler::sendUpdateModelsResponse(Connection* conn, const UpdateModelsResponse& response) {
    auto data = protocol_->serializeUpdateModelsResponse(response);
    conn->writeMessage(MessageType::UPDATE_MODELS_RESPONSE, 0, data);
}

void RequestHandler::sendDeleteReportResponse(Connection* conn, const DeleteReportResponse& response) {
    auto data = protocol_->serializeDeleteReportResponse(response);
    conn->writeMessage(MessageType::DELETE_REPORT_RESPONSE, 0, data);
}

void RequestHandler::sendStatusResponse(Connection* conn) {
    StatusResponse response;
    response.healthy = true;
    response.sdk_version = semantics_av::SemanticsAV::getVersion();
    
    static auto start_time = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
    response.uptime_seconds = uptime.count();
    
    auto data = protocol_->serializeStatusResponse(response);
    conn->writeMessage(MessageType::STATUS_RESPONSE, 0, data);
}

void RequestHandler::sendErrorResponse(Connection* conn, const std::string& error) {
    auto data = protocol_->serializeErrorResponse(error);
    conn->writeMessage(MessageType::ERROR_RESPONSE, 0, data);
}

void RequestHandler::sendAck(Connection* conn) {
    nlohmann::json json;
    json["ack"] = true;
    std::string json_str = json.dump();
    std::vector<uint8_t> data(json_str.begin(), json_str.end());
    conn->writeMessage(MessageType::STATUS_RESPONSE, 0, data);
}

void RequestHandler::updateSummaryCounters(ScanDirectoryResponse& summary, const common::ScanMetadata& result) {
    switch (result.result) {
        case common::ScanResult::CLEAN:
            summary.clean_files++;
            break;
        case common::ScanResult::MALICIOUS:
            summary.malicious_files++;
            break;
        case common::ScanResult::UNSUPPORTED:
            summary.unsupported_files++;
            break;
        case common::ScanResult::ERROR:
            summary.error_files++;
            break;
    }
}

}}