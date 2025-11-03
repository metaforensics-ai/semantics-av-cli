#include "semantics_av/daemon/http_server.hpp"
#include "semantics_av/http/response.hpp"
#include "semantics_av/core/error_codes.hpp"
#include "semantics_av/common/error_framework.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/constants.hpp"
#include "semantics_av/network/downloader.hpp"
#include "semantics_av/update/updater.hpp"
#include "semantics_av/format/json_formatter.hpp"
#include "semantics_av/report/storage.hpp"
#include <semantics_av/semantics_av.hpp>
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>
#include <system_error>
#include <cerrno>

namespace semantics_av {
namespace daemon {

HttpApiServer::HttpApiServer(const std::string& host, uint16_t port,
                             core::SemanticsAVEngine* engine, const std::string& api_key)
    : host_(host), port_(port), engine_(engine), api_key_(api_key) {
    server_ = std::make_unique<httplib::Server>();
    
    auto& global_config = common::Config::instance().global();
    std::string effective_api_key = api_key_.empty() ? global_config.api_key : api_key_;
    
    downloader_ = std::make_shared<network::ModelDownloader>(global_config.network_timeout);
    
    if (!effective_api_key.empty()) {
        analysis_service_ = std::make_shared<network::AnalysisService>(
            engine_, effective_api_key, global_config.network_timeout);
    }
}

HttpApiServer::~HttpApiServer() {
    stop();
}

bool HttpApiServer::start() {
    if (running_) {
        return true;
    }
    
    setupRoutes();
    
    server_->set_read_timeout(10, 0);
    server_->set_write_timeout(10, 0);
    server_->set_idle_interval(1, 0);
    server_->set_keep_alive_max_count(100);
    
    running_ = true;
    
    server_thread_ = std::thread([this]() {
        common::Logger::instance().info("[HTTP] Server starting | host={} | port={}", 
                                       host_, port_);
        
        if (!server_->listen(host_, port_)) {
            common::Logger::instance().error("[HTTP] Failed to bind | host={} | port={}", 
                                            host_, port_);
            running_ = false;
        }
    });
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    if (running_) {
        common::Logger::instance().info("[HTTP] Server started | host={} | port={}", 
                                       host_, port_);
    }
    
    return running_;
}

void HttpApiServer::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    if (server_) {
        server_->stop();
        server_.release();
    }
    
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    
    common::Logger::instance().info("[HTTP] Server stopped");
}

void HttpApiServer::updateNetworkConfig(const ReloadableConfig& config) {
    common::Logger::instance().info("[HTTP] Network config update | has_api_key={}", 
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
        common::Logger::instance().info("[HTTP] AnalysisService created");
    }
    
    common::Logger::instance().info("[HTTP] Config updated | active={}", 
                                    analysis_service_ != nullptr);
}

void HttpApiServer::setupRoutes() {
    server_->Post("/api/v1/scan", [this](const auto& req, auto& res) {
        handleScanFile(req, res);
    });
    
    server_->Post("/api/v1/analyze", [this](const auto& req, auto& res) {
        handleAnalyzeFile(req, res);
    });
    
    server_->Post("/api/v1/models/update", [this](const auto& req, auto& res) {
        handleUpdateModels(req, res);
    });
    
    server_->Get("/api/v1/status", [this](const auto& req, auto& res) {
        handleStatus(req, res);
    });
    
    server_->Get("/api/v1/health", [this](const auto& req, auto& res) {
        handleHealth(req, res);
    });
    
    server_->Get("/api/v1/reports", [this](const auto& req, auto& res) {
        handleListReports(req, res);
    });
    
    server_->Get(R"(/api/v1/reports/([a-zA-Z0-9_]+))", [this](const auto& req, auto& res) {
        handleShowReport(req, res);
    });
    
    server_->set_error_handler([](const auto& req, auto& res) {
        if (!res.body.empty()) {
            return;
        }
        
        if (res.status == 404) {
            http::HttpResponse::sendError(res, http::ErrorCode::REQUEST_INVALID_ENDPOINT);
        } else if (res.status == 405) {
            http::HttpResponse::sendError(res, http::ErrorCode::REQUEST_METHOD_NOT_ALLOWED);
        }
    });
}

void HttpApiServer::handleListReports(const httplib::Request& req, httplib::Response& res) {
    try {
        common::Logger::instance().debug("[HTTP] List reports request");
        
        report::ReportStorage storage;
        report::ListOptions options;
        
        if (req.has_param("filter_verdict")) {
            options.filter_verdict = req.get_param_value("filter_verdict");
        }
        
        if (req.has_param("filter_date")) {
            options.filter_date = req.get_param_value("filter_date");
        }
        
        if (req.has_param("filter_file_type")) {
            options.filter_file_type = req.get_param_value("filter_file_type");
        }
        
        if (req.has_param("sort_by")) {
            options.sort_by = req.get_param_value("sort_by");
        } else {
            options.sort_by = "time";
        }
        
        if (req.has_param("limit")) {
            try {
                options.limit = std::stoull(req.get_param_value("limit"));
            } catch (...) {
                options.limit = 20;
            }
        } else {
            options.limit = 20;
        }
        
        auto reports = storage.list(options);
        
        nlohmann::json reports_array = nlohmann::json::array();
        for (const auto& report : reports) {
            nlohmann::json report_json;
            report_json["report_id"] = report.report_id;
            report_json["file_path"] = report.file_path;
            report_json["verdict"] = report.verdict;
            report_json["confidence"] = report.confidence;
            report_json["file_type"] = report.file_type;
            report_json["file_size"] = report.file_size;
            
            auto saved_time = std::chrono::system_clock::to_time_t(report.saved_at);
            std::tm tm = *std::gmtime(&saved_time);
            std::ostringstream oss;
            oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
            report_json["saved_at"] = oss.str();
            
            auto analyzed_time = std::chrono::system_clock::to_time_t(report.analyzed_at);
            tm = *std::gmtime(&analyzed_time);
            oss.str("");
            oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
            report_json["analyzed_at"] = oss.str();
            
            reports_array.push_back(report_json);
        }
        
        nlohmann::json response_data;
        response_data["reports"] = reports_array;
        response_data["total"] = reports.size();
        
        http::HttpResponse::sendSuccess(res, response_data);
        
        common::Logger::instance().info("[HTTP] List reports complete | count={}", reports.size());
        
    } catch (const std::exception& e) {
        common::ErrorContext ctx;
        ctx.component = "HTTP";
        ctx.details["exception"] = e.what();
        ctx.details["endpoint"] = "/api/v1/reports";
        
        nlohmann::json details;
        details["exception"] = e.what();
        http::HttpResponse::sendError(res, http::ErrorCode::SYSTEM_INTERNAL_ERROR, details);
        common::Logger::instance().error("[HTTP] List reports exception | {}", common::formatContext(ctx));
    }
}

void HttpApiServer::handleShowReport(const httplib::Request& req, httplib::Response& res) {
    try {
        std::string report_id = req.matches[1];
        
        common::Logger::instance().debug("[HTTP] Show report request | id={}", report_id);
        
        report::ReportStorage storage;
        auto result = storage.load(report_id);
        
        if (!result) {
            nlohmann::json details;
            details["report_id"] = report_id;
            http::HttpResponse::sendError(res, http::ErrorCode::FILE_NOT_FOUND, 
                                         "Report not found", details);
            common::Logger::instance().warn("[HTTP] Report not found | id={}", report_id);
            return;
        }
        
        auto report_json = format::JsonFormatter::format(*result);
        http::HttpResponse::sendSuccess(res, report_json);
        
        common::Logger::instance().info("[HTTP] Show report complete | id={}", report_id);
        
    } catch (const std::exception& e) {
        common::ErrorContext ctx;
        ctx.component = "HTTP";
        ctx.details["exception"] = e.what();
        ctx.details["endpoint"] = "/api/v1/reports/:id";
        
        nlohmann::json details;
        details["exception"] = e.what();
        http::HttpResponse::sendError(res, http::ErrorCode::SYSTEM_INTERNAL_ERROR, details);
        common::Logger::instance().error("[HTTP] Show report exception | {}", common::formatContext(ctx));
    }
}

void HttpApiServer::handleScanFile(const httplib::Request& req, httplib::Response& res) {
    try {
        if (!req.is_multipart_form_data()) {
            nlohmann::json details;
            details["expected_content_type"] = "multipart/form-data";
            details["received_content_type"] = req.get_header_value("Content-Type");
            http::HttpResponse::sendError(res, http::ErrorCode::REQUEST_INVALID_PARAMETER, details);
            return;
        }
        
        if (!req.form.has_file("file")) {
            http::HttpResponse::sendError(res, http::ErrorCode::FILE_NOT_PROVIDED);
            return;
        }
        
        auto file = req.form.get_file("file");
        
        if (!validateFileSize(file.content.size())) {
            auto& config = common::Config::instance().global();
            nlohmann::json details;
            details["max_size_mb"] = config.max_scan_size_mb;
            details["received_size_mb"] = file.content.size() / (1024 * 1024);
            http::HttpResponse::sendError(res, http::ErrorCode::FILE_TOO_LARGE, details);
            return;
        }
        
        bool include_hashes = false;
        if (req.has_param("include_hashes")) {
            std::string val = req.get_param_value("include_hashes");
            include_hashes = (val == "true" || val == "1");
        }
        
        auto start_time = std::chrono::steady_clock::now();
        
        std::vector<uint8_t> buffer(file.content.begin(), file.content.end());
        auto result = engine_->scan(buffer, include_hashes);
        
        result.file_path = file.filename.empty() ? "uploaded_file" : file.filename;
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time
        );
        result.scan_time = duration;
        
        if (result.result == common::ScanResult::ERROR) {
            nlohmann::json details;
            if (result.error_message) {
                details["error_message"] = *result.error_message;
            }
            
            http::ErrorCode http_code = http::ErrorCode::SCAN_FAILED;
            if (result.error_code) {
                http_code = http::ErrorCodeHelper::mapCoreErrorCode(*result.error_code);
                details["core_error_code"] = core::CoreErrorCodeHelper::toString(*result.error_code);
            }
            
            if (result.error_context) {
                for (const auto& [key, value] : result.error_context->details) {
                    details[key] = value;
                }
            }
            
            http::HttpResponse::sendError(res, http_code, details);
            
            common::ErrorContext ctx;
            if (result.error_context) {
                ctx = *result.error_context;
            }
            ctx.details["file"] = file.filename;
            common::Logger::instance().error("[HTTP] Scan failed | {}", common::formatContext(ctx));
            return;
        }
        
        if (result.result == common::ScanResult::UNSUPPORTED) {
            nlohmann::json details;
            details["file_type"] = result.file_type;
            details["supported_types"] = constants::file_types::getSupported();
            
            http::ErrorCode http_code = http::ErrorCode::ANALYSIS_UNSUPPORTED_FILE_TYPE;
            if (result.error_code) {
                http_code = http::ErrorCodeHelper::mapCoreErrorCode(*result.error_code);
                details["core_error_code"] = core::CoreErrorCodeHelper::toString(*result.error_code);
            }
            
            http::HttpResponse::sendError(res, http_code, details);
            common::Logger::instance().warn("[HTTP] Scan unsupported | file={} | type={}", 
                                           file.filename, result.file_type);
            return;
        }
        
        auto json_result = scanResultToJson(result);
        http::HttpResponse::sendSuccess(res, json_result);
        
        common::Logger::instance().info("[HTTP] Scan complete | result={} | confidence={:.1f}", 
                                       common::to_string(result.result), 
                                       result.confidence * 100);
        
    } catch (const std::exception& e) {
        common::ErrorContext ctx;
        ctx.component = "HTTP";
        ctx.details["exception"] = e.what();
        ctx.details["endpoint"] = "/api/v1/scan";
        
        nlohmann::json details;
        details["exception"] = e.what();
        http::HttpResponse::sendError(res, http::ErrorCode::SYSTEM_INTERNAL_ERROR, details);
        common::Logger::instance().error("[HTTP] Scan exception | {}", common::formatContext(ctx));
    }
}

void HttpApiServer::handleAnalyzeFile(const httplib::Request& req, httplib::Response& res) {
    try {
        if (!req.is_multipart_form_data()) {
            nlohmann::json details;
            details["expected_content_type"] = "multipart/form-data";
            details["received_content_type"] = req.get_header_value("Content-Type");
            http::HttpResponse::sendError(res, http::ErrorCode::REQUEST_INVALID_PARAMETER, details);
            
            common::ErrorContext ctx;
            ctx.component = "HTTP";
            ctx.details["expected"] = "multipart/form-data";
            ctx.details["received"] = req.get_header_value("Content-Type");
            common::Logger::instance().warn("[HTTP] Invalid content type | {}", common::formatContext(ctx));
            return;
        }
        
        if (!req.form.has_file("file")) {
            http::HttpResponse::sendError(res, http::ErrorCode::FILE_NOT_PROVIDED);
            return;
        }
        
        std::shared_ptr<network::AnalysisService> service;
        {
            std::lock_guard<std::mutex> lock(analysis_service_mutex_);
            service = analysis_service_;
        }
        
        if (!service) {
            http::HttpResponse::sendError(res, http::ErrorCode::ANALYSIS_API_KEY_REQUIRED);
            return;
        }
        
        auto file = req.form.get_file("file");
        
        if (!validateFileSize(file.content.size())) {
            auto& config = common::Config::instance().global();
            nlohmann::json details;
            details["max_size_mb"] = config.max_scan_size_mb;
            details["received_size_mb"] = file.content.size() / (1024 * 1024);
            http::HttpResponse::sendError(res, http::ErrorCode::FILE_TOO_LARGE, details);
            
            common::ErrorContext ctx;
            ctx.component = "HTTP";
            ctx.details["max_size_mb"] = std::to_string(config.max_scan_size_mb);
            ctx.details["received_size_mb"] = std::to_string(file.content.size() / (1024 * 1024));
            common::Logger::instance().warn("[HTTP] File too large | {}", common::formatContext(ctx));
            return;
        }
        
        std::string language = constants::languages::DEFAULT;
        if (req.has_param("language")) {
            language = req.get_param_value("language");
            if (!validateLanguage(language)) {
                nlohmann::json details;
                details["provided"] = language;
                details["supported"] = constants::languages::SUPPORTED;
                http::HttpResponse::sendError(res, http::ErrorCode::ANALYSIS_INVALID_LANGUAGE, details);
                
                common::ErrorContext ctx;
                ctx.component = "HTTP";
                ctx.details["provided_language"] = language;
                common::Logger::instance().warn("[HTTP] Invalid language | {}", common::formatContext(ctx));
                return;
            }
        }
        
        std::vector<uint8_t> buffer(file.content.begin(), file.content.end());
        auto analysis_payload = engine_->extractAnalysisPayload(buffer, language);
        
        if (!analysis_payload.isValid()) {
            core::CoreErrorCode core_error_code = core::mapSdkResult(*analysis_payload.sdk_result);
            http::ErrorCode http_error_code = http::ErrorCodeHelper::mapCoreErrorCode(core_error_code);
            
            nlohmann::json details;
            details["sdk_result"] = static_cast<int>(*analysis_payload.sdk_result);
            details["detected_type"] = analysis_payload.file_type;
            details["core_error_code"] = core::CoreErrorCodeHelper::toString(core_error_code);
            
            http::HttpResponse::sendError(res, http_error_code, details);
            
            common::ErrorContext ctx;
            ctx.component = "HTTP";
            ctx.details["file"] = file.filename;
            ctx.details["core_error_code"] = core::CoreErrorCodeHelper::toString(core_error_code);
            ctx.details["sdk_result"] = std::to_string(static_cast<int>(*analysis_payload.sdk_result));
            common::Logger::instance().warn("[HTTP] SDK extraction failed | {}", common::formatContext(ctx));
            return;
        }
        
        if (analysis_payload.analysis_blob.empty()) {
            nlohmann::json details;
            details["file_type"] = analysis_payload.file_type;
            details["reason"] = "Defensive check: blob empty despite OK result";
            details["core_error_code"] = core::CoreErrorCodeHelper::toString(core::CoreErrorCode::ANALYSIS_PAYLOAD_EMPTY);
            
            http::ErrorCode http_code = http::ErrorCodeHelper::mapCoreErrorCode(core::CoreErrorCode::ANALYSIS_PAYLOAD_EMPTY);
            http::HttpResponse::sendError(res, http_code, details);
            
            common::ErrorContext ctx;
            ctx.component = "HTTP";
            ctx.details["file"] = file.filename;
            ctx.details["core_error_code"] = core::CoreErrorCodeHelper::toString(core::CoreErrorCode::ANALYSIS_PAYLOAD_EMPTY);
            common::Logger::instance().error("[HTTP] Defensive check failed | {}", common::formatContext(ctx));
            return;
        }
        
        try {
            auto result = service->analyze(analysis_payload);
            
            if (result.verdict == "error") {
                nlohmann::json details;
                details["file_type"] = analysis_payload.file_type;
                
                http::HttpResponse::sendError(res, http::ErrorCode::ANALYSIS_CLOUD_FAILED, details);
                
                common::ErrorContext ctx;
                ctx.component = "HTTP";
                ctx.details["file"] = file.filename;
                common::Logger::instance().error("[HTTP] Cloud analysis failed | {}", common::formatContext(ctx));
                return;
            }
            
            auto json_result = format::JsonFormatter::format(result);
            http::HttpResponse::sendSuccess(res, json_result);
            
            common::Logger::instance().info("[HTTP] Analysis complete | file={} | verdict={} | confidence={:.1f}", 
                                           file.filename, result.verdict, result.confidence * 100);
            
        } catch (const std::system_error& e) {
            nlohmann::json details;
            details["error_code"] = e.code().value();
            details["error_message"] = e.what();
            
            common::ErrorContext ctx;
            ctx.component = "HTTP";
            ctx.details["file"] = file.filename;
            ctx.details["error_code"] = std::to_string(e.code().value());
            ctx.details["error_message"] = e.what();
            
            if (e.code().value() == ETIMEDOUT) {
                http::HttpResponse::sendError(res, http::ErrorCode::ANALYSIS_NETWORK_TIMEOUT, details);
                common::Logger::instance().error("[HTTP] Network timeout | {}", common::formatContext(ctx));
            } else {
                http::HttpResponse::sendError(res, http::ErrorCode::ANALYSIS_NETWORK_CONNECTION_FAILED, details);
                common::Logger::instance().error("[HTTP] Network connection failed | {}", common::formatContext(ctx));
            }
            return;
        } catch (const std::exception& e) {
            nlohmann::json details;
            details["exception"] = e.what();
            details["file_type"] = analysis_payload.file_type;
            
            http::HttpResponse::sendError(res, http::ErrorCode::SYSTEM_INTERNAL_ERROR, details);
            
            common::ErrorContext ctx;
            ctx.component = "HTTP";
            ctx.details["file"] = file.filename;
            ctx.details["exception"] = e.what();
            common::Logger::instance().error("[HTTP] Analysis exception | {}", common::formatContext(ctx));
            return;
        }
        
    } catch (const std::exception& e) {
        common::ErrorContext ctx;
        ctx.component = "HTTP";
        ctx.details["exception"] = e.what();
        ctx.details["endpoint"] = "/api/v1/analyze";
        
        nlohmann::json details;
        details["exception"] = e.what();
        http::HttpResponse::sendError(res, http::ErrorCode::SYSTEM_INTERNAL_ERROR, details);
        common::Logger::instance().error("[HTTP] Analyze exception | {}", common::formatContext(ctx));
    }
}

void HttpApiServer::handleUpdateModels(const httplib::Request& req, httplib::Response& res) {
    try {
        nlohmann::json request_json;
        try {
            if (!req.body.empty()) {
                request_json = nlohmann::json::parse(req.body);
            }
        } catch (...) {
            nlohmann::json details;
            details["reason"] = "Invalid JSON body";
            http::HttpResponse::sendError(res, http::ErrorCode::REQUEST_INVALID_PARAMETER, details);
            return;
        }
        
        std::vector<std::string> model_types;
        if (request_json.contains("model_types") && request_json["model_types"].is_array()) {
            for (const auto& type : request_json["model_types"]) {
                model_types.push_back(type);
            }
        }
        
        if (model_types.empty()) {
            model_types = constants::file_types::getSupported();
        }
        
        bool force_update = request_json.value("force_update", false);
        bool check_only = request_json.value("check_only", false);
        
        std::shared_ptr<network::ModelDownloader> local_downloader;
        {
            std::lock_guard<std::mutex> lock(downloader_mutex_);
            local_downloader = downloader_;
        }
        
        update::ModelUpdater updater(engine_, local_downloader.get());
        
        update::UpdateOptions options;
        options.model_types = model_types;
        options.force_update = force_update;
        options.check_only = check_only;
        options.quiet = false;
        
        auto summary = updater.updateModelsSync(options);
        
        nlohmann::json response;
        response["total_models"] = summary.total_models;
        response["updated_models"] = summary.updated_models;
        response["failed_models"] = summary.failed_models;
        response["updated_types"] = summary.updated_types;
        response["failed_types"] = summary.failed_types;
        response["total_time_ms"] = summary.total_time.count();
        
        nlohmann::json version_updates = nlohmann::json::array();
        for (const auto& ver_info : summary.version_info) {
            nlohmann::json ver_json;
            ver_json["model_type"] = ver_info.model_type;
            ver_json["current_timestamp"] = ver_info.current_timestamp;
            ver_json["server_timestamp"] = ver_info.server_timestamp;
            ver_json["update_available"] = ver_info.update_available;
            ver_json["has_local_version"] = ver_info.has_local_version;
            version_updates.push_back(ver_json);
        }
        response["version_info"] = version_updates;
        
        http::HttpResponse::sendSuccess(res, response);
        
        common::Logger::instance().info("[HTTP] Update complete | updated={} | failed={}", 
                                       summary.updated_models, summary.failed_models);
        
    } catch (const std::exception& e) {
        common::ErrorContext ctx;
        ctx.component = "HTTP";
        ctx.details["exception"] = e.what();
        ctx.details["endpoint"] = "/api/v1/models/update";
        
        nlohmann::json details;
        details["exception"] = e.what();
        http::HttpResponse::sendError(res, http::ErrorCode::SYSTEM_INTERNAL_ERROR, details);
        common::Logger::instance().error("[HTTP] Update exception | {}", common::formatContext(ctx));
    }
}

void HttpApiServer::handleStatus(const httplib::Request& req, httplib::Response& res) {
    nlohmann::json response;
    response["healthy"] = true;
    response["sdk_version"] = semantics_av::SemanticsAV::getVersion();
    
    static auto start_time = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
    response["uptime_seconds"] = uptime.count();
    
    http::HttpResponse::sendSuccess(res, response);
}

void HttpApiServer::handleHealth(const httplib::Request& req, httplib::Response& res) {
    nlohmann::json response;
    response["status"] = "ok";
    http::HttpResponse::sendSuccess(res, response);
}

bool HttpApiServer::validateFileSize(size_t size) {
    auto& config = common::Config::instance().global();
    size_t max_size = static_cast<size_t>(config.max_scan_size_mb) * 1024 * 1024;
    return size <= max_size;
}

bool HttpApiServer::validateLanguage(const std::string& language) {
    return constants::languages::isSupported(language);
}

bool HttpApiServer::validateFormat(const std::string& format) {
    return format == "json";
}

void HttpApiServer::sendJsonResponse(httplib::Response& res, const nlohmann::json& data, int status) {
    res.status = status;
    res.set_content(data.dump(2), "application/json");
}

void HttpApiServer::sendCsvResponse(httplib::Response& res, const std::string& csv_data) {
    res.status = 200;
    res.set_content(csv_data, "text/csv");
}

void HttpApiServer::sendJsonError(httplib::Response& res, int status, const std::string& message) {
    nlohmann::json error;
    error["error"] = message;
    res.status = status;
    res.set_content(error.dump(), "application/json");
    
    common::ErrorContext ctx;
    ctx.component = "HTTP";
    ctx.details["status"] = std::to_string(status);
    ctx.details["message"] = message;
    
    common::Logger::instance().warn("[HTTP] Error response | {}", common::formatContext(ctx));
}

nlohmann::json HttpApiServer::scanResultToJson(const common::ScanMetadata& result) {
    nlohmann::json json;
    
    json["file_path"] = result.file_path;
    json["result"] = common::to_string(result.result);
    json["confidence"] = result.confidence;
    json["file_type"] = result.file_type;
    json["file_size"] = result.file_size;
    json["scan_time_ms"] = result.scan_time.count();
    
    auto now = std::chrono::system_clock::now();
    auto time_t_val = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::gmtime(&time_t_val);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    json["scan_timestamp"] = oss.str();
    
    json["sdk_version"] = semantics_av::SemanticsAV::getVersion();
    
    if (!result.file_type.empty() && result.file_type != "unknown") {
        auto model_info = engine_->getModelInfo(result.file_type);
        auto model_time = std::chrono::system_clock::to_time_t(model_info.server_created_at);
        std::tm model_tm = *std::gmtime(&model_time);
        std::ostringstream model_oss;
        model_oss << std::put_time(&model_tm, "%Y-%m-%dT%H:%M:%SZ");
        json["model_version"] = model_oss.str();
    }
    
    if (result.error_message) {
        json["error"] = *result.error_message;
    }
    
    if (result.file_hashes && !result.file_hashes->empty()) {
        json["file_hashes"] = *result.file_hashes;
    }
    
    return json;
}

std::string HttpApiServer::scanResultToCsv(const common::ScanMetadata& result) {
    std::ostringstream csv;
    
    csv << "\"" << result.file_path << "\","
        << common::to_string(result.result) << ","
        << result.confidence << ","
        << result.file_type << ","
        << result.file_size << ","
        << result.scan_time.count();
    
    if (result.error_message) {
        csv << ",\"" << *result.error_message << "\"";
    }
    
    csv << "\n";
    return csv.str();
}

nlohmann::json HttpApiServer::analysisResultToJson(const network::AnalysisResult& result) {
    return format::JsonFormatter::format(result);
}

}}