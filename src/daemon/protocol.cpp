#include "semantics_av/daemon/protocol.hpp"
#include "semantics_av/common/constants.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/format/json_formatter.hpp"
#include <nlohmann/json.hpp>
#include <cstring>

namespace semantics_av {
namespace daemon {

Protocol::Protocol() : next_sequence_(1) {}
Protocol::~Protocol() = default;

bool Protocol::parseScanRequest(const std::vector<uint8_t>& data, ScanRequest& request) {
    if (data.empty()) return false;
    
    std::string json_str(data.begin(), data.end());
    auto json = nlohmann::json::parse(json_str);
    
    request.file_path = json["file_path"].get<std::string>();
    request.include_hashes = json.value("include_hashes", false);
    
    return !request.file_path.empty();
}

bool Protocol::parseScanDirectoryInit(const std::vector<uint8_t>& data, ScanDirectoryInit& request) {
    if (data.empty()) return false;
    
    std::string json_str(data.begin(), data.end());
    auto json = nlohmann::json::parse(json_str);
    
    request.total_files = json["total_files"];
    request.total_batches = json["total_batches"];
    request.recursive = json.value("recursive", false);
    request.max_file_size = json.value("max_file_size", constants::limits::DEFAULT_MAX_FILE_SIZE_MB * 1024 * 1024);
    request.max_threads = json.value("max_threads", constants::limits::DEFAULT_SCAN_THREADS);
    request.infected_only = json.value("infected_only", false);
    request.include_hashes = json.value("include_hashes", false);
    request.verbose = json.value("verbose", false);
    
    if (json.contains("exclude_patterns") && json["exclude_patterns"].is_array()) {
        for (const auto& pattern : json["exclude_patterns"]) {
            request.exclude_patterns.push_back(pattern.get<std::string>());
        }
    }
    
    return request.total_files > 0;
}

bool Protocol::parseScanBatchFds(const std::vector<uint8_t>& data, ScanBatchFds& request) {
    if (data.empty()) return false;
    
    std::string json_str(data.begin(), data.end());
    auto json = nlohmann::json::parse(json_str);
    
    request.batch_index = json["batch_index"];
    
    if (json.contains("file_paths") && json["file_paths"].is_array()) {
        for (const auto& path : json["file_paths"]) {
            request.file_paths.push_back(path.get<std::string>());
        }
    }
    
    return !request.file_paths.empty();
}

bool Protocol::parseAnalyzeRequest(const std::vector<uint8_t>& data, AnalyzeRequest& request) {
    if (data.empty()) return false;
    
    std::string json_str(data.begin(), data.end());
    auto json = nlohmann::json::parse(json_str);
    
    request.file_path = json["file_path"].get<std::string>();
    request.language = json.value("language", "");
    
    return !request.file_path.empty();
}

bool Protocol::parseStatusRequest(const std::vector<uint8_t>& data, StatusRequest& request) {
    if (data.empty()) {
        request.include_stats = false;
        return true;
    }
    
    std::string json_str(data.begin(), data.end());
    auto json = nlohmann::json::parse(json_str);
    request.include_stats = json.value("include_stats", false);
    
    return true;
}

bool Protocol::parsePingRequest(const std::vector<uint8_t>& data, PingRequest& request) {
    if (data.empty()) {
        request.payload = "";
        return true;
    }
    
    std::string json_str(data.begin(), data.end());
    auto json = nlohmann::json::parse(json_str);
    request.payload = json.value("payload", "");
    
    return true;
}

bool Protocol::parseShutdownRequest(const std::vector<uint8_t>& data, ShutdownRequest& request) {
    if (data.empty()) {
        request.force = false;
        return true;
    }
    
    std::string json_str(data.begin(), data.end());
    auto json = nlohmann::json::parse(json_str);
    request.force = json.value("force", false);
    
    return true;
}

bool Protocol::parseScanFileComplete(const std::vector<uint8_t>& data, ScanFileComplete& result) {
    if (data.empty()) return false;
    
    std::string json_str(data.begin(), data.end());
    auto json = nlohmann::json::parse(json_str);
    
    result.file_path = json["file_path"].get<std::string>();
    
    std::string result_str = json["result"];
    if (result_str == "CLEAN") result.result = common::ScanResult::CLEAN;
    else if (result_str == "MALICIOUS") result.result = common::ScanResult::MALICIOUS;
    else if (result_str == "UNSUPPORTED") result.result = common::ScanResult::UNSUPPORTED;
    else result.result = common::ScanResult::ERROR;
    
    result.confidence = json["confidence"];
    result.file_type = json["file_type"];
    result.file_size = json["file_size"];
    result.scan_time_ms = json.value("scan_time_ms", 0);
    result.current_file = json["current_file"];
    result.total_files = json["total_files"];
    
    if (json.contains("error")) {
        result.error_message = json["error"];
    }
    
    if (json.contains("file_hashes") && json["file_hashes"].is_object()) {
        for (auto it = json["file_hashes"].begin(); it != json["file_hashes"].end(); ++it) {
            result.file_hashes[it.key()] = it.value();
        }
    }
    
    return true;
}

bool Protocol::parseUpdateModelsRequest(const std::vector<uint8_t>& data, UpdateModelsRequest& request) {
    if (data.empty()) return false;
    
    std::string json_str(data.begin(), data.end());
    auto json = nlohmann::json::parse(json_str);
    
    if (json.contains("model_types") && json["model_types"].is_array()) {
        for (const auto& type : json["model_types"]) {
            request.model_types.push_back(type.get<std::string>());
        }
    }
    
    request.force_update = json.value("force_update", false);
    request.check_only = json.value("check_only", false);
    
    return true;
}

bool Protocol::parseConfigGetRequest(const std::vector<uint8_t>& data, ConfigGetRequest& request) {
    if (data.empty()) {
        request.include_metadata = false;
        return true;
    }
    
    std::string json_str(data.begin(), data.end());
    auto json = nlohmann::json::parse(json_str);
    
    if (json.contains("keys") && json["keys"].is_array()) {
        for (const auto& key : json["keys"]) {
            request.keys.push_back(key.get<std::string>());
        }
    }
    
    request.include_metadata = json.value("include_metadata", false);
    return true;
}

bool Protocol::parseDeleteReportRequest(const std::vector<uint8_t>& data, DeleteReportRequest& request) {
    if (data.empty()) return false;
    
    std::string json_str(data.begin(), data.end());
    auto json = nlohmann::json::parse(json_str);
    
    request.report_id = json["report_id"].get<std::string>();
    
    return !request.report_id.empty();
}

bool Protocol::parseListReportsRequest(const std::vector<uint8_t>& data, ListReportsRequest& request) {
    if (data.empty()) {
        request.limit = 20;
        request.sort_by = "time";
        return true;
    }
    
    std::string json_str(data.begin(), data.end());
    auto json = nlohmann::json::parse(json_str);
    
    request.filter_verdict = json.value("filter_verdict", "");
    request.filter_date = json.value("filter_date", "");
    request.filter_file_type = json.value("filter_file_type", "");
    request.sort_by = json.value("sort_by", "time");
    request.limit = json.value("limit", 20);
    
    return true;
}

bool Protocol::parseShowReportRequest(const std::vector<uint8_t>& data, ShowReportRequest& request) {
    if (data.empty()) return false;
    
    std::string json_str(data.begin(), data.end());
    auto json = nlohmann::json::parse(json_str);
    
    request.report_id = json["report_id"].get<std::string>();
    
    return !request.report_id.empty();
}

std::vector<uint8_t> Protocol::serializeScanResponse(const ScanResponse& response) {
    nlohmann::json json;
    
    json["result"] = common::to_string(response.result);
    json["confidence"] = response.confidence;
    json["file_type"] = response.file_type;
    json["file_path"] = response.file_path;
    json["file_size"] = response.file_size;
    json["scan_time_ms"] = response.scan_time_ms;
    json["scan_timestamp"] = response.scan_timestamp;
    json["sdk_version"] = response.sdk_version;
    json["model_version"] = response.model_version;
    
    if (!response.error_message.empty()) {
        json["error"] = response.error_message;
    }
    
    if (!response.file_hashes.empty()) {
        json["file_hashes"] = response.file_hashes;
    }
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeScanDirectoryInit(const ScanDirectoryInit& init) {
    nlohmann::json json;
    json["total_files"] = init.total_files;
    json["total_batches"] = init.total_batches;
    json["recursive"] = init.recursive;
    json["max_file_size"] = init.max_file_size;
    json["max_threads"] = init.max_threads;
    json["infected_only"] = init.infected_only;
    json["include_hashes"] = init.include_hashes;
    json["verbose"] = init.verbose;
    json["exclude_patterns"] = init.exclude_patterns;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeScanBatchFds(const ScanBatchFds& batch) {
    nlohmann::json json;
    json["batch_index"] = batch.batch_index;
    json["file_paths"] = batch.file_paths;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeScanFileComplete(const ScanFileComplete& result) {
    nlohmann::json json;
    
    json["file_path"] = result.file_path;
    json["result"] = common::to_string(result.result);
    json["confidence"] = result.confidence;
    json["file_type"] = result.file_type;
    json["file_size"] = result.file_size;
    json["scan_time_ms"] = result.scan_time_ms;
    json["current_file"] = result.current_file;
    json["total_files"] = result.total_files;
    
    if (!result.error_message.empty()) {
        json["error"] = result.error_message;
    }
    
    if (!result.file_hashes.empty()) {
        json["file_hashes"] = result.file_hashes;
    }
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeScanDirectoryResponse(const ScanDirectoryResponse& response) {
    nlohmann::json json;
    
    json["total_files"] = response.total_files;
    json["clean_files"] = response.clean_files;
    json["malicious_files"] = response.malicious_files;
    json["unsupported_files"] = response.unsupported_files;
    json["error_files"] = response.error_files;
    json["total_time_ms"] = response.total_time_ms;
    
    nlohmann::json results_array = nlohmann::json::array();
    for (const auto& result : response.results) {
        nlohmann::json result_json;
        result_json["file_path"] = result.file_path;
        result_json["result"] = common::to_string(result.result);
        result_json["confidence"] = result.confidence;
        result_json["file_type"] = result.file_type;
        result_json["file_size"] = result.file_size;
        
        if (result.error_message) {
            result_json["error"] = *result.error_message;
        }
        
        if (result.file_hashes && !result.file_hashes->empty()) {
            result_json["file_hashes"] = *result.file_hashes;
        }
        
        results_array.push_back(result_json);
    }
    json["results"] = results_array;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeAnalyzeResponse(const AnalyzeResponse& response) {
    nlohmann::json json;
    
    json["verdict"] = response.verdict;
    json["confidence"] = response.confidence;
    json["tags"] = response.tags;
    json["natural_language_report"] = response.natural_language_report;
    json["analysis_timestamp"] = response.analysis_timestamp;
    json["file_type"] = response.file_type;
    json["sdk_version"] = response.sdk_version;
    
    if (!response.signature.empty()) {
        json["signature"] = response.signature;
    }
    
    if (!response.static_attributes_json.empty()) {
        json["static_attributes"] = nlohmann::json::parse(response.static_attributes_json);
    }
    
    if (!response.file_hashes_json.empty()) {
        json["file_hashes"] = nlohmann::json::parse(response.file_hashes_json);
    }
    
    if (!response.intelligence_json.empty()) {
        json["intelligence"] = nlohmann::json::parse(response.intelligence_json);
    }
    
    if (!response.saved_report_id.empty()) {
        json["saved_report_id"] = response.saved_report_id;
    }
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeStatusResponse(const StatusResponse& response) {
    nlohmann::json json;
    
    json["healthy"] = response.healthy;
    json["uptime_seconds"] = response.uptime_seconds;
    json["scans_processed"] = response.scans_processed;
    json["active_connections"] = response.active_connections;
    json["sdk_version"] = response.sdk_version;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializePingResponse(const PingResponse& response) {
    nlohmann::json json;
    json["payload"] = response.payload;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeErrorResponse(const std::string& error) {
    nlohmann::json json;
    json["error"] = error;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeErrorResponse(const std::string& error, const std::string& error_code) {
    nlohmann::json json;
    json["error"]["message"] = error;
    json["error"]["code"] = error_code;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeUpdateModelsRequest(const UpdateModelsRequest& request) {
    nlohmann::json json;
    json["model_types"] = request.model_types;
    json["force_update"] = request.force_update;
    json["check_only"] = request.check_only;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeUpdateModelsResponse(const UpdateModelsResponse& response) {
    nlohmann::json json;
    json["total_models"] = response.total_models;
    json["updated_models"] = response.updated_models;
    json["failed_models"] = response.failed_models;
    json["updated_types"] = response.updated_types;
    json["failed_types"] = response.failed_types;
    json["total_time_ms"] = response.total_time_ms;
    
    nlohmann::json version_updates_array = nlohmann::json::array();
    for (const auto& ver_update : response.version_updates) {
        nlohmann::json ver_json;
        ver_json["model_type"] = ver_update.model_type;
        ver_json["old_timestamp"] = ver_update.old_timestamp;
        ver_json["new_timestamp"] = ver_update.new_timestamp;
        ver_json["was_updated"] = ver_update.was_updated;
        ver_json["had_previous_version"] = ver_update.had_previous_version;
        version_updates_array.push_back(ver_json);
    }
    json["version_updates"] = version_updates_array;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeConfigGetRequest(const ConfigGetRequest& request) {
    nlohmann::json json;
    json["keys"] = request.keys;
    json["include_metadata"] = request.include_metadata;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeConfigGetResponse(const ConfigGetResponse& response) {
    nlohmann::json json;
    json["values"] = response.values;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeDeleteReportRequest(const DeleteReportRequest& request) {
    nlohmann::json json;
    json["report_id"] = request.report_id;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeDeleteReportResponse(const DeleteReportResponse& response) {
    nlohmann::json json;
    json["success"] = response.success;
    if (!response.error_message.empty()) {
        json["error_message"] = response.error_message;
    }
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeListReportsRequest(const ListReportsRequest& request) {
    nlohmann::json json;
    json["filter_verdict"] = request.filter_verdict;
    json["filter_date"] = request.filter_date;
    json["filter_file_type"] = request.filter_file_type;
    json["sort_by"] = request.sort_by;
    json["limit"] = request.limit;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeListReportsResponse(const ListReportsResponse& response) {
    nlohmann::json json;
    nlohmann::json reports_array = nlohmann::json::array();
    
    for (const auto& report : response.reports) {
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
    
    json["reports"] = reports_array;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeShowReportRequest(const ShowReportRequest& request) {
    nlohmann::json json;
    json["report_id"] = request.report_id;
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

std::vector<uint8_t> Protocol::serializeShowReportResponse(const ShowReportResponse& response) {
    nlohmann::json json;
    json["success"] = response.success;
    
    if (!response.error_message.empty()) {
        json["error_message"] = response.error_message;
    }
    
    if (!response.report_json.empty()) {
        json["report"] = nlohmann::json::parse(response.report_json);
    }
    
    std::string json_str = json.dump();
    return std::vector<uint8_t>(json_str.begin(), json_str.end());
}

}}