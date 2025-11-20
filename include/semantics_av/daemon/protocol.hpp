#pragma once

#include "semantics_av/common/types.hpp"
#include "semantics_av/common/constants.hpp"
#include "semantics_av/scan/scanner.hpp"
#include "semantics_av/report/storage.hpp"
#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace semantics_av {
namespace daemon {

enum class MessageType : uint8_t {
    SCAN_REQUEST = 1,
    SCAN_RESPONSE = 2,
    STATUS_REQUEST = 3,
    STATUS_RESPONSE = 4,
    PING_REQUEST = 5,
    PING_RESPONSE = 6,
    SHUTDOWN_REQUEST = 7,
    ERROR_RESPONSE = 8,
    ANALYZE_REQUEST = 9,
    ANALYZE_RESPONSE = 10,
    SCAN_DIRECTORY_INIT = 11,
    SCAN_BATCH_FDS = 12,
    SCAN_DIRECTORY_COMPLETE = 14,
    SCAN_DIRECTORY_RESPONSE = 15,
    SCAN_FILE_COMPLETE = 16,
    UPDATE_MODELS_REQUEST = 17,
    UPDATE_MODELS_RESPONSE = 18,
    CONFIG_GET_REQUEST = 19,
    CONFIG_GET_RESPONSE = 20,
    DELETE_REPORT_REQUEST = 21,
    DELETE_REPORT_RESPONSE = 22,
    LIST_REPORTS_REQUEST = 23,
    LIST_REPORTS_RESPONSE = 24,
    SHOW_REPORT_REQUEST = 25,
    SHOW_REPORT_RESPONSE = 26
};

struct MessageHeader {
    uint32_t magic;
    MessageType type;
    uint32_t length;
    uint32_t sequence;
    
    MessageHeader() 
        : magic(constants::protocol::MAGIC_NUMBER)
        , type()
        , length(0)
        , sequence(0) {}
} __attribute__((packed));

struct ScanRequest {
    std::string file_path;
    bool include_hashes = false;
};

struct ScanResponse {
    common::ScanResult result;
    float confidence;
    std::string file_type;
    std::string file_path;
    size_t file_size;
    uint64_t scan_time_ms;
    std::string scan_timestamp;
    std::string sdk_version;
    std::string model_version;
    std::string error_message;
    std::map<std::string, std::string> file_hashes;
    
    bool is_archive = false;
    size_t archive_total_files = 0;
    size_t archive_malicious_files = 0;
    size_t archive_clean_files = 0;
    size_t archive_unsupported_files = 0;
    size_t archive_error_files = 0;
    size_t archive_encrypted_files = 0;
    std::vector<std::string> infected_files;
    std::vector<common::ScanMetadata> archive_results;
};

struct ScanDirectoryInit {
    size_t total_files;
    size_t total_batches;
    bool recursive;
    size_t max_file_size;
    int max_threads;
    std::vector<std::string> exclude_patterns;
    bool infected_only;
    bool include_hashes;
    bool verbose;
};

struct ScanBatchFds {
    std::vector<std::string> file_paths;
    size_t batch_index;
};

struct ScanFileComplete {
    std::string file_path;
    common::ScanResult result;
    float confidence;
    std::string file_type;
    size_t file_size;
    uint64_t scan_time_ms;
    std::string error_message;
    size_t current_file;
    size_t total_files;
    std::map<std::string, std::string> file_hashes;
};

struct ScanDirectoryResponse {
    size_t total_files;
    size_t clean_files;
    size_t malicious_files;
    size_t unsupported_files;
    size_t error_files;
    uint64_t total_time_ms;
    std::vector<common::ScanMetadata> results;
    std::string source_file_path;
    size_t source_file_size;
    common::ScanResult aggregated_result;
    float aggregated_confidence;
    size_t client_open_failures = 0;
    size_t encrypted_files = 0;
    size_t archive_errors = 0;
    size_t compression_ratio_exceeded = 0;
};

struct AnalyzeRequest {
    std::string file_path;
    std::string language;
};

struct AnalyzeResponse {
    std::string verdict;
    float confidence;
    std::vector<std::string> tags;
    std::string signature;
    std::string static_attributes_json;
    std::string file_hashes_json;
    std::string file_type;
    std::string natural_language_report;
    std::string analysis_timestamp;
    std::string sdk_version;
    std::string intelligence_json;
    std::string saved_report_id;
};

struct StatusRequest {
    bool include_stats;
};

struct StatusResponse {
    bool healthy;
    uint64_t uptime_seconds;
    uint64_t scans_processed;
    uint32_t active_connections;
    std::string sdk_version;
};

struct PingRequest {
    std::string payload;
};

struct PingResponse {
    std::string payload;
};

struct ShutdownRequest {
    bool force;
};

struct UpdateModelsRequest {
    std::vector<std::string> model_types;
    bool force_update;
    bool check_only;
};

struct ModelVersionUpdate {
    std::string model_type;
    int64_t old_timestamp;
    int64_t new_timestamp;
    bool was_updated;
    bool had_previous_version;
};

struct UpdateModelsResponse {
    size_t total_models;
    size_t updated_models;
    size_t failed_models;
    std::vector<std::string> updated_types;
    std::vector<std::string> failed_types;
    std::vector<ModelVersionUpdate> version_updates;
    uint64_t total_time_ms;
};

struct ConfigGetRequest {
    std::vector<std::string> keys;
    bool include_metadata;
};

struct ConfigGetResponse {
    std::map<std::string, std::string> values;
};

struct DeleteReportRequest {
    std::string report_id;
};

struct DeleteReportResponse {
    bool success;
    std::string error_message;
};

struct ListReportsRequest {
    std::string filter_verdict;
    std::string filter_date;
    std::string filter_file_type;
    std::string sort_by;
    size_t limit;
};

struct ListReportsResponse {
    std::vector<report::ReportMetadata> reports;
};

struct ShowReportRequest {
    std::string report_id;
};

struct ShowReportResponse {
    bool success;
    std::string error_message;
    std::string report_json;
};

class Connection {
public:
    virtual ~Connection() = default;
    
    virtual bool readMessage(MessageHeader& header, std::vector<uint8_t>& data) = 0;
    virtual bool writeMessage(MessageType type, uint32_t sequence, 
                              const std::vector<uint8_t>& data) = 0;
    virtual void close() = 0;
    virtual bool isConnected() const = 0;
    
    virtual std::string getRemoteAddress() const = 0;
    virtual uint16_t getRemotePort() const = 0;
    
    virtual bool readMessageWithFd(MessageHeader& header, std::vector<uint8_t>& data, int& fd) = 0;
    virtual bool readMessageWithFds(MessageHeader& header, std::vector<uint8_t>& data, std::vector<int>& fds) = 0;
    virtual bool writeMessageWithFd(MessageType type, uint32_t sequence,
                                    const std::vector<uint8_t>& data, int fd) = 0;
    virtual bool writeMessageWithFds(MessageType type, uint32_t sequence,
                                     const std::vector<uint8_t>& data, const std::vector<int>& fds) = 0;
};

class Protocol {
public:
    Protocol();
    ~Protocol();
    
    bool parseScanRequest(const std::vector<uint8_t>& data, ScanRequest& request);
    bool parseScanDirectoryInit(const std::vector<uint8_t>& data, ScanDirectoryInit& request);
    bool parseScanBatchFds(const std::vector<uint8_t>& data, ScanBatchFds& request);
    bool parseAnalyzeRequest(const std::vector<uint8_t>& data, AnalyzeRequest& request);
    bool parseStatusRequest(const std::vector<uint8_t>& data, StatusRequest& request);
    bool parsePingRequest(const std::vector<uint8_t>& data, PingRequest& request);
    bool parseShutdownRequest(const std::vector<uint8_t>& data, ShutdownRequest& request);
    bool parseScanFileComplete(const std::vector<uint8_t>& data, ScanFileComplete& result);
    bool parseUpdateModelsRequest(const std::vector<uint8_t>& data, UpdateModelsRequest& request);
    bool parseConfigGetRequest(const std::vector<uint8_t>& data, ConfigGetRequest& request);
    bool parseDeleteReportRequest(const std::vector<uint8_t>& data, DeleteReportRequest& request);
    bool parseListReportsRequest(const std::vector<uint8_t>& data, ListReportsRequest& request);
    bool parseShowReportRequest(const std::vector<uint8_t>& data, ShowReportRequest& request);
    
    std::vector<uint8_t> serializeScanResponse(const ScanResponse& response);
    std::vector<uint8_t> serializeScanDirectoryInit(const ScanDirectoryInit& init);
    std::vector<uint8_t> serializeScanBatchFds(const ScanBatchFds& batch);
    std::vector<uint8_t> serializeScanFileComplete(const ScanFileComplete& result);
    std::vector<uint8_t> serializeScanDirectoryResponse(const ScanDirectoryResponse& response);
    std::vector<uint8_t> serializeAnalyzeResponse(const AnalyzeResponse& response);
    std::vector<uint8_t> serializeStatusResponse(const StatusResponse& response);
    std::vector<uint8_t> serializePingResponse(const PingResponse& response);
    std::vector<uint8_t> serializeErrorResponse(const std::string& error);
    std::vector<uint8_t> serializeErrorResponse(const std::string& error, const std::string& error_code);
    std::vector<uint8_t> serializeUpdateModelsRequest(const UpdateModelsRequest& request);
    std::vector<uint8_t> serializeUpdateModelsResponse(const UpdateModelsResponse& response);
    std::vector<uint8_t> serializeConfigGetRequest(const ConfigGetRequest& request);
    std::vector<uint8_t> serializeConfigGetResponse(const ConfigGetResponse& response);
    std::vector<uint8_t> serializeDeleteReportRequest(const DeleteReportRequest& request);
    std::vector<uint8_t> serializeDeleteReportResponse(const DeleteReportResponse& response);
    std::vector<uint8_t> serializeListReportsRequest(const ListReportsRequest& request);
    std::vector<uint8_t> serializeListReportsResponse(const ListReportsResponse& response);
    std::vector<uint8_t> serializeShowReportRequest(const ShowReportRequest& request);
    std::vector<uint8_t> serializeShowReportResponse(const ShowReportResponse& response);

private:
    uint32_t next_sequence_;
    
    template<typename T>
    bool deserialize(const std::vector<uint8_t>& data, T& obj);
    
    template<typename T>
    std::vector<uint8_t> serialize(const T& obj);
};

}}