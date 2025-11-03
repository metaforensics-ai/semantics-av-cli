#include "semantics_av/daemon/client.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/config.hpp"
#include "semantics_av/common/paths.hpp"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <fcntl.h>
#include <thread>
#include <queue>
#include <condition_variable>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

namespace semantics_av {
namespace daemon {

struct BatchContext {
    size_t batch_index;
    std::vector<std::string> file_paths;
    size_t expected_responses;
    size_t received_responses{0};
};

struct PipelineState {
    std::queue<BatchContext> in_flight_batches;
    std::mutex queue_mutex;
    std::condition_variable sender_cv;
    std::condition_variable receiver_cv;
    
    std::atomic<size_t> files_sent{0};
    std::atomic<size_t> files_received{0};
    std::atomic<bool> sending_complete{false};
    std::atomic<bool> error_occurred{false};
    
    const size_t total_files;
    const size_t MAX_IN_FLIGHT;
    
    explicit PipelineState(size_t total, size_t server_threads) 
        : total_files(total),
          MAX_IN_FLIGHT(std::max(4UL, server_threads * 2)) {}
};

class DaemonClient::Impl {
public:
    Impl() : socket_fd_(-1), is_unix_socket_(false), is_http_(false) {}
    
    ~Impl() {
        disconnect();
    }
    
    bool connectUnixSocket(const std::string& socket_path) {
        socket_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd_ < 0) {
            return false;
        }
        
        int sndbuf = 1048576;
        int rcvbuf = 1048576;
        setsockopt(socket_fd_, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        setsockopt(socket_fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
        
        if (::connect(socket_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            ::close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }
        
        is_unix_socket_ = true;
        is_http_ = false;
        return true;
    }
    
    bool connectHttpApi(const std::string& host, uint16_t port) {
        try {
            http_client_ = std::make_unique<httplib::Client>(host, port);
            http_client_->set_connection_timeout(5, 0);
            
            auto res = http_client_->Get("/api/v1/health");
            if (res && res->status == 200) {
                is_http_ = true;
                is_unix_socket_ = false;
                http_host_ = host;
                http_port_ = port;
                return true;
            }
        } catch (...) {
        }
        
        http_client_.reset();
        return false;
    }
    
    void disconnect() {
        if (socket_fd_ >= 0) {
            ::close(socket_fd_);
            socket_fd_ = -1;
        }
        
        if (http_client_) {
            try {
                http_client_->stop();
                http_client_.release();
            } catch (...) {
            }
        }
        
        is_unix_socket_ = false;
        is_http_ = false;
    }
    
    bool isConnected() const {
        return is_unix_socket_ || is_http_;
    }
    
    bool isUnixSocket() const {
        return is_unix_socket_;
    }
    
    bool sendRequest(MessageType type, const std::vector<uint8_t>& data) {
        if (!is_unix_socket_ || socket_fd_ < 0) return false;
        
        MessageHeader header;
        header.type = type;
        header.length = data.size();
        header.sequence = sequence_++;
        
        ssize_t result = send(socket_fd_, &header, sizeof(header), MSG_NOSIGNAL);
        if (result != sizeof(header)) {
            return false;
        }
        
        if (!data.empty()) {
            result = send(socket_fd_, data.data(), data.size(), MSG_NOSIGNAL);
            if (result != static_cast<ssize_t>(data.size())) {
                return false;
            }
        }
        
        return true;
    }
    
    bool sendRequestWithFd(MessageType type, const std::vector<uint8_t>& data, int fd) {
        if (!is_unix_socket_ || socket_fd_ < 0) return false;
        
        MessageHeader header;
        header.type = type;
        header.length = data.size();
        header.sequence = sequence_++;
        
        struct msghdr msg;
        std::memset(&msg, 0, sizeof(msg));
        
        struct iovec iov[2];
        char ctrl_buf[CMSG_SPACE(sizeof(int))];
        
        iov[0].iov_base = &header;
        iov[0].iov_len = sizeof(header);
        iov[1].iov_base = const_cast<uint8_t*>(data.data());
        iov[1].iov_len = data.size();
        
        msg.msg_iov = iov;
        msg.msg_iovlen = 2;
        msg.msg_control = ctrl_buf;
        msg.msg_controllen = sizeof(ctrl_buf);
        
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        *reinterpret_cast<int*>(CMSG_DATA(cmsg)) = fd;
        
        ssize_t result = sendmsg(socket_fd_, &msg, 0);
        return result > 0;
    }
    
    bool sendRequestWithFds(MessageType type, const std::vector<uint8_t>& data, const std::vector<int>& fds) {
        if (!is_unix_socket_ || socket_fd_ < 0 || fds.empty()) return false;
        
        MessageHeader header;
        header.type = type;
        header.length = data.size();
        header.sequence = sequence_++;
        
        struct msghdr msg;
        std::memset(&msg, 0, sizeof(msg));
        
        struct iovec iov[2];
        size_t cmsg_size = CMSG_SPACE(sizeof(int) * fds.size());
        std::vector<char> ctrl_buf(cmsg_size);
        
        iov[0].iov_base = &header;
        iov[0].iov_len = sizeof(header);
        iov[1].iov_base = const_cast<uint8_t*>(data.data());
        iov[1].iov_len = data.size();
        
        msg.msg_iov = iov;
        msg.msg_iovlen = 2;
        msg.msg_control = ctrl_buf.data();
        msg.msg_controllen = cmsg_size;
        
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int) * fds.size());
        
        std::memcpy(CMSG_DATA(cmsg), fds.data(), sizeof(int) * fds.size());
        
        ssize_t result = sendmsg(socket_fd_, &msg, 0);
        return result > 0;
    }
    
    std::optional<std::vector<uint8_t>> receiveResponse(MessageType expected_type) {
        if (!is_unix_socket_ || socket_fd_ < 0) return std::nullopt;
        
        MessageHeader header;
        ssize_t result = recv(socket_fd_, &header, sizeof(header), MSG_WAITALL);
        if (result != sizeof(header)) {
            return std::nullopt;
        }
        
        if (header.magic != 0x53415643) {
            return std::nullopt;
        }
        
        if (header.type == MessageType::ERROR_RESPONSE) {
            if (header.length > 0) {
                std::vector<uint8_t> error_data(header.length);
                recv(socket_fd_, error_data.data(), header.length, MSG_WAITALL);
            }
            return std::nullopt;
        }
        
        if (header.type != expected_type) {
            return std::nullopt;
        }
        
        if (header.length == 0) {
            return std::vector<uint8_t>();
        }
        
        std::vector<uint8_t> data(header.length);
        result = recv(socket_fd_, data.data(), header.length, MSG_WAITALL);
        if (result != static_cast<ssize_t>(header.length)) {
            return std::nullopt;
        }
        
        return data;
    }
    
    std::optional<std::pair<MessageType, std::vector<uint8_t>>> receiveAnyResponse() {
        if (!is_unix_socket_ || socket_fd_ < 0) return std::nullopt;
        
        MessageHeader header;
        ssize_t result = recv(socket_fd_, &header, sizeof(header), MSG_WAITALL);
        if (result != sizeof(header)) {
            return std::nullopt;
        }
        
        if (header.magic != 0x53415643) {
            return std::nullopt;
        }
        
        std::vector<uint8_t> data;
        if (header.length > 0) {
            data.resize(header.length);
            result = recv(socket_fd_, data.data(), header.length, MSG_WAITALL);
            if (result != static_cast<ssize_t>(header.length)) {
                return std::nullopt;
            }
        }
        
        return std::make_pair(header.type, data);
    }
    
    int socket_fd_;
    bool is_unix_socket_;
    bool is_http_;
    uint32_t sequence_ = 1;
    
    std::unique_ptr<httplib::Client> http_client_;
    std::string http_host_;
    uint16_t http_port_;
};

DaemonClient::DaemonClient() : pimpl_(std::make_unique<Impl>()) {}

DaemonClient::~DaemonClient() = default;

bool DaemonClient::connect() {
    auto& config = common::Config::instance().global();
    
    if (connectUnixSocket(config.daemon.socket_path)) {
        return true;
    }
    
    if (connectHttpApi(config.daemon.http_host, config.daemon.http_port)) {
        return true;
    }
    
    return false;
}

bool DaemonClient::connectUnixSocket(const std::string& socket_path) {
    return pimpl_->connectUnixSocket(socket_path);
}

bool DaemonClient::connectHttpApi(const std::string& host, uint16_t port) {
    return pimpl_->connectHttpApi(host, port);
}

void DaemonClient::disconnect() {
    pimpl_->disconnect();
}

bool DaemonClient::isConnected() const {
    return pimpl_->isConnected();
}

bool DaemonClient::isUnixSocket() const {
    return pimpl_->isUnixSocket();
}

std::optional<ScanResponse> DaemonClient::scan(const std::string& file_path, bool include_hashes) {
    if (!pimpl_->isUnixSocket()) {
        return std::nullopt;
    }
    
    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) {
        return std::nullopt;
    }
    
    nlohmann::json request_json;
    request_json["file_path"] = file_path;
    request_json["include_hashes"] = include_hashes;
    
    std::string json_str = request_json.dump();
    std::vector<uint8_t> request_data(json_str.begin(), json_str.end());
    
    if (!sendRequestWithFd(MessageType::SCAN_REQUEST, request_data, fd)) {
        close(fd);
        return std::nullopt;
    }
    
    close(fd);
    
    auto response_data = receiveResponse(MessageType::SCAN_RESPONSE);
    if (!response_data) {
        return std::nullopt;
    }
    
    std::string json_str2(response_data->begin(), response_data->end());
    auto json = nlohmann::json::parse(json_str2);
    
    ScanResponse response;
    
    std::string result_str = json["result"];
    if (result_str == "CLEAN") response.result = common::ScanResult::CLEAN;
    else if (result_str == "MALICIOUS") response.result = common::ScanResult::MALICIOUS;
    else if (result_str == "UNSUPPORTED") response.result = common::ScanResult::UNSUPPORTED;
    else response.result = common::ScanResult::ERROR;
    
    response.confidence = json.value("confidence", 0.0f);
    response.file_type = json.value("file_type", "");
    response.file_size = json.value("file_size", 0);
    response.scan_time_ms = json.value("scan_time_ms", 0);
    response.scan_timestamp = json.value("scan_timestamp", "");
    response.sdk_version = json.value("sdk_version", "");
    response.model_version = json.value("model_version", "");
    response.error_message = json.value("error", "");
    
    if (json.contains("file_hashes") && json["file_hashes"].is_object()) {
        for (auto it = json["file_hashes"].begin(); it != json["file_hashes"].end(); ++it) {
            response.file_hashes[it.key()] = it.value();
        }
    }
    
    return response;
}

std::optional<ScanDirectoryResponse> DaemonClient::scanDirectoryWithFds(
    const ScanDirectoryInit& init,
    const std::vector<std::filesystem::path>& files,
    size_t batch_size,
    std::function<void(const ScanFileComplete&)> file_complete_callback)
{
    if (!pimpl_->isUnixSocket()) {
        return std::nullopt;
    }
    
    auto init_data = Protocol().serializeScanDirectoryInit(init);
    if (!sendRequest(MessageType::SCAN_DIRECTORY_INIT, init_data)) {
        return std::nullopt;
    }
    
    auto ack = receiveResponse(MessageType::STATUS_RESPONSE);
    if (!ack) {
        return std::nullopt;
    }
        
    PipelineState state(files.size(), init.max_threads);
    Protocol protocol;
    
    std::thread sender_thread([&]() {
        size_t batch_index = 0;

        for (size_t start_idx = 0; start_idx < files.size(); start_idx += batch_size) {
            {
                std::unique_lock<std::mutex> lock(state.queue_mutex);
                state.sender_cv.wait(lock, [&] {
                    return state.in_flight_batches.size() < state.MAX_IN_FLIGHT || 
                           state.error_occurred.load();
                });
                
                if (state.error_occurred.load()) {
                    return;
                }
            }
            
            size_t end_idx = std::min(start_idx + batch_size, files.size());
            
            std::vector<int> fds;
            std::vector<std::string> paths;
            
            for (size_t i = start_idx; i < end_idx; ++i) {
                int fd = open(files[i].c_str(), O_RDONLY);
                if (fd >= 0) {
                    fds.push_back(fd);
                    paths.push_back(files[i].string());
                }
            }
            
            if (fds.empty()) {
                continue;
            }
            
            BatchContext ctx;
            ctx.batch_index = batch_index;
            ctx.file_paths = paths;
            ctx.expected_responses = fds.size();
            
            ScanBatchFds batch;
            batch.batch_index = batch_index;
            batch.file_paths = paths;
            
            auto batch_data = protocol.serializeScanBatchFds(batch);
            
            if (!pimpl_->sendRequestWithFds(MessageType::SCAN_BATCH_FDS, batch_data, fds)) {
                for (int fd : fds) {
                    close(fd);
                }
                state.error_occurred.store(true);
                state.receiver_cv.notify_one();
                return;
            }
            
            for (int fd : fds) {
                close(fd);
            }
            
            {
                std::lock_guard<std::mutex> lock(state.queue_mutex);
                state.in_flight_batches.push(std::move(ctx));
            }
            
            state.files_sent += fds.size();
            batch_index++;
        }
        
        state.sending_complete.store(true);
        state.receiver_cv.notify_one();
    });
    
    std::thread receiver_thread([&]() {
        while (true) {
            if (state.error_occurred.load()) {
                break;
            }
            
            if (state.sending_complete.load() && state.files_received >= state.files_sent.load()) {
                break;
            }
            
            auto response = pimpl_->receiveAnyResponse();
            if (!response) {
                if (state.sending_complete.load()) {
                    break;
                }
                state.error_occurred.store(true);
                state.sender_cv.notify_one();
                break;
            }
            
            auto [type, data] = *response;
            
            if (type == MessageType::ERROR_RESPONSE) {
                state.error_occurred.store(true);
                state.sender_cv.notify_one();
                break;
            }
            
            if (type == MessageType::SCAN_FILE_COMPLETE) {
                ScanFileComplete file_result;
                if (protocol.parseScanFileComplete(data, file_result)) {
                    state.files_received++;
                    
                    if (file_complete_callback) {
                        file_complete_callback(file_result);
                    }
                    
                    {
                        std::lock_guard<std::mutex> lock(state.queue_mutex);
                        if (!state.in_flight_batches.empty()) {
                            auto& front = state.in_flight_batches.front();
                            front.received_responses++;
                            
                            if (front.received_responses >= front.expected_responses) {
                                state.in_flight_batches.pop();
                                state.sender_cv.notify_one();
                            }
                        }
                    }
                }
            }
        }
    });
    
    sender_thread.join();
    receiver_thread.join();
    
    if (state.error_occurred.load()) {
        return std::nullopt;
    }
    
    auto complete_data = protocol.serializeErrorResponse("");
    if (!sendRequest(MessageType::SCAN_DIRECTORY_COMPLETE, complete_data)) {
        return std::nullopt;
    }
    
    auto response_data = receiveResponse(MessageType::SCAN_DIRECTORY_RESPONSE);
    if (!response_data) {
        return std::nullopt;
    }
    
    std::string json_str(response_data->begin(), response_data->end());
    auto json = nlohmann::json::parse(json_str);
    
    ScanDirectoryResponse response;
    response.total_files = json.value("total_files", 0);
    response.clean_files = json.value("clean_files", 0);
    response.malicious_files = json.value("malicious_files", 0);
    response.unsupported_files = json.value("unsupported_files", 0);
    response.error_files = json.value("error_files", 0);
    response.total_time_ms = json.value("total_time_ms", 0);
    
    if (json.contains("results") && json["results"].is_array()) {
        for (const auto& result_json : json["results"]) {
            common::ScanMetadata result;
            result.file_path = result_json.value("file_path", "");
            
            std::string result_str = result_json.value("result", "ERROR");
            if (result_str == "CLEAN") result.result = common::ScanResult::CLEAN;
            else if (result_str == "MALICIOUS") result.result = common::ScanResult::MALICIOUS;
            else if (result_str == "UNSUPPORTED") result.result = common::ScanResult::UNSUPPORTED;
            else result.result = common::ScanResult::ERROR;
            
            result.confidence = result_json.value("confidence", 0.0f);
            result.file_type = result_json.value("file_type", "");
            result.file_size = result_json.value("file_size", 0);
            
            if (result_json.contains("error")) {
                result.error_message = result_json["error"];
            }
            
            if (result_json.contains("file_hashes") && result_json["file_hashes"].is_object()) {
                std::map<std::string, std::string> hashes;
                for (auto it = result_json["file_hashes"].begin(); it != result_json["file_hashes"].end(); ++it) {
                    hashes[it.key()] = it.value();
                }
                result.file_hashes = hashes;
            }
            
            response.results.push_back(result);
        }
    }
    
    return response;
}

std::optional<network::AnalysisResult> DaemonClient::analyze(const std::string& file_path, 
                                                               const std::string& language) {
    if (!pimpl_->isUnixSocket()) {
        return std::nullopt;
    }
    
    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) {
        return std::nullopt;
    }
    
    nlohmann::json request_json;
    request_json["file_path"] = file_path;
    request_json["language"] = language;
    
    std::string json_str = request_json.dump();
    std::vector<uint8_t> request_data(json_str.begin(), json_str.end());
    
    if (!sendRequestWithFd(MessageType::ANALYZE_REQUEST, request_data, fd)) {
        close(fd);
        return std::nullopt;
    }
    
    close(fd);
    
    auto response_data = receiveResponse(MessageType::ANALYZE_RESPONSE);
    if (!response_data) {
        return std::nullopt;
    }
    
    std::string json_str2(response_data->begin(), response_data->end());
    auto json = nlohmann::json::parse(json_str2);
    
    network::AnalysisResult result;
    result.verdict = json.value("verdict", "error");
    result.confidence = json.value("confidence", 0.0f);
    result.file_type = json.value("file_type", "");
    result.analysis_timestamp = json.value("analysis_timestamp", "");
    result.sdk_version = json.value("sdk_version", "");
    
    if (json.contains("tags") && json["tags"].is_array()) {
        for (const auto& tag : json["tags"]) {
            result.tags.push_back(tag);
        }
    }
    
    if (json.contains("signature") && !json["signature"].is_null()) {
        result.signature = json["signature"];
    }
    
    if (json.contains("static_attributes") && json["static_attributes"].is_object()) {
        result.static_attributes_json = json["static_attributes"].dump();
    }
    
    if (json.contains("file_hashes") && json["file_hashes"].is_object()) {
        for (auto it = json["file_hashes"].begin(); it != json["file_hashes"].end(); ++it) {
            result.file_hashes[it.key()] = it.value();
        }
    }
    
    result.natural_language_report = json.value("natural_language_report", "");
    
    if (json.contains("intelligence") && json["intelligence"].is_object()) {
        auto intel = json["intelligence"];
        
        if (intel.contains("similar_samples") && intel["similar_samples"].is_array()) {
            for (const auto& sample : intel["similar_samples"]) {
                network::SimilarSample similar;
                
                if (sample.contains("file_hashes") && sample["file_hashes"].is_object()) {
                    for (auto it = sample["file_hashes"].begin(); it != sample["file_hashes"].end(); ++it) {
                        similar.file_hashes[it.key()] = it.value();
                    }
                }
                
                similar.similarity_score = sample.value("similarity_score", 0.0f);
                
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
                
                result.intelligence.similar_samples.push_back(similar);
            }
        }
        
        if (intel.contains("statistics")) {
            auto stats = intel["statistics"];
            
            result.intelligence.statistics.processed_samples = stats.value("processed_samples", 0);
            
            auto parse_label_stats = [](const nlohmann::json& label_json) -> network::LabelStatistics {
                network::LabelStatistics label_stats;
                label_stats.count = label_json.value("count", 0);
                if (label_json.contains("max_similarity") && !label_json["max_similarity"].is_null()) {
                    label_stats.max_similarity = label_json["max_similarity"];
                }
                if (label_json.contains("avg_similarity") && !label_json["avg_similarity"].is_null()) {
                    label_stats.avg_similarity = label_json["avg_similarity"];
                }
                return label_stats;
            };
            
            if (stats.contains("by_label")) {
                auto by_label = stats["by_label"];
                
                if (by_label.contains("malicious")) {
                    result.intelligence.statistics.malicious = parse_label_stats(by_label["malicious"]);
                }
                
                if (by_label.contains("suspicious")) {
                    result.intelligence.statistics.suspicious = parse_label_stats(by_label["suspicious"]);
                }
                
                if (by_label.contains("clean")) {
                    result.intelligence.statistics.clean = parse_label_stats(by_label["clean"]);
                }
                
                if (by_label.contains("unknown")) {
                    result.intelligence.statistics.unknown = parse_label_stats(by_label["unknown"]);
                }
            }
            
            if (stats.contains("by_signature") && stats["by_signature"].is_object()) {
                for (auto it = stats["by_signature"].begin(); it != stats["by_signature"].end(); ++it) {
                    network::SignatureStatistics sig_stat;
                    sig_stat.count = it.value().value("count", 0);
                    sig_stat.max_similarity = it.value().value("max_similarity", 0.0f);
                    sig_stat.avg_similarity = it.value().value("avg_similarity", 0.0f);
                    result.intelligence.statistics.by_signature[it.key()] = sig_stat;
                }
            }
        }
    }
    
    return result;
}

std::optional<StatusResponse> DaemonClient::getStatus(bool include_stats) {
    nlohmann::json request_json;
    request_json["include_stats"] = include_stats;
    
    std::string json_str = request_json.dump();
    std::vector<uint8_t> request_data(json_str.begin(), json_str.end());
    
    if (!sendRequest(MessageType::STATUS_REQUEST, request_data)) {
        return std::nullopt;
    }
    
    auto response_data = receiveResponse(MessageType::STATUS_RESPONSE);
    if (!response_data) {
        return std::nullopt;
    }
    
    std::string json_str2(response_data->begin(), response_data->end());
    auto json = nlohmann::json::parse(json_str2);
    
    StatusResponse response;
    response.healthy = json.value("healthy", false);
    response.uptime_seconds = json.value("uptime_seconds", 0);
    response.scans_processed = json.value("scans_processed", 0);
    response.active_connections = json.value("active_connections", 0);
    response.sdk_version = json.value("sdk_version", "");
    
    return response;
}

std::optional<UpdateModelsResponse> DaemonClient::updateModels(const std::vector<std::string>& model_types,
                                                                bool force_update,
                                                                bool check_only) {
    UpdateModelsRequest request;
    request.model_types = model_types;
    request.force_update = force_update;
    request.check_only = check_only;
    
    Protocol protocol;
    auto request_data = protocol.serializeUpdateModelsRequest(request);
    
    if (!sendRequest(MessageType::UPDATE_MODELS_REQUEST, request_data)) {
        return std::nullopt;
    }
    
    auto response_data = receiveResponse(MessageType::UPDATE_MODELS_RESPONSE);
    if (!response_data) {
        return std::nullopt;
    }
    
    std::string json_str(response_data->begin(), response_data->end());
    auto json = nlohmann::json::parse(json_str);
    
    UpdateModelsResponse response;
    response.total_models = json.value("total_models", 0);
    response.updated_models = json.value("updated_models", 0);
    response.failed_models = json.value("failed_models", 0);
    response.total_time_ms = json.value("total_time_ms", 0);
    
    if (json.contains("updated_types") && json["updated_types"].is_array()) {
        for (const auto& type : json["updated_types"]) {
            response.updated_types.push_back(type);
        }
    }
    
    if (json.contains("failed_types") && json["failed_types"].is_array()) {
        for (const auto& type : json["failed_types"]) {
            response.failed_types.push_back(type);
        }
    }
    
    if (json.contains("version_updates") && json["version_updates"].is_array()) {
        for (const auto& ver_json : json["version_updates"]) {
            ModelVersionUpdate ver_update;
            ver_update.model_type = ver_json.value("model_type", "");
            ver_update.old_timestamp = ver_json.value("old_timestamp", 0);
            ver_update.new_timestamp = ver_json.value("new_timestamp", 0);
            ver_update.was_updated = ver_json.value("was_updated", false);
            ver_update.had_previous_version = ver_json.value("had_previous_version", false);
            response.version_updates.push_back(ver_update);
        }
    }
    
    return response;
}

std::optional<ConfigGetResponse> DaemonClient::getConfig(const std::vector<std::string>& keys) {
    ConfigGetRequest request;
    request.keys = keys;
    request.include_metadata = false;
    
    Protocol protocol;
    auto request_data = protocol.serializeConfigGetRequest(request);
    
    if (!sendRequest(MessageType::CONFIG_GET_REQUEST, request_data)) {
        return std::nullopt;
    }
    
    auto response_data = receiveResponse(MessageType::CONFIG_GET_RESPONSE);
    if (!response_data) {
        return std::nullopt;
    }
    
    std::string json_str(response_data->begin(), response_data->end());
    auto json = nlohmann::json::parse(json_str);
    
    ConfigGetResponse response;
    if (json.contains("values") && json["values"].is_object()) {
        for (auto it = json["values"].begin(); it != json["values"].end(); ++it) {
            response.values[it.key()] = it.value();
        }
    }
    
    return response;
}

std::optional<DeleteReportResponse> DaemonClient::deleteReport(const std::string& report_id) {
    DeleteReportRequest request;
    request.report_id = report_id;
    
    Protocol protocol;
    auto request_data = protocol.serializeDeleteReportRequest(request);
    
    if (!sendRequest(MessageType::DELETE_REPORT_REQUEST, request_data)) {
        return std::nullopt;
    }
    
    auto response_data = receiveResponse(MessageType::DELETE_REPORT_RESPONSE);
    if (!response_data) {
        return std::nullopt;
    }
    
    std::string json_str(response_data->begin(), response_data->end());
    auto json = nlohmann::json::parse(json_str);
    
    DeleteReportResponse response;
    response.success = json.value("success", false);
    response.error_message = json.value("error_message", "");
    
    return response;
}

std::optional<ListReportsResponse> DaemonClient::listReports(const std::string& filter_verdict,
                                                              const std::string& filter_date,
                                                              const std::string& filter_file_type,
                                                              const std::string& sort_by,
                                                              size_t limit) {
    ListReportsRequest request;
    request.filter_verdict = filter_verdict;
    request.filter_date = filter_date;
    request.filter_file_type = filter_file_type;
    request.sort_by = sort_by;
    request.limit = limit;
    
    Protocol protocol;
    auto request_data = protocol.serializeListReportsRequest(request);
    
    if (!sendRequest(MessageType::LIST_REPORTS_REQUEST, request_data)) {
        return std::nullopt;
    }
    
    auto response_data = receiveResponse(MessageType::LIST_REPORTS_RESPONSE);
    if (!response_data) {
        return std::nullopt;
    }
    
    std::string json_str(response_data->begin(), response_data->end());
    auto json = nlohmann::json::parse(json_str);
    
    ListReportsResponse response;
    
    if (json.contains("reports") && json["reports"].is_array()) {
        for (const auto& report_json : json["reports"]) {
            report::ReportMetadata metadata;
            metadata.report_id = report_json.value("report_id", "");
            metadata.file_path = report_json.value("file_path", "");
            metadata.verdict = report_json.value("verdict", "");
            metadata.confidence = report_json.value("confidence", 0.0f);
            metadata.file_type = report_json.value("file_type", "");
            metadata.file_size = report_json.value("file_size", 0);
            
            if (report_json.contains("saved_at")) {
                std::string saved_at_str = report_json["saved_at"];
                std::tm tm = {};
                std::istringstream ss(saved_at_str);
                ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
                if (!ss.fail()) {
                    metadata.saved_at = std::chrono::system_clock::from_time_t(timegm(&tm));
                }
            }
            
            if (report_json.contains("analyzed_at")) {
                std::string analyzed_at_str = report_json["analyzed_at"];
                std::tm tm = {};
                std::istringstream ss(analyzed_at_str);
                ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
                if (!ss.fail()) {
                    metadata.analyzed_at = std::chrono::system_clock::from_time_t(timegm(&tm));
                }
            }
            
            response.reports.push_back(metadata);
        }
    }
    
    return response;
}

std::optional<network::AnalysisResult> DaemonClient::showReport(const std::string& report_id) {
    ShowReportRequest request;
    request.report_id = report_id;
    
    Protocol protocol;
    auto request_data = protocol.serializeShowReportRequest(request);
    
    if (!sendRequest(MessageType::SHOW_REPORT_REQUEST, request_data)) {
        return std::nullopt;
    }
    
    auto response_data = receiveResponse(MessageType::SHOW_REPORT_RESPONSE);
    if (!response_data) {
        return std::nullopt;
    }
    
    std::string json_str(response_data->begin(), response_data->end());
    auto json = nlohmann::json::parse(json_str);
    
    if (!json.value("success", false)) {
        return std::nullopt;
    }
    
    if (!json.contains("report") || json["report"].is_null()) {
        return std::nullopt;
    }
    
    auto report_json = json["report"];
    
    network::AnalysisResult result;
    result.file_type = report_json.value("file_type", "");
    result.analysis_timestamp = report_json.value("analysis_timestamp", "");
    result.sdk_version = report_json.value("sdk_version", "");
    
    if (report_json.contains("detection") && report_json["detection"].is_object()) {
        auto detection = report_json["detection"];
        result.verdict = detection.value("verdict", "error");
        result.confidence = detection.value("confidence", 0.0f);
        
        if (detection.contains("tags") && detection["tags"].is_array()) {
            for (const auto& tag : detection["tags"]) {
                if (tag.is_string()) {
                    result.tags.push_back(tag);
                }
            }
        }
        
        if (detection.contains("signature") && !detection["signature"].is_null()) {
            result.signature = detection["signature"];
        }
        
        if (detection.contains("static_attributes") && !detection["static_attributes"].is_null()) {
            result.static_attributes_json = detection["static_attributes"].dump();
        }
    }
    
    if (report_json.contains("file_hashes") && report_json["file_hashes"].is_object()) {
        for (auto it = report_json["file_hashes"].begin(); it != report_json["file_hashes"].end(); ++it) {
            result.file_hashes[it.key()] = it.value();
        }
    }
    
    result.natural_language_report = report_json.value("natural_language_report", "");
    
    if (report_json.contains("intelligence")) {
        auto intel = report_json["intelligence"];
        
        if (intel.contains("similar_samples") && intel["similar_samples"].is_array()) {
            for (const auto& sample_json : intel["similar_samples"]) {
                network::SimilarSample sample;
                
                if (sample_json.contains("file_hashes") && sample_json["file_hashes"].is_object()) {
                    for (auto it = sample_json["file_hashes"].begin(); it != sample_json["file_hashes"].end(); ++it) {
                        sample.file_hashes[it.key()] = it.value();
                    }
                }
                
                sample.similarity_score = sample_json.value("similarity_score", 0.0f);
                
                if (sample_json.contains("tags") && sample_json["tags"].is_array()) {
                    for (const auto& tag : sample_json["tags"]) {
                        sample.tags.push_back(tag);
                    }
                }
                
                if (sample_json.contains("signature") && !sample_json["signature"].is_null()) {
                    sample.signature = sample_json["signature"];
                }
                
                if (sample_json.contains("static_attributes") && !sample_json["static_attributes"].is_null()) {
                    sample.static_attributes_json = sample_json["static_attributes"].dump();
                }
                
                result.intelligence.similar_samples.push_back(sample);
            }
        }
        
        if (intel.contains("statistics")) {
            auto stats = intel["statistics"];
            result.intelligence.statistics.processed_samples = stats.value("processed_samples", 0);
            
            auto parse_label_stats = [](const nlohmann::json& label_json) -> network::LabelStatistics {
                network::LabelStatistics stats;
                stats.count = label_json.value("count", 0);
                if (label_json.contains("max_similarity") && !label_json["max_similarity"].is_null()) {
                    stats.max_similarity = label_json["max_similarity"];
                }
                if (label_json.contains("avg_similarity") && !label_json["avg_similarity"].is_null()) {
                    stats.avg_similarity = label_json["avg_similarity"];
                }
                return stats;
            };
            
            if (stats.contains("by_label")) {
                auto by_label = stats["by_label"];
                if (by_label.contains("malicious")) {
                    result.intelligence.statistics.malicious = parse_label_stats(by_label["malicious"]);
                }
                if (by_label.contains("suspicious")) {
                    result.intelligence.statistics.suspicious = parse_label_stats(by_label["suspicious"]);
                }
                if (by_label.contains("clean")) {
                    result.intelligence.statistics.clean = parse_label_stats(by_label["clean"]);
                }
                if (by_label.contains("unknown")) {
                    result.intelligence.statistics.unknown = parse_label_stats(by_label["unknown"]);
                }
            }
            
            if (stats.contains("by_signature") && stats["by_signature"].is_object()) {
                for (auto it = stats["by_signature"].begin(); it != stats["by_signature"].end(); ++it) {
                    network::SignatureStatistics sig_stat;
                    sig_stat.count = it.value().value("count", 0);
                    sig_stat.max_similarity = it.value().value("max_similarity", 0.0f);
                    sig_stat.avg_similarity = it.value().value("avg_similarity", 0.0f);
                    result.intelligence.statistics.by_signature[it.key()] = sig_stat;
                }
            }
        }
    }
    
    return result;
}

bool DaemonClient::ping(const std::string& payload) {
    nlohmann::json request_json;
    request_json["payload"] = payload;
    
    std::string json_str = request_json.dump();
    std::vector<uint8_t> request_data(json_str.begin(), json_str.end());
    
    if (!sendRequest(MessageType::PING_REQUEST, request_data)) {
        return false;
    }
    
    auto response_data = receiveResponse(MessageType::PING_RESPONSE);
    return response_data.has_value();
}

bool DaemonClient::shutdown(bool force) {
    nlohmann::json request_json;
    request_json["force"] = force;
    
    std::string json_str = request_json.dump();
    std::vector<uint8_t> request_data(json_str.begin(), json_str.end());
    
    return sendRequest(MessageType::SHUTDOWN_REQUEST, request_data);
}

bool DaemonClient::isDaemonRunning() {
    std::string socket_path = common::Config::instance().global().daemon.socket_path;
    
    std::error_code ec;
    if (!std::filesystem::exists(socket_path, ec) || ec) {
        return false;
    }
    
    int test_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (test_fd < 0) {
        return false;
    }
    
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
    
    bool is_running = (::connect(test_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    
    ::close(test_fd);
    
    return is_running;
}

std::string DaemonClient::getDefaultSocketPath() {
    return common::PathManager::instance().getSocketPath();
}

bool DaemonClient::sendRequest(MessageType type, const std::vector<uint8_t>& data) {
    return pimpl_->sendRequest(type, data);
}

bool DaemonClient::sendRequestWithFd(MessageType type, const std::vector<uint8_t>& data, int fd) {
    return pimpl_->sendRequestWithFd(type, data, fd);
}

bool DaemonClient::sendRequestWithFds(MessageType type, const std::vector<uint8_t>& data, const std::vector<int>& fds) {
    return pimpl_->sendRequestWithFds(type, data, fds);
}

std::optional<std::vector<uint8_t>> DaemonClient::receiveResponse(MessageType expected_type) {
    return pimpl_->receiveResponse(expected_type);
}

std::optional<std::pair<MessageType, std::vector<uint8_t>>> DaemonClient::receiveAnyResponse() {
    return pimpl_->receiveAnyResponse();
}

}}