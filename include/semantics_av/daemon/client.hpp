#pragma once

#include "../common/types.hpp"
#include "../network/client.hpp"
#include "../report/storage.hpp"
#include "protocol.hpp"
#include <string>
#include <memory>
#include <optional>
#include <functional>

namespace semantics_av {
namespace daemon {

class DaemonClient {
public:
    DaemonClient();
    ~DaemonClient();
    
    bool connect();
    void disconnect();
    bool isConnected() const;
    bool isUnixSocket() const;
    
    std::optional<ScanResponse> scan(const std::string& file_path, bool include_hashes = false);
    std::optional<ScanDirectoryResponse> scanDirectoryWithFds(
        const ScanDirectoryInit& init,
        const std::vector<std::filesystem::path>& files,
        size_t batch_size,
        std::function<void(const ScanFileComplete&)> file_complete_callback = nullptr);
    std::optional<network::AnalysisResult> analyze(const std::string& file_path, 
                                                     const std::string& language = "");
    std::optional<StatusResponse> getStatus(bool include_stats = false);
    std::optional<UpdateModelsResponse> updateModels(const std::vector<std::string>& model_types,
                                                      bool force_update = false,
                                                      bool check_only = false);
    std::optional<ConfigGetResponse> getConfig(const std::vector<std::string>& keys = {});
    std::optional<DeleteReportResponse> deleteReport(const std::string& report_id);
    std::optional<ListReportsResponse> listReports(const std::string& filter_verdict = "",
                                                    const std::string& filter_date = "",
                                                    const std::string& filter_file_type = "",
                                                    const std::string& sort_by = "time",
                                                    size_t limit = 20);
    std::optional<network::AnalysisResult> showReport(const std::string& report_id);
    bool ping(const std::string& payload = "");
    bool shutdown(bool force = false);
    
    static bool isDaemonRunning();
    static std::string getDefaultSocketPath();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
    
    bool connectUnixSocket(const std::string& socket_path);
    bool connectHttpApi(const std::string& host, uint16_t port);
    
    bool sendRequest(MessageType type, const std::vector<uint8_t>& data);
    bool sendRequestWithFd(MessageType type, const std::vector<uint8_t>& data, int fd);
    bool sendRequestWithFds(MessageType type, const std::vector<uint8_t>& data, const std::vector<int>& fds);
    std::optional<std::vector<uint8_t>> receiveResponse(MessageType expected_type);
    std::optional<std::pair<MessageType, std::vector<uint8_t>>> receiveAnyResponse();
};

}}