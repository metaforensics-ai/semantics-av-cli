#pragma once

#include "../common/config.hpp"
#include "../common/types.hpp"
#include "../core/engine.hpp"
#include "reloadable_config.hpp"
#include "handler.hpp"
#include "http_server.hpp"
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>

namespace semantics_av {
namespace daemon {

class DaemonServer {
public:
    explicit DaemonServer(const common::DaemonConfig& config);
    ~DaemonServer();
    
    bool bindSockets();
    bool createPidFileBeforePrivilegeDrop();
    bool startServiceWithoutPidFile();
    bool startService();
    void stopService();
    void run();
    
    bool isRunning() const { return running_; }
    size_t getActiveConnections() const { return active_connections_.load(); }
    
    static bool isDaemonRunning();
    static int getDaemonPid();
    static bool sendSignalToDaemon(int signal);

private:
    common::DaemonConfig config_;
    std::unique_ptr<core::SemanticsAVEngine> engine_;
    std::unique_ptr<RequestHandler> handler_;
    std::unique_ptr<HttpApiServer> http_server_;
    
    std::atomic<bool> running_{false};
    std::atomic<bool> shutdown_requested_{false};
    std::atomic<size_t> active_connections_{0};
    bool pid_file_created_{false};
    
    std::atomic<bool> reload_requested_{false};
    std::mutex reload_mutex_;
    std::atomic<bool> reload_in_progress_{false};
    
    class UnixSocketServer;
    
    std::unique_ptr<UnixSocketServer> unix_server_;
    
    std::vector<std::thread> worker_threads_;
    std::thread auto_update_thread_;
    std::thread reload_thread_;
    
    std::deque<std::shared_ptr<Connection>> connection_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    static std::atomic<DaemonServer*> instance_;
    
    bool createPidFile();
    void removePidFile();
    bool checkExistingDaemon();
    void ensureModelsAvailable();
    
    void setupSignalHandlers();
    static void signalHandlerStatic(int signal);
    void signalHandler(int signal);
    void reloadConfiguration();
    ReloadableConfig captureReloadableConfig() const;
    void workerThreadMain();
    void autoUpdateThreadMain();
    void reloadThreadMain();
    void acceptConnections();
    
    static bool isRunningInContainer();
};

}}