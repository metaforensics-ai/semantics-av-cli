#include "semantics_av/daemon/server.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/security.hpp"
#include "semantics_av/common/config.hpp"
#include "semantics_av/common/paths.hpp"
#include "semantics_av/common/diagnostics.hpp"
#include "semantics_av/network/downloader.hpp"
#include "semantics_av/update/updater.hpp"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <fstream>
#include <thread>
#include <cstring>

namespace semantics_av {
namespace daemon {

class UnixSocketConnection : public Connection {
public:
    UnixSocketConnection(int socket_fd, int read_timeout, int write_timeout) 
        : socket_fd_(socket_fd) {
        struct timeval tv_read;
        tv_read.tv_sec = read_timeout;
        tv_read.tv_usec = 0;
        setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv_read, sizeof(tv_read));
        
        struct timeval tv_write;
        tv_write.tv_sec = write_timeout;
        tv_write.tv_usec = 0;
        setsockopt(socket_fd_, SOL_SOCKET, SO_SNDTIMEO, &tv_write, sizeof(tv_write));
    }
    
    ~UnixSocketConnection() override {
        close();
    }
    
    bool readMessage(MessageHeader& header, std::vector<uint8_t>& data) override {
        if (socket_fd_ < 0) return false;
        
        ssize_t result = recv(socket_fd_, &header, sizeof(header), MSG_WAITALL);
        if (result != sizeof(header)) {
            return false;
        }
        
        if (header.magic != 0x53415643) {
            return false;
        }
        
        if (header.length > 0) {
            data.resize(header.length);
            result = recv(socket_fd_, data.data(), header.length, MSG_WAITALL);
            if (result != static_cast<ssize_t>(header.length)) {
                return false;
            }
        }
        
        return true;
    }
    
    bool readMessageWithFd(MessageHeader& header, std::vector<uint8_t>& data, int& fd) override {
        if (socket_fd_ < 0) return false;
        
        fd = -1;
        
        struct msghdr msg;
        std::memset(&msg, 0, sizeof(msg));
        
        struct iovec iov[1];
        char ctrl_buf[CMSG_SPACE(sizeof(int))];
        char buffer[65536];
        
        iov[0].iov_base = buffer;
        iov[0].iov_len = sizeof(buffer);
        
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl_buf;
        msg.msg_controllen = sizeof(ctrl_buf);
        
        ssize_t result = recvmsg(socket_fd_, &msg, 0);
        if (result < 0) {
            return false;
        }
        
        if (result < static_cast<ssize_t>(sizeof(MessageHeader))) {
            return false;
        }
        
        std::memcpy(&header, buffer, sizeof(MessageHeader));
        
        if (header.magic != 0x53415643) {
            return false;
        }
        
        if (header.length > 0) {
            size_t data_offset = sizeof(MessageHeader);
            if (result >= static_cast<ssize_t>(data_offset + header.length)) {
                data.resize(header.length);
                std::memcpy(data.data(), buffer + data_offset, header.length);
            } else {
                return false;
            }
        }
        
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            fd = *reinterpret_cast<int*>(CMSG_DATA(cmsg));
        }
        
        return true;
    }
    
    bool readMessageWithFds(MessageHeader& header, std::vector<uint8_t>& data, std::vector<int>& fds) override {
        if (socket_fd_ < 0) return false;
        
        fds.clear();
        
        struct msghdr msg;
        std::memset(&msg, 0, sizeof(msg));
        
        struct iovec iov[1];
        char ctrl_buf[CMSG_SPACE(sizeof(int) * 256)];
        char buffer[65536];
        
        iov[0].iov_base = buffer;
        iov[0].iov_len = sizeof(buffer);
        
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl_buf;
        msg.msg_controllen = sizeof(ctrl_buf);
        
        ssize_t result = recvmsg(socket_fd_, &msg, 0);
        if (result < 0) {
            return false;
        }
        
        if (result < static_cast<ssize_t>(sizeof(MessageHeader))) {
            return false;
        }
        
        if ((msg.msg_flags & MSG_CTRUNC) != 0) {
            struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
            if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                size_t fd_count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                int* fd_ptr = reinterpret_cast<int*>(CMSG_DATA(cmsg));
                for (size_t i = 0; i < fd_count; ++i) {
                    ::close(fd_ptr[i]);
                }
            }
            return false;
        }
        
        std::memcpy(&header, buffer, sizeof(MessageHeader));
        
        if (header.magic != 0x53415643) {
            return false;
        }
        
        if (header.length > 0) {
            size_t data_offset = sizeof(MessageHeader);
            if (result >= static_cast<ssize_t>(data_offset + header.length)) {
                data.resize(header.length);
                std::memcpy(data.data(), buffer + data_offset, header.length);
            } else {
                return false;
            }
        }
        
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            size_t fd_count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            int* fd_ptr = reinterpret_cast<int*>(CMSG_DATA(cmsg));
            fds.assign(fd_ptr, fd_ptr + fd_count);
        }
        
        return true;
    }
    
    bool writeMessage(MessageType type, uint32_t sequence, 
                      const std::vector<uint8_t>& data) override {
        if (socket_fd_ < 0) return false;
        
        MessageHeader header;
        header.type = type;
        header.length = data.size();
        header.sequence = sequence;
        
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
    
    bool writeMessageWithFd(MessageType type, uint32_t sequence,
                           const std::vector<uint8_t>& data, int fd) override {
        if (socket_fd_ < 0) return false;
        
        MessageHeader header;
        header.type = type;
        header.length = data.size();
        header.sequence = sequence;
        
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
    
    bool writeMessageWithFds(MessageType type, uint32_t sequence,
                            const std::vector<uint8_t>& data, const std::vector<int>& fds) override {
        if (socket_fd_ < 0 || fds.empty()) return false;
        
        MessageHeader header;
        header.type = type;
        header.length = data.size();
        header.sequence = sequence;
        
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
    
    void close() override {
        if (socket_fd_ >= 0) {
            ::close(socket_fd_);
            socket_fd_ = -1;
        }
    }
    
    bool isConnected() const override {
        return socket_fd_ >= 0;
    }
    
    std::string getRemoteAddress() const override {
        return "unix-socket";
    }
    
    uint16_t getRemotePort() const override {
        return 0;
    }

private:
    int socket_fd_;
};

class DaemonServer::UnixSocketServer {
public:
    UnixSocketServer(const std::string& socket_path, bool is_system_mode, 
                     const std::string& user, const std::string& group) 
        : socket_path_(socket_path), socket_fd_(-1), 
          is_system_mode_(is_system_mode), user_(user), group_(group) {}
    
    ~UnixSocketServer() {
        cleanup();
    }
    
    bool bindSocket() {
        auto& global_config = common::Config::instance().global();
        
        socket_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd_ < 0) {
            common::Logger::instance().error("[Socket] Unix socket creation failed | error={}", 
                                             strerror(errno));
            return false;
        }
        
        int buffer_size = static_cast<int>(global_config.daemon.socket_buffer_kb * 1024);
        setsockopt(socket_fd_, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
        setsockopt(socket_fd_, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
        
        unlink(socket_path_.c_str());
        
        std::filesystem::path socket_dir = std::filesystem::path(socket_path_).parent_path();
        std::error_code ec;
        if (!std::filesystem::create_directories(socket_dir, ec) && 
            !std::filesystem::exists(socket_dir, ec)) {
            common::Logger::instance().error("[Socket] Failed to create directory | path={} | error={}", 
                                             socket_dir.string(), ec.message());
            ::close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }
        
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);
        
        if (bind(socket_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            common::Logger::instance().error("[Socket] Bind failed | path={} | error={}", 
                                             socket_path_, strerror(errno));
            return false;
        }
        
        if (listen(socket_fd_, global_config.daemon.connection_backlog) < 0) {
            common::Logger::instance().error("[Socket] Listen failed | error={}", strerror(errno));
            return false;
        }
        
        mode_t socket_mode = is_system_mode_ ? 0666 : 0600;
        chmod(socket_path_.c_str(), socket_mode);
        
        if (is_system_mode_ && !user_.empty()) {
            struct passwd* pw = getpwnam(user_.c_str());
            struct group* gr = !group_.empty() ? getgrnam(group_.c_str()) : nullptr;
            if (pw) {
                gid_t gid = gr ? gr->gr_gid : pw->pw_gid;
                if (chown(socket_path_.c_str(), pw->pw_uid, gid) != 0) {
                    common::Logger::instance().warn("[Socket] Chown failed | error={}", strerror(errno));
                }
            }
        }
        
        common::Logger::instance().info("[Socket] Unix bound | path={} | mode={:o}", 
                                        socket_path_, socket_mode);
        return true;
    }
    
    std::shared_ptr<Connection> acceptConnection() {
        if (socket_fd_ < 0) return nullptr;
        
        int client_fd = accept(socket_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                common::Logger::instance().error("[Socket] Accept failed | error={}", strerror(errno));
            }
            return nullptr;
        }
        
        auto& global_config = common::Config::instance().global();
        
        int buffer_size = static_cast<int>(global_config.daemon.socket_buffer_kb * 1024);
        setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
        setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
        
        return std::make_shared<UnixSocketConnection>(
            client_fd, 
            global_config.daemon.read_timeout,
            global_config.daemon.read_timeout
        );
    }
    
    int getSocketFd() const { return socket_fd_; }
    
    void cleanup() {
        if (socket_fd_ >= 0) {
            ::close(socket_fd_);
            socket_fd_ = -1;
        }
        unlink(socket_path_.c_str());
    }

private:
    std::string socket_path_;
    int socket_fd_;
    bool is_system_mode_;
    std::string user_;
    std::string group_;
};

std::atomic<DaemonServer*> DaemonServer::instance_{nullptr};

DaemonServer::DaemonServer(const common::DaemonConfig& config) : config_(config) {
    engine_ = std::make_unique<core::SemanticsAVEngine>();
    auto& global_config = common::Config::instance().global();
    handler_ = std::make_unique<RequestHandler>(engine_.get(), global_config.api_key);
}

DaemonServer::~DaemonServer() {
    stopService();
}

bool DaemonServer::isRunningInContainer() {
    return std::getenv("SEMANTICS_AV_CONTAINER") != nullptr ||
           std::filesystem::exists("/.dockerenv") ||
           std::getenv("KUBERNETES_SERVICE_HOST") != nullptr;
}

bool DaemonServer::createPidFile() {
    std::string pid_file = common::Config::instance().getPidFilePath();
    std::filesystem::path pid_dir = std::filesystem::path(pid_file).parent_path();
    
    std::error_code ec;
    if (!std::filesystem::exists(pid_dir, ec)) {
        common::Logger::instance().error("[Daemon] PID directory missing | path={}", pid_dir.string());
        return false;
    }
    
    if (std::filesystem::exists(pid_file)) {
        std::ifstream file(pid_file);
        if (file) {
            pid_t old_pid;
            file >> old_pid;
            file.close();
            
            if (kill(old_pid, 0) == 0) {
                common::Logger::instance().error("[Daemon] Already running | pid={}", old_pid);
                return false;
            } else {
                common::Logger::instance().warn("[Daemon] Stale PID file removed | old_pid={}", old_pid);
                std::filesystem::remove(pid_file);
            }
        }
    }
    
    std::ofstream file(pid_file);
    if (!file) {
        common::Logger::instance().error("[Daemon] PID file creation failed | path={}", pid_file);
        return false;
    }
    
    file << getpid();
    file.close();
    
    chmod(pid_file.c_str(), 0644);
    
    common::Logger::instance().info("[Daemon] PID file created | path={} | pid={}", pid_file, getpid());
    return true;
}

void DaemonServer::removePidFile() {
    std::string pid_file = common::Config::instance().getPidFilePath();
    if (std::filesystem::exists(pid_file)) {
        std::filesystem::remove(pid_file);
        common::Logger::instance().debug("[Daemon] PID file removed | path={}", pid_file);
    }
}

bool DaemonServer::checkExistingDaemon() {
    std::string pid_file = common::Config::instance().getPidFilePath();
    
    if (!std::filesystem::exists(pid_file)) {
        return false;
    }
    
    std::ifstream file(pid_file);
    if (!file) {
        return false;
    }
    
    pid_t pid;
    file >> pid;
    file.close();
    
    if (kill(pid, 0) == 0) {
        return true;
    }
    
    std::filesystem::remove(pid_file);
    return false;
}

bool DaemonServer::isDaemonRunning() {
    std::string pid_file = common::Config::instance().getPidFilePath();
    
    if (!std::filesystem::exists(pid_file)) {
        return false;
    }
    
    std::ifstream file(pid_file);
    if (!file) {
        return false;
    }
    
    pid_t pid;
    file >> pid;
    file.close();
    
    return kill(pid, 0) == 0;
}

int DaemonServer::getDaemonPid() {
    std::string pid_file = common::Config::instance().getPidFilePath();
    
    if (!std::filesystem::exists(pid_file)) {
        return -1;
    }
    
    std::ifstream file(pid_file);
    if (!file) {
        return -1;
    }
    
    pid_t pid;
    file >> pid;
    file.close();
    
    if (kill(pid, 0) == 0) {
        return pid;
    }
    
    return -1;
}

bool DaemonServer::sendSignalToDaemon(int signal) {
    int pid = getDaemonPid();
    if (pid < 0) {
        return false;
    }
    
    return kill(pid, signal) == 0;
}

bool DaemonServer::bindSockets() {
    auto& path_manager = common::PathManager::instance();
    bool is_system_mode = path_manager.isSystemMode();
    
    unix_server_ = std::make_unique<UnixSocketServer>(
        config_.socket_path, is_system_mode, config_.user, config_.group);
    
    if (!unix_server_->bindSocket()) {
        return false;
    }
    
    return true;
}

bool DaemonServer::createPidFileBeforePrivilegeDrop() {
    if (isRunningInContainer()) {
        common::Logger::instance().debug("[Daemon] Container mode, skipping PID file");
        return true;
    }
    
    std::string pid_file = common::Config::instance().getPidFilePath();
    std::filesystem::path pid_dir = std::filesystem::path(pid_file).parent_path();
    
    std::error_code ec;
    if (!std::filesystem::exists(pid_dir, ec)) {
        common::Logger::instance().error("[Daemon] PID directory missing | path={}", pid_dir.string());
        return false;
    }
    
    if (std::filesystem::exists(pid_file)) {
        std::ifstream file(pid_file);
        if (file) {
            pid_t old_pid;
            file >> old_pid;
            file.close();
            
            if (kill(old_pid, 0) == 0) {
                common::Logger::instance().error("[Daemon] Already running | pid={}", old_pid);
                return false;
            } else {
                common::Logger::instance().warn("[Daemon] Stale PID file removed | old_pid={}", old_pid);
                std::filesystem::remove(pid_file);
            }
        }
    }
    
    std::ofstream file(pid_file);
    if (!file) {
        common::Logger::instance().error("[Daemon] PID file creation failed | path={}", pid_file);
        return false;
    }
    
    file << getpid();
    file.close();
    
    chmod(pid_file.c_str(), 0644);
    
    common::Logger::instance().info("[Daemon] PID file created | path={} | pid={}", pid_file, getpid());
    pid_file_created_ = true;
    return true;
}

void DaemonServer::ensureModelsAvailable() {
    auto& global_config = common::Config::instance().global();
    
    if (diagnostics::hasModelFiles(global_config.models_path)) {
        common::Logger::instance().info("[Daemon] Model files available");
        return;
    }
    
    common::Logger::instance().warn("[Daemon] No model files found, downloading...");
    
    try {
        network::ModelDownloader downloader(global_config.network_timeout);
        update::ModelUpdater updater(engine_.get(), &downloader);
        
        update::UpdateOptions options;
        options.model_types = constants::file_types::getSupported();
        options.force_update = false;
        options.check_only = false;
        options.quiet = false;
        
        auto summary = updater.updateModelsSync(options);
        
        if (summary.updated_models > 0) {
            common::Logger::instance().info("[Daemon] Initial models downloaded | updated={}", 
                                           summary.updated_models);
        } else {
            common::Logger::instance().warn("[Daemon] Model download failed | failed={}", 
                                           summary.failed_models);
        }
        
    } catch (const std::exception& e) {
        common::Logger::instance().error("[Daemon] Model download exception | error={}", e.what());
    }
}

bool DaemonServer::startServiceWithoutPidFile() {
    if (running_) {
        common::Logger::instance().warn("[Daemon] Already running");
        return true;
    }
    
    auto& global_config = common::Config::instance().global();
    auto& path_manager = common::PathManager::instance();
    
    common::Logger::instance().info("[Daemon] Starting | version=1.0.0 | mode={} | pid={}", 
                                    path_manager.isSystemMode() ? "system" : "user", getpid());
    
    if (!common::Logger::instance().isInitialized()) {
        common::Logger::instance().error("[Daemon] Logger not initialized");
        return false;
    }
    
    if (!engine_->initialize(global_config.base_path, global_config.api_key)) {
        common::Logger::instance().error("[Engine] Initialization failed | base_path={}", 
                                         global_config.base_path);
        return false;
    }
    
    common::Logger::instance().info("[Engine] Initialized | base_path={} | has_api_key={}", 
                                    global_config.base_path, !global_config.api_key.empty());
    
    ensureModelsAvailable();
    
    http_server_ = std::make_unique<HttpApiServer>(
        config_.http_host, config_.http_port, engine_.get(), global_config.api_key);
    
    if (!http_server_->start()) {
        common::Logger::instance().error("[HTTP] Failed to start server");
        return false;
    }
    
    setupSignalHandlers();
    
    running_ = true;
    shutdown_requested_ = false;
    
    size_t worker_count = global_config.daemon.worker_threads == 0 
        ? (std::thread::hardware_concurrency() > 0 ? std::thread::hardware_concurrency() : 4)
        : static_cast<size_t>(global_config.daemon.worker_threads);
    
    for (size_t i = 0; i < worker_count; ++i) {
        worker_threads_.emplace_back(&DaemonServer::workerThreadMain, this);
    }
    
    common::Logger::instance().info("[Workers] Started | count={} | cpu_cores={}", 
                                    worker_count, std::thread::hardware_concurrency());
    
    if (global_config.auto_update && global_config.update_interval_minutes > 0) {
        auto_update_thread_ = std::thread(&DaemonServer::autoUpdateThreadMain, this);
        common::Logger::instance().info("[AutoUpdate] Started | interval_minutes={}", 
                                       global_config.update_interval_minutes);
    } else {
        common::Logger::instance().info("[AutoUpdate] Disabled");
    }
    
    reload_thread_ = std::thread(&DaemonServer::reloadThreadMain, this);
    common::Logger::instance().info("[Reload] Thread started");
    
    return true;
}

bool DaemonServer::startService() {
    if (running_) {
        common::Logger::instance().warn("[Daemon] Already running");
        return true;
    }
    
    if (!isRunningInContainer() && checkExistingDaemon()) {
        common::Logger::instance().error("[Daemon] Another instance is running");
        return false;
    }
    
    if (!pid_file_created_ && !createPidFile()) {
        return false;
    }
    
    return startServiceWithoutPidFile();
}

void DaemonServer::stopService() {
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false)) {
        return;
    }
    
    common::Logger::instance().info("[Daemon] Shutting down | active_conns={} | queued_conns={}", 
                                    active_connections_.load(), connection_queue_.size());
    
    shutdown_requested_ = true;
    
    if (http_server_) {
        http_server_->stop();
        http_server_.reset();
    }
    
    auto shutdown_start = std::chrono::steady_clock::now();
    while (active_connections_.load() > 0) {
        auto elapsed = std::chrono::steady_clock::now() - shutdown_start;
        if (elapsed > std::chrono::seconds(30)) {
            common::Logger::instance().warn("[Daemon] Shutdown timeout | remaining_conns={}", 
                                           active_connections_.load());
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    queue_cv_.notify_all();
    
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads_.clear();
    
    if (auto_update_thread_.joinable()) {
        auto_update_thread_.join();
    }
    
    if (reload_thread_.joinable()) {
        reload_thread_.join();
    }
    
    common::Logger::instance().debug("[Workers] All stopped");
    
    if (unix_server_) {
        unix_server_->cleanup();
        unix_server_.reset();
    }
    
    if (engine_) {
        engine_->cleanup();
    }
    
    if (!isRunningInContainer()) {
        removePidFile();
    }
    
    common::Logger::instance().info("[Daemon] Stopped");
}

void DaemonServer::run() {
    if (!running_) {
        common::Logger::instance().error("[Daemon] Not started, cannot run accept loop");
        return;
    }
    
    acceptConnections();
}

void DaemonServer::setupSignalHandlers() {
    instance_.store(this);
    signal(SIGINT, &DaemonServer::signalHandlerStatic);
    signal(SIGTERM, &DaemonServer::signalHandlerStatic);
    signal(SIGHUP, &DaemonServer::signalHandlerStatic);
}

void DaemonServer::signalHandlerStatic(int signal) {
    auto* server = instance_.load();
    if (server) {
        server->signalHandler(signal);
    }
}

void DaemonServer::signalHandler(int signal) {
    if (signal == SIGHUP) {
        reload_requested_.store(true, std::memory_order_release);
    } else {
        if (shutdown_requested_.exchange(true)) {
            return;
        }
    }
}

ReloadableConfig DaemonServer::captureReloadableConfig() const {
    auto& config = common::Config::instance().global();
    
    ReloadableConfig reloadable;
    reloadable.api_key = config.api_key;
    reloadable.network_timeout = config.network_timeout;
    reloadable.log_level = config.log_level;
    reloadable.auto_update = config.auto_update;
    
    return reloadable;
}

void DaemonServer::reloadConfiguration() {
    if (reload_in_progress_.exchange(true)) {
        common::Logger::instance().warn("[Reload] Already in progress, skipping");
        return;
    }
    
    std::lock_guard<std::mutex> reload_lock(reload_mutex_);
    
    auto reload_start = std::chrono::steady_clock::now();
    common::Logger::instance().info("[Reload] Configuration reload initiated");
    
    try {
        auto old_config = captureReloadableConfig();
        
        auto& config = common::Config::instance();
        if (!config.load()) {
            common::Logger::instance().error("[Reload] Failed to load config | retaining previous configuration");
            reload_in_progress_.store(false);
            return;
        }
        
        auto new_config = captureReloadableConfig();
        
        std::vector<std::string> changes;
        if (old_config.api_key != new_config.api_key) changes.push_back("api_key");
        if (old_config.network_timeout != new_config.network_timeout) changes.push_back("network_timeout");
        if (old_config.log_level != new_config.log_level) changes.push_back("log_level");
        if (old_config.auto_update != new_config.auto_update) changes.push_back("auto_update");
        
        if (changes.empty()) {
            common::Logger::instance().info("[Reload] No changes detected");
            reload_in_progress_.store(false);
            return;
        }
        
        common::Logger::instance().info("[Reload] Changes detected | count={}", changes.size());
        for (const auto& change : changes) {
            common::Logger::instance().debug("[Reload]   - {}", change);
        }
        
        if (new_config.networkConfigChanged(old_config)) {
            common::Logger::instance().info("[Reload] Updating network services");
            
            if (handler_) {
                handler_->updateNetworkConfig(new_config);
            }
            
            if (http_server_) {
                http_server_->updateNetworkConfig(new_config);
            }
        }
        
        if (old_config.log_level != new_config.log_level) {
            common::Logger::instance().info("[Reload] Log level changed | {}→{}", 
                                           static_cast<int>(old_config.log_level),
                                           static_cast<int>(new_config.log_level));
            common::Logger::instance().setLevel(new_config.log_level);
        }
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - reload_start);
        
        common::Logger::instance().info("[Reload] Complete | duration_ms={}", duration.count());
        
    } catch (const std::exception& e) {
        common::Logger::instance().error("[Reload] Exception | error={} | retaining previous config", 
                                        e.what());
    }
    
    reload_in_progress_.store(false);
}

void DaemonServer::reloadThreadMain() {
    common::Logger::instance().debug("[Reload] Thread loop started");
    
    while (running_ && !shutdown_requested_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        if (reload_requested_.load(std::memory_order_acquire)) {
            reload_requested_.store(false, std::memory_order_release);
            
            common::Logger::instance().info("[Reload] Signal received, processing configuration reload");
            reloadConfiguration();
        }
    }
    
    common::Logger::instance().debug("[Reload] Thread stopped");
}

void DaemonServer::workerThreadMain() {
    common::Logger::instance().debug("[Worker] Thread started");
    
    while (running_) {
        std::shared_ptr<Connection> conn;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] {
                return !connection_queue_.empty() || !running_;
            });
            
            if (!running_) {
                break;
            }
            
            if (!connection_queue_.empty()) {
                conn = connection_queue_.front();
                connection_queue_.pop_front();
            }
        }
        
        if (conn) {
            active_connections_.fetch_add(1);
            
            try {
                handler_->handleConnection(conn);
            } catch (const std::exception& e) {
                common::Logger::instance().error("[Worker] Exception | error={}", e.what());
            }
            
            active_connections_.fetch_sub(1);
        }
    }
    
    common::Logger::instance().debug("[Worker] Thread stopped");
}

void DaemonServer::autoUpdateThreadMain() {
    auto& global_config = common::Config::instance().global();
    int interval_minutes = global_config.update_interval_minutes;
    
    common::Logger::instance().debug("[AutoUpdate] Thread started | interval_minutes={}", 
                                     interval_minutes);
    
    while (running_ && !shutdown_requested_) {
        for (int i = 0; i < interval_minutes * 60 && running_ && !shutdown_requested_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        if (!running_ || shutdown_requested_) {
            break;
        }
        
        common::Logger::instance().info("[AutoUpdate] Starting automatic model update");
        
        try {
            network::ModelDownloader downloader(global_config.network_timeout);
            update::ModelUpdater updater(engine_.get(), &downloader);
            
            update::UpdateOptions options;
            options.model_types = {"pe", "elf"};
            options.force_update = false;
            options.check_only = false;
            options.quiet = true;
            
            auto summary = updater.updateModelsSync(options);
            
            if (summary.updated_models > 0) {
                common::Logger::instance().info("[AutoUpdate] Complete | updated={} | failed={}", 
                                               summary.updated_models, summary.failed_models);
            } else {
                common::Logger::instance().debug("[AutoUpdate] No updates available");
            }
        } catch (const std::exception& e) {
            common::Logger::instance().error("[AutoUpdate] Failed | error={}", e.what());
        }
    }
    
    common::Logger::instance().debug("[AutoUpdate] Thread stopped");
}

void DaemonServer::acceptConnections() {
    common::Logger::instance().info("[Accept] Loop started | max_conns={}", config_.max_connections);
    
    while (running_ && !shutdown_requested_) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        
        int unix_fd = unix_server_->getSocketFd();
        FD_SET(unix_fd, &read_fds);
        
        struct timeval timeout{0, 100000};
        int result = select(unix_fd + 1, &read_fds, nullptr, nullptr, &timeout);
        
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            common::Logger::instance().error("[Accept] Select failed | error={}", strerror(errno));
            continue;
        }
        
        if (result == 0) continue;
        
        size_t current_conns = active_connections_.load();
        if (current_conns >= static_cast<size_t>(config_.max_connections)) {
            common::Logger::instance().warn("[Accept] Max connections reached | current={} | max={}", 
                                           current_conns, config_.max_connections);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        if (FD_ISSET(unix_fd, &read_fds)) {
            auto conn = unix_server_->acceptConnection();
            if (conn) {
                common::Logger::instance().debug("[Connection] Accepted | type=unix | active={} | queued={}", 
                                                current_conns + 1, connection_queue_.size());
                {
                    std::lock_guard<std::mutex> lock(queue_mutex_);
                    connection_queue_.push_back(conn);
                }
                queue_cv_.notify_one();
            }
        }
    }
    
    common::Logger::instance().info("[Accept] Loop stopped");
}

}}