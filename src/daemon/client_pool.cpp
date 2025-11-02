#include "semantics_av/daemon/client_pool.hpp"
#include "semantics_av/common/logger.hpp"
#include <thread>
#include <chrono>

namespace semantics_av {
namespace daemon {

DaemonClientPool::DaemonClientPool(size_t pool_size)
    : pool_size_(pool_size) {
    all_clients_.reserve(pool_size);
    available_clients_.reserve(pool_size);
}

DaemonClientPool::~DaemonClientPool() {
    std::lock_guard<std::mutex> lock(mutex_);
    common::Logger::instance().debug("[Pool] Destroying | size={}", pool_size_);
    all_clients_.clear();
}

bool DaemonClientPool::initialize() {
    if (initialized_) {
        return true;
    }
    
    common::Logger::instance().info("[Pool] Initializing | size={}", pool_size_);
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (size_t i = 0; i < pool_size_; ++i) {
        auto client = std::make_unique<DaemonClient>();
        
        bool connected = false;
        for (int retry = 0; retry < 3; ++retry) {
            if (client->connect()) {
                connected = true;
                break;
            }
            if (retry < 2) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        
        if (!connected) {
            common::Logger::instance().error("[Pool] Client connect failed | index={}", i);
            return false;
        }
        
        available_clients_.push_back(client.get());
        all_clients_.push_back(std::move(client));
    }
    
    initialized_ = true;
    common::Logger::instance().info("[Pool] Initialized | size={}", pool_size_);
    return true;
}

PooledClient DaemonClientPool::acquire() {
    std::unique_lock<std::mutex> lock(mutex_);
    
    cv_.wait(lock, [this] { return !available_clients_.empty(); });
    
    DaemonClient* client = available_clients_.back();
    available_clients_.pop_back();
    
    if (!client->isConnected()) {
        common::Logger::instance().warn("[Pool] Reconnecting client");
        if (!reconnectClient(client)) {
            available_clients_.push_back(client);
            cv_.notify_one();
            throw std::runtime_error("Failed to reconnect client");
        }
    }
    
    return PooledClient(client, [this](DaemonClient* c) {
        this->returnClient(c);
    });
}

void DaemonClientPool::returnClient(DaemonClient* client) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        available_clients_.push_back(client);
    }
    cv_.notify_one();
}

bool DaemonClientPool::reconnectClient(DaemonClient* client) {
    client->disconnect();
    
    for (int retry = 0; retry < 3; ++retry) {
        if (client->connect()) {
            common::Logger::instance().debug("[Pool] Client reconnected | retry={}", retry);
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    common::Logger::instance().error("[Pool] Reconnect failed after retries");
    return false;
}

size_t DaemonClientPool::available() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return available_clients_.size();
}

bool DaemonClientPool::isHealthy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& client : all_clients_) {
        if (!client->isConnected()) {
            return false;
        }
    }
    
    return true;
}

}}