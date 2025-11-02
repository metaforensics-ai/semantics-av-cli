#pragma once

#include "semantics_av/daemon/client.hpp"
#include <memory>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>

namespace semantics_av {
namespace daemon {

class DaemonClientPool;

class PooledClient {
public:
    PooledClient(DaemonClient* client, std::function<void(DaemonClient*)> return_func)
        : client_(client), return_func_(std::move(return_func)) {}
    
    ~PooledClient() {
        if (client_ && return_func_) {
            return_func_(client_);
        }
    }
    
    PooledClient(PooledClient&& other) noexcept
        : client_(other.client_), return_func_(std::move(other.return_func_)) {
        other.client_ = nullptr;
    }
    
    PooledClient& operator=(PooledClient&& other) noexcept {
        if (this != &other) {
            if (client_ && return_func_) {
                return_func_(client_);
            }
            client_ = other.client_;
            return_func_ = std::move(other.return_func_);
            other.client_ = nullptr;
        }
        return *this;
    }
    
    PooledClient(const PooledClient&) = delete;
    PooledClient& operator=(const PooledClient&) = delete;
    
    DaemonClient* operator->() { return client_; }
    DaemonClient& operator*() { return *client_; }
    bool valid() const { return client_ != nullptr; }
    
private:
    DaemonClient* client_;
    std::function<void(DaemonClient*)> return_func_;
};

class DaemonClientPool {
public:
    explicit DaemonClientPool(size_t pool_size = 4);
    ~DaemonClientPool();
    
    bool initialize();
    PooledClient acquire();
    size_t size() const { return pool_size_; }
    size_t available() const;
    bool isHealthy() const;
    
private:
    void returnClient(DaemonClient* client);
    bool reconnectClient(DaemonClient* client);
    
    size_t pool_size_;
    std::vector<std::unique_ptr<DaemonClient>> all_clients_;
    std::vector<DaemonClient*> available_clients_;
    
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> initialized_{false};
};

}
}