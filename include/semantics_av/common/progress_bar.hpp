#pragma once

#include <string>
#include <chrono>
#include <ostream>

namespace semantics_av {
namespace common {

class ProgressBarRenderer {
public:
    explicit ProgressBarRenderer(const std::string& label, bool use_colors = true);
    
    void update(size_t current_bytes, size_t total_bytes);
    void complete();
    void clear();
    
    void render(std::ostream& out);
    
    bool isComplete() const { return completed_; }

private:
    std::string label_;
    bool use_colors_;
    bool completed_;
    
    size_t current_bytes_;
    size_t total_bytes_;
    
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point last_update_;
    size_t last_bytes_;
    
    std::string formatBytes(size_t bytes) const;
    std::string formatSpeed(double bytes_per_sec) const;
    int getTerminalWidth() const;
};

}}