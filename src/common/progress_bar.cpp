#include "semantics_av/common/progress_bar.hpp"
#include <sstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <sys/ioctl.h>
#include <unistd.h>

namespace semantics_av {
namespace common {

ProgressBarRenderer::ProgressBarRenderer(const std::string& label, bool use_colors)
    : label_(label),
      use_colors_(use_colors),
      completed_(false),
      current_bytes_(0),
      total_bytes_(0),
      last_bytes_(0) {
    start_time_ = std::chrono::steady_clock::now();
    last_update_ = start_time_;
}

void ProgressBarRenderer::update(size_t current_bytes, size_t total_bytes) {
    current_bytes_ = current_bytes;
    total_bytes_ = total_bytes;
    
    auto now = std::chrono::steady_clock::now();
    last_update_ = now;
}

void ProgressBarRenderer::complete() {
    completed_ = true;
}

void ProgressBarRenderer::clear() {
    if (!isatty(STDOUT_FILENO)) return;
    std::cout << "\r\033[K" << std::flush;
}

void ProgressBarRenderer::render(std::ostream& out) {
    if (!isatty(STDOUT_FILENO) && !completed_) {
        return;
    }
    
    if (completed_) {
        out << "\r\033[K";
        return;
    }
    
    std::ostringstream oss;
    
    if (total_bytes_ > 0) {
        double progress = static_cast<double>(current_bytes_) / total_bytes_;
        int percent = static_cast<int>(progress * 100);
        
        int bar_width = 20;
        int filled = static_cast<int>(bar_width * progress);
        
        oss << "\r";
        
        if (use_colors_) {
            oss << "\033[36m";
        }
        
        oss << label_ << ": [";
        
        for (int i = 0; i < bar_width; ++i) {
            if (i < filled) {
                oss << "=";
            } else if (i == filled) {
                oss << ">";
            } else {
                oss << " ";
            }
        }
        
        oss << "] " << percent << "% ";
        
        if (use_colors_) {
            oss << "\033[0m";
        }
        
        oss << "(" << formatBytes(current_bytes_) << "/" << formatBytes(total_bytes_) << ")";
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update_);
        
        if (elapsed.count() > 0 && current_bytes_ > last_bytes_) {
            double bytes_diff = current_bytes_ - last_bytes_;
            double seconds = elapsed.count() / 1000.0;
            double speed = bytes_diff / seconds;
            
            oss << " @ " << formatSpeed(speed);
            last_bytes_ = current_bytes_;
        }
        
    } else {
        oss << "\r";
        
        if (use_colors_) {
            oss << "\033[36m";
        }
        
        oss << label_ << ": " << formatBytes(current_bytes_) << " downloaded...";
        
        if (use_colors_) {
            oss << "\033[0m";
        }
    }
    
    out << oss.str() << std::flush;
}

std::string ProgressBarRenderer::formatBytes(size_t bytes) const {
    std::ostringstream oss;
    
    if (bytes < 1024) {
        oss << bytes << " B";
    } else if (bytes < 1024 * 1024) {
        oss << std::fixed << std::setprecision(1) << (bytes / 1024.0) << " KB";
    } else if (bytes < 1024 * 1024 * 1024) {
        oss << std::fixed << std::setprecision(1) << (bytes / (1024.0 * 1024.0)) << " MB";
    } else {
        oss << std::fixed << std::setprecision(1) << (bytes / (1024.0 * 1024.0 * 1024.0)) << " GB";
    }
    
    return oss.str();
}

std::string ProgressBarRenderer::formatSpeed(double bytes_per_sec) const {
    std::ostringstream oss;
    
    if (bytes_per_sec < 1024) {
        oss << std::fixed << std::setprecision(0) << bytes_per_sec << " B/s";
    } else if (bytes_per_sec < 1024 * 1024) {
        oss << std::fixed << std::setprecision(1) << (bytes_per_sec / 1024.0) << " KB/s";
    } else {
        oss << std::fixed << std::setprecision(1) << (bytes_per_sec / (1024.0 * 1024.0)) << " MB/s";
    }
    
    return oss.str();
}

int ProgressBarRenderer::getTerminalWidth() const {
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 0) {
        return w.ws_col;
    }
    return 80;
}

}}