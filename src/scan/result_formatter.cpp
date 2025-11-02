#include "semantics_av/scan/result_formatter.hpp"
#include <nlohmann/json.hpp>
#include <iomanip>

namespace semantics_av {
namespace scan {

ResultFormatter::ResultFormatter(OutputFormat format) : format_(format) {}

void ResultFormatter::formatScanResult(const common::ScanMetadata& result, std::ostream& out) {
    if (format_ == OutputFormat::JSON) {
        formatJsonResult(result, out);
    } else {
        formatTextResult(result, out);
    }
}

void ResultFormatter::formatScanSummary(const ScanSummary& summary, std::ostream& out) {
    if (format_ == OutputFormat::JSON) {
        formatJsonSummary(summary, out);
    } else {
        formatTextSummary(summary, out);
    }
}

void ResultFormatter::formatTextResult(const common::ScanMetadata& result, std::ostream& out) {
    std::string status_str;
    std::string color;
    
    switch (result.result) {
        case common::ScanResult::CLEAN:
            status_str = "CLEAN";
            color = "\033[32m";
            break;
        case common::ScanResult::MALICIOUS:
            status_str = "MALICIOUS";
            color = "\033[31m";
            break;
        case common::ScanResult::UNSUPPORTED:
            status_str = "UNSUPPORTED";
            color = "\033[36m";
            break;
        case common::ScanResult::ERROR:
            status_str = "ERROR";
            color = "\033[31m";
            break;
    }
    
    if (colors_enabled_) {
        out << color << status_str << "\033[0m";
    } else {
        out << status_str;
    }
    
    out << ": " << result.file_path;
    
    if (verbose_) {
        out << " (" << result.file_type;
        out << ", confidence: " << std::fixed << std::setprecision(1) 
            << (result.confidence * 100) << "%";
        out << ", " << formatFileSize(result.file_size);
        out << ", " << formatDuration(result.scan_time) << ")";
    }
    
    if (result.error_message && verbose_) {
        out << " - " << *result.error_message;
    }
    
    out << "\n";
}

void ResultFormatter::formatJsonResult(const common::ScanMetadata& result, std::ostream& out) {
    nlohmann::json json;
    
    json["file_path"] = result.file_path;
    json["result"] = common::to_string(result.result);
    json["confidence"] = result.confidence;
    json["file_type"] = result.file_type;
    json["file_size"] = result.file_size;
    json["scan_time_ms"] = result.scan_time.count();
    
    if (result.error_message) {
        json["error"] = *result.error_message;
    }
    
    if (result.file_hashes && !result.file_hashes->empty()) {
        json["file_hashes"] = *result.file_hashes;
    }
    
    out << json.dump(verbose_ ? 2 : 0) << "\n";
}

void ResultFormatter::formatTextSummary(const ScanSummary& summary, std::ostream& out) {
    out << "\n" << colorize("----------- SCAN SUMMARY -----------", "\033[1m") << "\n";
    
    out << "Total files found: " << summary.total_files_found << "\n";
    
    size_t analyzed_files = summary.clean_files + summary.malicious_files;
    out << "Files analyzed: " << analyzed_files << "\n";
    
    if (summary.malicious_files > 0) {
        out << "  - " << colorize("Malicious", "\033[31m") << ": " << summary.malicious_files << "\n";
    }
    
    if (summary.clean_files > 0) {
        out << "  - " << colorize("Clean", "\033[32m") << ": " << summary.clean_files << "\n";
    }
    
    if (summary.error_files > 0) {
        out << "Files with errors: " << summary.error_files << "\n";
    }
    
    size_t total_skipped = summary.unsupported_files + summary.permission_denied_files + summary.size_exceeded_files;
    if (total_skipped > 0) {
        out << "Files skipped:\n";
        
        if (summary.unsupported_files > 0) {
            out << "  - Unsupported: " << summary.unsupported_files << "\n";
        }
        
        if (summary.permission_denied_files > 0) {
            out << "  - Permission denied: " << summary.permission_denied_files << "\n";
        }
        
        if (summary.size_exceeded_files > 0) {
            out << "  - Size exceeded: " << summary.size_exceeded_files << "\n";
        }
    }
    
    double total_seconds = summary.total_time.count() / 1000.0;
    out << "Analysis time: " << std::fixed << std::setprecision(3) << total_seconds << " sec\n";
    
    size_t total_bytes = 0;
    for (const auto& result : summary.results) {
        total_bytes += result.file_size;
    }
    out << "Data analyzed: " << formatFileSize(total_bytes) << "\n";
    
    auto start_time = std::chrono::system_clock::now() - summary.total_time;
    auto end_time = std::chrono::system_clock::now();
    
    auto format_time = [](const std::chrono::system_clock::time_point& tp) {
        auto tt = std::chrono::system_clock::to_time_t(tp);
        std::tm tm = *std::localtime(&tt);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    };
    
    out << "Start time: " << format_time(start_time) << "\n";
    out << "End time:   " << format_time(end_time) << "\n";
}

void ResultFormatter::formatJsonSummary(const ScanSummary& summary, std::ostream& out) {
    nlohmann::json json;
    
    json["total_files_found"] = summary.total_files_found;
    json["total_files"] = summary.total_files;
    json["clean_files"] = summary.clean_files;
    json["malicious_files"] = summary.malicious_files;
    json["unsupported_files"] = summary.unsupported_files;
    json["error_files"] = summary.error_files;
    json["permission_denied_files"] = summary.permission_denied_files;
    json["size_exceeded_files"] = summary.size_exceeded_files;
    json["total_time_ms"] = summary.total_time.count();
    
    if (verbose_) {
        json["results"] = nlohmann::json::array();
        for (const auto& result : summary.results) {
            nlohmann::json result_json;
            result_json["file_path"] = result.file_path;
            result_json["result"] = common::to_string(result.result);
            result_json["confidence"] = result.confidence;
            result_json["file_type"] = result.file_type;
            result_json["file_size"] = result.file_size;
            result_json["scan_time_ms"] = result.scan_time.count();
            
            if (result.error_message) {
                result_json["error"] = *result.error_message;
            }
            
            json["results"].push_back(result_json);
        }
    }
    
    out << json.dump(2) << "\n";
}

std::string ResultFormatter::colorize(const std::string& text, const std::string& color) {
    if (colors_enabled_) {
        return color + text + "\033[0m";
    }
    return text;
}

std::string ResultFormatter::formatFileSize(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit_index < 4) {
        size /= 1024.0;
        unit_index++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << size << " " << units[unit_index];
    return oss.str();
}

std::string ResultFormatter::formatDuration(std::chrono::milliseconds ms) {
    auto count = ms.count();
    
    if (count < 1000) {
        return std::to_string(count) + "ms";
    } else if (count < 60000) {
        return std::to_string(count / 1000) + "." + std::to_string((count % 1000) / 100) + "s";
    } else {
        auto minutes = count / 60000;
        auto seconds = (count % 60000) / 1000;
        return std::to_string(minutes) + "m " + std::to_string(seconds) + "s";
    }
}

}}