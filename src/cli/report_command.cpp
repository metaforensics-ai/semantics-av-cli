#include "report_command.hpp"
#include "semantics_av/report/storage.hpp"
#include "semantics_av/report/converter.hpp"
#include "semantics_av/format/json_formatter.hpp"
#include "semantics_av/daemon/client.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/paths.hpp"
#include "semantics_av/common/diagnostics.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>
#include <unistd.h>

namespace semantics_av {
namespace cli {

ReportCommand::ReportCommand() : was_called_(false) {}

void ReportCommand::setup(CLI::App* subcommand) {
    subcommand_ = subcommand;
    
    list_cmd_ = subcommand->add_subcommand("list", "List saved reports");
    list_cmd_->add_option("-s,--sort", list_sort_, "Sort by: time, verdict, file, size (default: time)")
               ->default_val("time");
    list_cmd_->add_option("-f,--filter", list_filter_, "Filter: verdict:VALUE, date:RANGE, file-type:TYPE");
    list_cmd_->add_option("-n,--limit", list_limit_, "Show last N reports (default: 20)")
               ->default_val(20);
    list_cmd_->add_option("-o,--format", list_format_, "Output format: table, json, csv (default: table)")
               ->default_val("table");
    list_cmd_->callback([this]() { was_called_ = true; });
    
    show_cmd_ = subcommand->add_subcommand("show", "Show specific report");
    show_cmd_->add_option("report_id", show_report_id_, "Report ID")->required();
    show_cmd_->add_option("-f,--format", show_format_, "Display format: console, json (default: console)")
               ->default_val("console");
    show_cmd_->callback([this]() { was_called_ = true; });
    
    convert_cmd_ = subcommand->add_subcommand("convert", "Convert report format");
    convert_cmd_->add_option("report_id", convert_report_id_, "Report ID")->required();
    convert_cmd_->add_option("-f,--format", convert_format_, "Target format: console, html, markdown, json")
                 ->required();
    convert_cmd_->add_option("-o,--output", convert_output_, "Output file path (required for html/markdown)");
    convert_cmd_->callback([this]() { was_called_ = true; });
    
    delete_cmd_ = subcommand->add_subcommand("delete", "Delete reports");
    delete_cmd_->add_option("report_id", delete_report_id_, "Report ID or glob pattern (* and ? supported)");
    delete_cmd_->add_option("-t,--older-than", delete_older_than_, "Delete reports older than N days");
    delete_cmd_->add_option("-v,--verdict", delete_verdict_, "Delete by verdict");
    delete_cmd_->add_flag("-y,--confirm", delete_confirm_, "Skip confirmation prompt");
    delete_cmd_->callback([this]() { was_called_ = true; });
    
    info_cmd_ = subcommand->add_subcommand("info", "Show report metadata");
    info_cmd_->add_option("report_id", info_report_id_, "Report ID")->required();
    info_cmd_->callback([this]() { was_called_ = true; });
    
    stats_cmd_ = subcommand->add_subcommand("stats", "Show statistics");
    stats_cmd_->callback([this]() { was_called_ = true; });
}

bool ReportCommand::wasCalled() const {
    return was_called_;
}

int ReportCommand::execute() {
    if (list_cmd_->parsed()) {
        return executeList();
    } else if (show_cmd_->parsed()) {
        return executeShow();
    } else if (convert_cmd_->parsed()) {
        return executeConvert();
    } else if (delete_cmd_->parsed()) {
        return executeDelete();
    } else if (info_cmd_->parsed()) {
        return executeInfo();
    } else if (stats_cmd_->parsed()) {
        return executeStats();
    }
    
    std::cout << subcommand_->help() << std::endl;
    return 0;
}

bool ReportCommand::matchPattern(const std::string& text, const std::string& pattern) const {
    size_t text_pos = 0;
    size_t pattern_pos = 0;
    size_t text_backup = std::string::npos;
    size_t pattern_backup = std::string::npos;
    
    while (text_pos < text.size()) {
        if (pattern_pos < pattern.size()) {
            if (pattern[pattern_pos] == '*') {
                pattern_backup = pattern_pos;
                text_backup = text_pos;
                pattern_pos++;
                continue;
            }
            
            if (pattern[pattern_pos] == '?' || pattern[pattern_pos] == text[text_pos]) {
                text_pos++;
                pattern_pos++;
                continue;
            }
        }
        
        if (pattern_backup != std::string::npos) {
            pattern_pos = pattern_backup + 1;
            text_backup++;
            text_pos = text_backup;
            continue;
        }
        
        return false;
    }
    
    while (pattern_pos < pattern.size() && pattern[pattern_pos] == '*') {
        pattern_pos++;
    }
    
    return pattern_pos == pattern.size();
}

int ReportCommand::executeList() {
    report::ReportStorage storage;
    
    report::ListOptions options;
    options.sort_by = list_sort_;
    options.limit = list_limit_;
    
    if (!list_filter_.empty()) {
        size_t colon = list_filter_.find(':');
        if (colon != std::string::npos) {
            std::string key = list_filter_.substr(0, colon);
            std::string value = list_filter_.substr(colon + 1);
            
            if (key == "verdict") {
                options.filter_verdict = value;
            } else if (key == "date") {
                options.filter_date = value;
            } else if (key == "file-type") {
                options.filter_file_type = value;
            }
        }
    }
    
    auto reports = storage.list(options);
    
    if (reports.empty()) {
        std::cout << "No reports found." << std::endl;
        return 0;
    }
    
    if (list_format_ == "json") {
        nlohmann::json json_array = nlohmann::json::array();
        for (const auto& metadata : reports) {
            auto result = storage.load(metadata.report_id);
            if (result) {
                json_array.push_back(format::JsonFormatter::format(*result));
            }
        }
        std::cout << json_array.dump(2) << std::endl;
    } else if (list_format_ == "csv") {
        std::cout << "report_id,file_type,verdict,confidence,file_size,saved_at\n";
        for (const auto& report : reports) {
            auto time_t_val = std::chrono::system_clock::to_time_t(report.saved_at);
            std::tm tm = *std::gmtime(&time_t_val);
            std::ostringstream oss;
            oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
            
            std::cout << report.report_id << ","
                      << report.file_type << ","
                      << report.verdict << ","
                      << std::fixed << std::setprecision(2) << (report.confidence * 100) << ","
                      << report.file_size << ","
                      << oss.str() << "\n";
        }
    } else {
        std::cout << std::left 
                  << std::setw(35) << "Report ID"
                  << std::setw(6) << "Type"
                  << std::setw(12) << "Verdict"
                  << std::setw(12) << "Confidence"
                  << std::setw(20) << "Saved At" << std::endl;
        std::cout << std::string(85, '-') << std::endl;
        
        for (const auto& report : reports) {
            auto time_t_val = std::chrono::system_clock::to_time_t(report.saved_at);
            std::tm tm = *std::localtime(&time_t_val);
            std::ostringstream oss;
            oss << std::put_time(&tm, "%Y-%m-%d %H:%M");
            
            std::cout << std::left 
                      << std::setw(35) << report.report_id
                      << std::setw(6) << report.file_type
                      << std::setw(12) << report.verdict
                      << std::setw(12) << (std::to_string(int(report.confidence * 100)) + "%")
                      << std::setw(20) << oss.str() << std::endl;
        }
    }
    
    return 0;
}

int ReportCommand::executeShow() {
    report::ReportStorage storage;
    auto result = storage.load(show_report_id_);
    
    if (!result) {
        std::cerr << "Report not found: " << show_report_id_ << std::endl;
        return 1;
    }
    
    if (show_format_ == "json") {
        auto json = format::JsonFormatter::format(*result);
        std::cout << json.dump(2) << std::endl;
    } else {
        report::ReportConverter converter;
        converter.convert(*result, report::ConvertFormat::CONSOLE, std::cout);
    }
    
    return 0;
}

int ReportCommand::executeConvert() {
    report::ConvertFormat format;
    std::string ext;
    
    if (convert_format_ == "console") {
        format = report::ConvertFormat::CONSOLE;
        ext = ".txt";
    } else if (convert_format_ == "json") {
        format = report::ConvertFormat::JSON;
        ext = ".json";
    } else if (convert_format_ == "html") {
        format = report::ConvertFormat::HTML;
        ext = ".html";
    } else if (convert_format_ == "markdown") {
        format = report::ConvertFormat::MARKDOWN;
        ext = ".md";
    } else {
        std::cerr << "Invalid format: " << convert_format_ << std::endl;
        return 1;
    }
    
    std::string output_path = convert_output_;
    
    if (output_path.empty() && (format == report::ConvertFormat::HTML || 
                                 format == report::ConvertFormat::MARKDOWN)) {
        output_path = convert_report_id_ + ext;
    }
    
    report::ReportConverter converter;
    
    if (output_path.empty()) {
        report::ReportStorage storage;
        auto result = storage.load(convert_report_id_);
        
        if (!result) {
            std::cerr << "Report not found: " << convert_report_id_ << std::endl;
            return 1;
        }
        
        converter.convert(*result, format, std::cout);
    } else {
        if (!converter.convertFile(convert_report_id_, format, output_path)) {
            std::cerr << "Conversion failed" << std::endl;
            return 1;
        }
        
        std::cout << "Converted to: " << std::filesystem::absolute(output_path).string() << std::endl;
    }
    
    return 0;
}

int ReportCommand::executeDelete() {
    report::ReportStorage storage;
    std::vector<std::string> to_delete;
    
    if (!delete_report_id_.empty()) {
        if (delete_report_id_.find('*') != std::string::npos || 
            delete_report_id_.find('?') != std::string::npos) {
            auto all_reports = storage.list({});
            for (const auto& report : all_reports) {
                if (matchPattern(report.report_id, delete_report_id_)) {
                    to_delete.push_back(report.report_id);
                }
            }
        } else {
            to_delete.push_back(delete_report_id_);
        }
    }
    
    if (delete_older_than_ > 0) {
        auto now = std::chrono::system_clock::now();
        auto cutoff = now - std::chrono::hours(24 * delete_older_than_);
        
        auto all = storage.list({});
        for (const auto& r : all) {
            if (r.saved_at < cutoff) {
                if (std::find(to_delete.begin(), to_delete.end(), r.report_id) == to_delete.end()) {
                    to_delete.push_back(r.report_id);
                }
            }
        }
    }
    
    if (!delete_verdict_.empty()) {
        report::ListOptions opts;
        opts.filter_verdict = delete_verdict_;
        auto filtered = storage.list(opts);
        for (const auto& r : filtered) {
            if (std::find(to_delete.begin(), to_delete.end(), r.report_id) == to_delete.end()) {
                to_delete.push_back(r.report_id);
            }
        }
    }
    
    if (to_delete.empty()) {
        std::cout << "No reports match the criteria." << std::endl;
        return 0;
    }
    
    if (!delete_confirm_ && to_delete.size() > 1) {
        std::cout << "Delete " << to_delete.size() << " reports? [y/N]: ";
        std::string response;
        std::getline(std::cin, response);
        if (response.empty() || (response[0] != 'y' && response[0] != 'Y')) {
            std::cout << "Cancelled." << std::endl;
            return 0;
        }
    } else if (!delete_confirm_ && to_delete.size() == 1) {
        std::cout << "Delete report " << to_delete[0] << "? [y/N]: ";
        std::string response;
        std::getline(std::cin, response);
        if (response.empty() || (response[0] != 'y' && response[0] != 'Y')) {
            std::cout << "Cancelled." << std::endl;
            return 0;
        }
    }
    
    bool use_daemon = daemon::DaemonClient::isDaemonRunning();
    
    size_t deleted = 0;
    if (use_daemon) {
        daemon::DaemonClient client;
        if (client.connect()) {
            for (const auto& id : to_delete) {
                auto response = client.deleteReport(id);
                if (response && response->success) {
                    deleted++;
                    std::cout << "Deleted: " << id << std::endl;
                } else {
                    std::cerr << "Failed to delete: " << id;
                    if (response && !response->error_message.empty()) {
                        std::cerr << " (" << response->error_message << ")";
                    }
                    std::cerr << std::endl;
                }
            }
        } else {
            std::cerr << "Failed to connect to daemon, falling back to direct delete" << std::endl;
            use_daemon = false;
        }
    }
    
    if (!use_daemon) {
        std::string reports_dir = storage.getReportsDir();
        if (access(reports_dir.c_str(), W_OK) != 0) {
            auto& path_manager = common::PathManager::instance();
            
            std::string command = "semantics-av report delete";
            if (!delete_report_id_.empty()) {
                command += " " + delete_report_id_;
            }
            if (delete_older_than_ > 0) {
                command += " --older-than " + std::to_string(delete_older_than_);
            }
            if (!delete_verdict_.empty()) {
                command += " --verdict " + delete_verdict_;
            }
            
            diagnostics::printPermissionGuide(reports_dir, command, path_manager.isSystemMode());
            return 1;
        }
        
        for (const auto& id : to_delete) {
            if (storage.deleteReport(id)) {
                deleted++;
                std::cout << "Deleted: " << id << std::endl;
            } else {
                std::cerr << "Failed to delete: " << id << std::endl;
            }
        }
    }
    
    std::cout << "\nDeleted " << deleted << " of " << to_delete.size() << " reports." << std::endl;
    
    return 0;
}

int ReportCommand::executeInfo() {
    report::ReportStorage storage;
    auto result = storage.load(info_report_id_);
    
    if (!result) {
        std::cerr << "Report not found: " << info_report_id_ << std::endl;
        return 1;
    }
    
    std::cout << "Report ID: " << info_report_id_ << std::endl;
    std::cout << "Verdict: " << result->verdict << std::endl;
    std::cout << "Confidence: " << (result->confidence * 100) << "%" << std::endl;
    std::cout << "File Type: " << result->file_type << std::endl;
    std::cout << "Analysis Timestamp: " << result->analysis_timestamp << std::endl;
    std::cout << "SDK Version: " << result->sdk_version << std::endl;
    
    return 0;
}

int ReportCommand::executeStats() {
    report::ReportStorage storage;
    auto stats = storage.getStats();
    
    std::cout << "Report Statistics" << std::endl;
    std::cout << "=================" << std::endl;
    std::cout << "Total Reports: " << stats.total_reports << std::endl;
    std::cout << "  Malicious: " << stats.malicious_count << std::endl;
    std::cout << "  Clean: " << stats.clean_count << std::endl;
    std::cout << "  Error: " << stats.error_count << std::endl;
    std::cout << "Storage Usage: " << (stats.total_size_bytes / 1024 / 1024) << " MB" << std::endl;
    
    if (stats.oldest_report) {
        auto time_t_val = std::chrono::system_clock::to_time_t(*stats.oldest_report);
        std::tm tm = *std::localtime(&time_t_val);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        std::cout << "Oldest Report: " << oss.str() << std::endl;
    }
    
    if (stats.newest_report) {
        auto time_t_val = std::chrono::system_clock::to_time_t(*stats.newest_report);
        std::tm tm = *std::localtime(&time_t_val);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        std::cout << "Newest Report: " << oss.str() << std::endl;
    }
    
    return 0;
}

}}