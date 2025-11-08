#include "semantics_av/report/storage.hpp"
#include "semantics_av/format/json_formatter.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/config.hpp"
#include "semantics_av/common/paths.hpp"
#include "semantics_av/common/version.hpp"
#include <fstream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <random>
#include <sys/stat.h>

namespace semantics_av {
namespace report {

ReportStorage::ReportStorage() : ReportStorage("") {}

ReportStorage::ReportStorage(const std::string& custom_dir) {
    auto& config = common::Config::instance().global();
    
    if (!custom_dir.empty()) {
        reports_dir_ = custom_dir;
    } else if (!config.report.reports_dir.empty()) {
        reports_dir_ = config.report.reports_dir;
    } else {
        auto& path_manager = common::PathManager::instance();
        reports_dir_ = path_manager.getDataDir() + "/reports";
    }
    
    std::filesystem::create_directories(reports_dir_);
    common::Logger::instance().debug("[ReportStorage] Initialized | dir={}", reports_dir_);
}

std::string ReportStorage::safeGetString(const nlohmann::json& json, const std::string& key, const std::string& default_value) const {
    if (json.contains(key) && !json[key].is_null() && json[key].is_string()) {
        return json[key].get<std::string>();
    }
    return default_value;
}

float ReportStorage::safeGetFloat(const nlohmann::json& json, const std::string& key, float default_value) const {
    if (json.contains(key) && !json[key].is_null() && json[key].is_number()) {
        return json[key].get<float>();
    }
    return default_value;
}

int ReportStorage::safeGetInt(const nlohmann::json& json, const std::string& key, int default_value) const {
    if (json.contains(key) && !json[key].is_null() && json[key].is_number()) {
        return json[key].get<int>();
    }
    return default_value;
}

bool ReportStorage::isValidReportId(const std::string& report_id) const {
    if (report_id.empty()) {
        return false;
    }
    
    size_t underscore_count = std::count(report_id.begin(), report_id.end(), '_');
    
    if (underscore_count == 2 && report_id.length() == 32) {
        return true;
    }
    
    if (underscore_count >= 2 && report_id.length() >= 40 && report_id.length() <= 100) {
        for (char c : report_id) {
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') {
                return false;
            }
        }
        return true;
    }
    
    return false;
}

std::string ReportStorage::generateReportId(const std::string& sha256,
                                            const std::chrono::system_clock::time_point& timestamp,
                                            const std::string& verdict) {
    std::string prefix;
    
    if (sha256.length() >= 16 && sha256 != "unknown") {
        bool valid_hex = true;
        for (size_t i = 0; i < 16; ++i) {
            if (!std::isxdigit(static_cast<unsigned char>(sha256[i]))) {
                valid_hex = false;
                break;
            }
        }
        
        if (valid_hex) {
            prefix = sha256.substr(0, 16);
        }
    }
    
    if (prefix.empty()) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        
        prefix.reserve(16);
        const char* hex_chars = "0123456789abcdef";
        for (int i = 0; i < 16; ++i) {
            prefix += hex_chars[dis(gen)];
        }
    }
    
    auto time_t_val = std::chrono::system_clock::to_time_t(timestamp);
    std::tm tm = *std::localtime(&time_t_val);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y%m%d_%H%M%S");
    
    return prefix + "_" + oss.str();
}

std::string ReportStorage::save(const network::AnalysisResult& result,
                                const std::string& original_path,
                                const std::string& language,
                                size_t file_size) {
    auto& config = common::Config::instance().global();
    
    if (!config.report.enable_storage) {
        common::Logger::instance().debug("[ReportStorage] Storage disabled");
        return "";
    }
    
    std::string sha256;
    if (result.file_hashes.find("sha256") != result.file_hashes.end()) {
        sha256 = result.file_hashes.at("sha256");
    } else {
        sha256 = "unknown";
    }
    
    auto now = std::chrono::system_clock::now();
    std::string report_id = generateReportId(sha256, now, result.verdict);
    
    nlohmann::json report_json;
    
    report_json["metadata"]["report_version"] = "1.0";
    
    auto time_t_val = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::gmtime(&time_t_val);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    report_json["metadata"]["saved_at"] = oss.str();
    
    report_json["metadata"]["cli_version"] = "1.0.0";
    report_json["metadata"]["sdk_version"] = common::getSDKVersion();
    
    report_json["metadata"]["original_file"]["path"] = original_path;
    report_json["metadata"]["original_file"]["size"] = file_size;
    report_json["metadata"]["original_file"]["analyzed_at"] = result.analysis_timestamp;
    
    report_json["metadata"]["report_options"]["language"] = language;
    report_json["metadata"]["report_options"]["include_hashes"] = !result.file_hashes.empty();
    
    report_json["analysis_result"] = format::JsonFormatter::format(result);
    
    auto report_path = getReportPath(report_id);
    std::ofstream file(report_path);
    if (!file) {
        common::Logger::instance().error("[ReportStorage] Failed to create file | path={}", 
                                        report_path.string());
        return "";
    }
    
    file << report_json.dump(2);
    file.close();
    
    auto& path_manager = common::PathManager::instance();
    chmod(report_path.c_str(), path_manager.isSystemMode() ? 0644 : 0600);
    
    if (config.report.auto_cleanup) {
        applyCleanupPolicies();
    }
    
    common::Logger::instance().info("[ReportStorage] Saved | id={} | verdict={}", 
                                    report_id, result.verdict);
    
    return report_id;
}

void ReportStorage::applyCleanupPolicies() {
    auto& config = common::Config::instance().global();
    
    if (config.report.retention_days > 0) {
        cleanupByAge(config.report.retention_days);
    }
    
    if (config.report.max_reports > 0) {
        cleanupByCount(config.report.max_reports);
    }
}

void ReportStorage::cleanupByAge(int days) {
    auto now = std::chrono::system_clock::now();
    auto cutoff = now - std::chrono::hours(24 * days);
    
    auto files = findReportFiles();
    size_t deleted = 0;
    
    for (const auto& file : files) {
        auto metadata = parseMetadataFromFile(file);
        if (metadata && metadata->saved_at < cutoff) {
            try {
                std::filesystem::remove(file);
                deleted++;
            } catch (...) {}
        }
    }
    
    if (deleted > 0) {
        common::Logger::instance().info("[ReportStorage] Cleanup by age | deleted={} | days={}", 
                                       deleted, days);
    }
}

void ReportStorage::cleanupByCount(int max) {
    auto files = findReportFiles();
    
    if (files.size() <= static_cast<size_t>(max)) {
        return;
    }
    
    std::vector<std::pair<std::chrono::system_clock::time_point, std::filesystem::path>> sorted;
    
    for (const auto& file : files) {
        auto metadata = parseMetadataFromFile(file);
        if (metadata) {
            sorted.push_back({metadata->saved_at, file});
        }
    }
    
    std::sort(sorted.begin(), sorted.end(), 
              [](const auto& a, const auto& b) { return a.first > b.first; });
    
    size_t deleted = 0;
    for (size_t i = max; i < sorted.size(); ++i) {
        try {
            std::filesystem::remove(sorted[i].second);
            deleted++;
        } catch (...) {}
    }
    
    if (deleted > 0) {
        common::Logger::instance().info("[ReportStorage] Cleanup by count | deleted={} | max={}", 
                                       deleted, max);
    }
}

std::optional<network::AnalysisResult> ReportStorage::parseAnalysisResultFromJsonInternal(
    const nlohmann::json& analysis_json) {
    
    network::AnalysisResult result;
    
    auto safeGetString = [](const nlohmann::json& json, const std::string& key, const std::string& default_value = "") {
        if (json.contains(key) && !json[key].is_null() && json[key].is_string()) {
            return json[key].get<std::string>();
        }
        return default_value;
    };
    
    auto safeGetFloat = [](const nlohmann::json& json, const std::string& key, float default_value = 0.0f) {
        if (json.contains(key) && !json[key].is_null() && json[key].is_number()) {
            return json[key].get<float>();
        }
        return default_value;
    };
    
    auto safeGetInt = [](const nlohmann::json& json, const std::string& key, int default_value = 0) {
        if (json.contains(key) && !json[key].is_null() && json[key].is_number()) {
            return json[key].get<int>();
        }
        return default_value;
    };
    
    result.file_type = safeGetString(analysis_json, "file_type");
    result.analysis_timestamp = safeGetString(analysis_json, "analysis_timestamp");
    result.sdk_version = safeGetString(analysis_json, "sdk_version");
    
    if (analysis_json.contains("detection") && analysis_json["detection"].is_object()) {
        auto detection = analysis_json["detection"];
        result.verdict = safeGetString(detection, "verdict", "error");
        result.confidence = safeGetFloat(detection, "confidence", 0.0f);
        
        if (detection.contains("tags") && detection["tags"].is_array()) {
            for (const auto& tag : detection["tags"]) {
                if (tag.is_string()) {
                    result.tags.push_back(tag.get<std::string>());
                }
            }
        }
        
        if (detection.contains("signature") && !detection["signature"].is_null() && detection["signature"].is_string()) {
            result.signature = detection["signature"].get<std::string>();
        }
        
        if (detection.contains("static_attributes") && !detection["static_attributes"].is_null()) {
            result.static_attributes_json = detection["static_attributes"].dump();
        }
    } else {
        result.verdict = safeGetString(analysis_json, "verdict", "error");
        result.confidence = safeGetFloat(analysis_json, "confidence", 0.0f);
        
        if (analysis_json.contains("tags") && analysis_json["tags"].is_array()) {
            for (const auto& tag : analysis_json["tags"]) {
                if (tag.is_string()) {
                    result.tags.push_back(tag.get<std::string>());
                }
            }
        }
        
        if (analysis_json.contains("signature") && !analysis_json["signature"].is_null() && analysis_json["signature"].is_string()) {
            result.signature = analysis_json["signature"].get<std::string>();
        }
        
        if (analysis_json.contains("static_attributes") && !analysis_json["static_attributes"].is_null()) {
            result.static_attributes_json = analysis_json["static_attributes"].dump();
        }
    }
    
    if (analysis_json.contains("file_hashes") && analysis_json["file_hashes"].is_object()) {
        for (auto it = analysis_json["file_hashes"].begin(); 
             it != analysis_json["file_hashes"].end(); ++it) {
            if (it.value().is_string()) {
                result.file_hashes[it.key()] = it.value().get<std::string>();
            }
        }
    }
    
    result.natural_language_report = safeGetString(analysis_json, "natural_language_report");
    
    if (analysis_json.contains("intelligence")) {
        auto intel_json = analysis_json["intelligence"];
        
        if (intel_json.contains("similar_samples") && intel_json["similar_samples"].is_array()) {
            for (const auto& sample_json : intel_json["similar_samples"]) {
                network::SimilarSample sample;
                
                if (sample_json.contains("file_hashes") && sample_json["file_hashes"].is_object()) {
                    for (auto it = sample_json["file_hashes"].begin(); 
                         it != sample_json["file_hashes"].end(); ++it) {
                        if (it.value().is_string()) {
                            sample.file_hashes[it.key()] = it.value().get<std::string>();
                        }
                    }
                }
                
                sample.similarity_score = safeGetFloat(sample_json, "similarity_score", 0.0f);
                
                if (sample_json.contains("tags") && sample_json["tags"].is_array()) {
                    for (const auto& tag : sample_json["tags"]) {
                        if (tag.is_string()) {
                            sample.tags.push_back(tag.get<std::string>());
                        }
                    }
                }
                
                if (sample_json.contains("signature") && !sample_json["signature"].is_null() && sample_json["signature"].is_string()) {
                    sample.signature = sample_json["signature"].get<std::string>();
                }
                
                if (sample_json.contains("static_attributes") && 
                    !sample_json["static_attributes"].is_null()) {
                    sample.static_attributes_json = sample_json["static_attributes"].dump();
                }
                
                result.intelligence.similar_samples.push_back(sample);
            }
        }
        
        if (intel_json.contains("statistics")) {
            auto stats_json = intel_json["statistics"];
            
            result.intelligence.statistics.processed_samples = safeGetInt(stats_json, "processed_samples", 0);
            
            auto parse_label_stats = [&safeGetInt, &safeGetFloat](const nlohmann::json& json) -> network::LabelStatistics {
                network::LabelStatistics stats;
                stats.count = safeGetInt(json, "count", 0);
                if (json.contains("max_similarity") && !json["max_similarity"].is_null() && json["max_similarity"].is_number()) {
                    stats.max_similarity = json["max_similarity"].get<float>();
                }
                if (json.contains("avg_similarity") && !json["avg_similarity"].is_null() && json["avg_similarity"].is_number()) {
                    stats.avg_similarity = json["avg_similarity"].get<float>();
                }
                return stats;
            };
            
            if (stats_json.contains("by_label")) {
                auto by_label = stats_json["by_label"];
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
            
            if (stats_json.contains("by_signature") && stats_json["by_signature"].is_object()) {
                for (auto it = stats_json["by_signature"].begin(); 
                     it != stats_json["by_signature"].end(); ++it) {
                    network::SignatureStatistics sig_stat;
                    sig_stat.count = safeGetInt(it.value(), "count", 0);
                    sig_stat.max_similarity = safeGetFloat(it.value(), "max_similarity", 0.0f);
                    sig_stat.avg_similarity = safeGetFloat(it.value(), "avg_similarity", 0.0f);
                    result.intelligence.statistics.by_signature[it.key()] = sig_stat;
                }
            }
        }
    }
    
    return result;
}

std::optional<network::AnalysisResult> ReportStorage::parseAnalysisResultFromJson(
    const std::string& json_str) {
    
    try {
        nlohmann::json json = nlohmann::json::parse(json_str);
        
        if (json.contains("analysis_result")) {
            return parseAnalysisResultFromJsonInternal(json["analysis_result"]);
        } else if (json.contains("detection") || json.contains("verdict")) {
            return parseAnalysisResultFromJsonInternal(json);
        } else {
            common::Logger::instance().error("[ReportStorage] Invalid JSON structure");
            return std::nullopt;
        }
    } catch (const std::exception& e) {
        common::Logger::instance().error("[ReportStorage] JSON parse failed | error={}", e.what());
        return std::nullopt;
    }
}

std::optional<network::AnalysisResult> ReportStorage::parseAnalysisResultFromJsonFile(
    const std::string& file_path) {
    
    std::ifstream file(file_path);
    if (!file) {
        common::Logger::instance().error("[ReportStorage] Failed to open file | path={}", file_path);
        return std::nullopt;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    
    return parseAnalysisResultFromJson(buffer.str());
}

std::optional<network::AnalysisResult> ReportStorage::load(const std::string& report_id) {
    if (!isValidReportId(report_id)) {
        common::Logger::instance().warn("[ReportStorage] Invalid report ID | id={}", report_id);
        return std::nullopt;
    }
    
    auto report_path = getReportPath(report_id);
    
    if (!std::filesystem::exists(report_path)) {
        common::Logger::instance().warn("[ReportStorage] Report not found | id={}", report_id);
        return std::nullopt;
    }
    
    std::ifstream file(report_path);
    if (!file) {
        common::Logger::instance().error("[ReportStorage] Failed to open file | path={}", 
                                        report_path.string());
        return std::nullopt;
    }
    
    nlohmann::json report_json;
    try {
        file >> report_json;
    } catch (const std::exception& e) {
        common::Logger::instance().error("[ReportStorage] Failed to parse JSON | error={}", e.what());
        return std::nullopt;
    }
    
    if (!report_json.contains("analysis_result")) {
        common::Logger::instance().error("[ReportStorage] Invalid report format | id={}", report_id);
        return std::nullopt;
    }
    
    common::Logger::instance().debug("[ReportStorage] Loaded | id={}", report_id);
    return parseAnalysisResultFromJsonInternal(report_json["analysis_result"]);
}

std::vector<ReportMetadata> ReportStorage::list(const ListOptions& options) {
    auto files = findReportFiles();
    std::vector<ReportMetadata> metadata_list;
    
    for (const auto& file : files) {
        auto metadata = parseMetadataFromFile(file);
        if (metadata && matchesFilter(*metadata, options)) {
            metadata_list.push_back(*metadata);
        }
    }
    
    if (options.sort_by == "time") {
        std::sort(metadata_list.begin(), metadata_list.end(),
                  [](const auto& a, const auto& b) { return a.saved_at > b.saved_at; });
    } else if (options.sort_by == "verdict") {
        std::sort(metadata_list.begin(), metadata_list.end(),
                  [](const auto& a, const auto& b) { return a.verdict < b.verdict; });
    } else if (options.sort_by == "file") {
        std::sort(metadata_list.begin(), metadata_list.end(),
                  [](const auto& a, const auto& b) { return a.file_path < b.file_path; });
    } else if (options.sort_by == "size") {
        std::sort(metadata_list.begin(), metadata_list.end(),
                  [](const auto& a, const auto& b) { return a.file_size > b.file_size; });
    }
    
    if (options.limit > 0 && metadata_list.size() > options.limit) {
        metadata_list.resize(options.limit);
    }
    
    return metadata_list;
}

bool ReportStorage::deleteReport(const std::string& report_id) {
    if (!isValidReportId(report_id)) {
        common::Logger::instance().warn("[ReportStorage] Invalid report ID | id={}", report_id);
        return false;
    }
    
    auto report_path = getReportPath(report_id);
    
    if (!std::filesystem::exists(report_path)) {
        common::Logger::instance().warn("[ReportStorage] Report not found | id={}", report_id);
        return false;
    }
    
    try {
        std::filesystem::remove(report_path);
        common::Logger::instance().info("[ReportStorage] Deleted | id={}", report_id);
        return true;
    } catch (const std::exception& e) {
        common::Logger::instance().error("[ReportStorage] Failed to delete | id={} | error={}", 
                                        report_id, e.what());
        return false;
    }
}

ReportStatistics ReportStorage::getStats() {
    ReportStatistics stats{};
    
    auto files = findReportFiles();
    stats.total_reports = files.size();
    
    for (const auto& file : files) {
        auto metadata = parseMetadataFromFile(file);
        if (!metadata) continue;
        
        if (metadata->verdict == "malicious") {
            stats.malicious_count++;
        } else if (metadata->verdict == "clean") {
            stats.clean_count++;
        } else {
            stats.error_count++;
        }
        
        try {
            stats.total_size_bytes += std::filesystem::file_size(file);
        } catch (...) {}
        
        if (!stats.oldest_report || metadata->saved_at < *stats.oldest_report) {
            stats.oldest_report = metadata->saved_at;
        }
        if (!stats.newest_report || metadata->saved_at > *stats.newest_report) {
            stats.newest_report = metadata->saved_at;
        }
    }
    
    return stats;
}

std::string ReportStorage::getReportsDir() const {
    return reports_dir_;
}

std::filesystem::path ReportStorage::getReportPath(const std::string& report_id) {
    return std::filesystem::path(reports_dir_) / (report_id + ".json");
}

std::vector<std::filesystem::path> ReportStorage::findReportFiles() {
    std::vector<std::filesystem::path> files;
    
    if (!std::filesystem::exists(reports_dir_)) {
        return files;
    }
    
    for (const auto& entry : std::filesystem::directory_iterator(reports_dir_)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            files.push_back(entry.path());
        }
    }
    
    return files;
}

std::optional<ReportMetadata> ReportStorage::parseMetadataFromFile(
    const std::filesystem::path& path) {
    
    std::ifstream file(path);
    if (!file) return std::nullopt;
    
    nlohmann::json report_json;
    try {
        file >> report_json;
    } catch (...) {
        return std::nullopt;
    }
    
    if (!report_json.contains("metadata") || !report_json.contains("analysis_result")) {
        return std::nullopt;
    }
    
    ReportMetadata metadata;
    metadata.report_id = path.stem().string();
    
    auto meta = report_json["metadata"];
    auto analysis = report_json["analysis_result"];
    
    metadata.file_path = safeGetString(meta["original_file"], "path");
    metadata.file_size = static_cast<size_t>(safeGetInt(meta["original_file"], "size", 0));
    metadata.file_type = safeGetString(analysis, "file_type");
    
    if (analysis.contains("detection") && analysis["detection"].is_object()) {
        auto detection = analysis["detection"];
        metadata.verdict = safeGetString(detection, "verdict", "error");
        metadata.confidence = safeGetFloat(detection, "confidence", 0.0f);
    } else {
        metadata.verdict = safeGetString(analysis, "verdict", "error");
        metadata.confidence = safeGetFloat(analysis, "confidence", 0.0f);
    }
    
    std::string saved_at_str = safeGetString(meta, "saved_at");
    std::string analyzed_at_str = safeGetString(meta["original_file"], "analyzed_at");
    
    std::tm tm = {};
    std::istringstream ss(saved_at_str);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    if (!ss.fail()) {
        metadata.saved_at = std::chrono::system_clock::from_time_t(std::mktime(&tm));
    }
    
    tm = {};
    ss.clear();
    ss.str(analyzed_at_str);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    if (!ss.fail()) {
        metadata.analyzed_at = std::chrono::system_clock::from_time_t(std::mktime(&tm));
    }
    
    return metadata;
}

bool ReportStorage::matchesFilter(const ReportMetadata& metadata, const ListOptions& options) {
    if (!options.filter_verdict.empty() && metadata.verdict != options.filter_verdict) {
        return false;
    }
    
    if (!options.filter_file_type.empty() && metadata.file_type != options.filter_file_type) {
        return false;
    }
    
    if (!options.filter_date.empty()) {
        auto now = std::chrono::system_clock::now();
        
        if (options.filter_date == "today") {
            auto today = std::chrono::floor<std::chrono::days>(now);
            auto report_day = std::chrono::floor<std::chrono::days>(metadata.saved_at);
            if (today != report_day) return false;
        } else if (options.filter_date == "week") {
            auto week_ago = now - std::chrono::hours(24 * 7);
            if (metadata.saved_at < week_ago) return false;
        } else if (options.filter_date == "month") {
            auto month_ago = now - std::chrono::hours(24 * 30);
            if (metadata.saved_at < month_ago) return false;
        } else {
            std::tm tm = {};
            std::istringstream ss(options.filter_date);
            ss >> std::get_time(&tm, "%Y-%m-%d");
            
            if (!ss.fail()) {
                auto target_time = std::chrono::system_clock::from_time_t(std::mktime(&tm));
                auto target_day = std::chrono::floor<std::chrono::days>(target_time);
                auto report_day = std::chrono::floor<std::chrono::days>(metadata.saved_at);
                
                if (report_day != target_day) return false;
            }
        }
    }
    
    return true;
}

}}