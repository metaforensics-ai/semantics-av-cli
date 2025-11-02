#pragma once

#include "../network/client.hpp"
#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace semantics_av {
namespace report {

struct ReportMetadata {
    std::string report_id;
    std::string file_path;
    std::string verdict;
    float confidence;
    std::string file_type;
    size_t file_size;
    std::chrono::system_clock::time_point saved_at;
    std::chrono::system_clock::time_point analyzed_at;
};

struct ReportStatistics {
    size_t total_reports;
    size_t malicious_count;
    size_t clean_count;
    size_t error_count;
    size_t total_size_bytes;
    std::optional<std::chrono::system_clock::time_point> oldest_report;
    std::optional<std::chrono::system_clock::time_point> newest_report;
};

struct ListOptions {
    std::string sort_by;
    std::string filter_verdict;
    std::string filter_date;
    std::string filter_file_type;
    size_t limit;
};

class ReportStorage {
public:
    ReportStorage();
    explicit ReportStorage(const std::string& custom_dir);
    
    std::string save(const network::AnalysisResult& result, 
                     const std::string& original_path,
                     const std::string& language,
                     size_t file_size = 0);
    
    std::optional<network::AnalysisResult> load(const std::string& report_id);
    
    std::vector<ReportMetadata> list(const ListOptions& options);
    
    bool deleteReport(const std::string& report_id);
    
    ReportStatistics getStats();
    
    std::string getReportsDir() const;

private:
    std::string reports_dir_;
    
    bool isValidReportId(const std::string& report_id) const;
    
    std::string generateReportId(const std::string& sha256, 
                                  const std::chrono::system_clock::time_point& timestamp,
                                  const std::string& verdict);
    
    std::filesystem::path getReportPath(const std::string& report_id);
    
    std::vector<std::filesystem::path> findReportFiles();
    
    std::optional<ReportMetadata> parseMetadataFromFile(const std::filesystem::path& path);
    
    bool matchesFilter(const ReportMetadata& metadata, const ListOptions& options);
    
    void applyCleanupPolicies();
    void cleanupByAge(int days);
    void cleanupByCount(int max);
    
    std::string safeGetString(const nlohmann::json& json, const std::string& key, const std::string& default_value = "") const;
    float safeGetFloat(const nlohmann::json& json, const std::string& key, float default_value = 0.0f) const;
    int safeGetInt(const nlohmann::json& json, const std::string& key, int default_value = 0) const;
};

}}