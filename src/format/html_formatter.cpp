#include "semantics_av/format/html_formatter.hpp"
#include "semantics_av/format/markdown_renderer.hpp"
#include "semantics_av/format/format_utils.hpp"
#include <inja/inja.hpp>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <set>

namespace semantics_av {
namespace format {

HtmlFormatter::HtmlFormatter() {}

std::string HtmlFormatter::format(const network::AnalysisResult& result) {
    inja::Environment env;
    
    auto template_data = prepareTemplateData(result);
    
    std::string html_template = getHtmlTemplate();
    
    return env.render(html_template, template_data);
}

std::string HtmlFormatter::escapeHtml(const std::string& text) {
    std::ostringstream oss;
    for (char c : text) {
        switch (c) {
            case '&': oss << "&amp;"; break;
            case '<': oss << "&lt;"; break;
            case '>': oss << "&gt;"; break;
            case '"': oss << "&quot;"; break;
            case '\'': oss << "&#39;"; break;
            default: oss << c; break;
        }
    }
    return oss.str();
}

std::string HtmlFormatter::formatValue(const nlohmann::json& value) {
    std::string result = formatBasicValue(value);
    
    if (result == "N/A" || result.length() <= 60) {
        return escapeHtml(result);
    }
    
    std::string full_value = result;
    std::string truncated = result.substr(0, 57) + "...";
    
    return "<span title=\"" + escapeHtml(full_value) + "\">" + 
           escapeHtml(truncated) + "</span>";
}

std::string HtmlFormatter::formatJsonForDisplay(const nlohmann::json& value) {
    if (value.is_null()) {
        return "N/A";
    }
    
    std::string json_str = value.dump(2);
    
    std::ostringstream highlighted;
    bool in_string = false;
    bool escaped = false;
    
    for (size_t i = 0; i < json_str.length(); ++i) {
        char c = json_str[i];
        
        if (escaped) {
            highlighted << c;
            escaped = false;
            continue;
        }
        
        if (c == '\\') {
            escaped = true;
            highlighted << c;
            continue;
        }
        
        if (c == '"') {
            if (in_string) {
                highlighted << c << "</span>";
                in_string = false;
            } else {
                highlighted << "<span class=\"json-string\">\"";
                in_string = true;
            }
            continue;
        }
        
        if (in_string) {
            if (c == '<') highlighted << "&lt;";
            else if (c == '>') highlighted << "&gt;";
            else if (c == '&') highlighted << "&amp;";
            else highlighted << c;
            continue;
        }
        
        if (c >= '0' && c <= '9') {
            size_t j = i;
            while (j < json_str.length() && 
                   ((json_str[j] >= '0' && json_str[j] <= '9') || 
                    json_str[j] == '.' || json_str[j] == '-' || 
                    json_str[j] == 'e' || json_str[j] == 'E')) {
                j++;
            }
            highlighted << "<span class=\"json-number\">" 
                       << json_str.substr(i, j - i) << "</span>";
            i = j - 1;
            continue;
        }
        
        if (json_str.substr(i, 4) == "true" || json_str.substr(i, 5) == "false") {
            size_t len = json_str.substr(i, 4) == "true" ? 4 : 5;
            highlighted << "<span class=\"json-boolean\">" 
                       << json_str.substr(i, len) << "</span>";
            i += len - 1;
            continue;
        }
        
        if (json_str.substr(i, 4) == "null") {
            highlighted << "<span class=\"json-null\">null</span>";
            i += 3;
            continue;
        }
        
        if (c == '{' || c == '}' || c == '[' || c == ']') {
            highlighted << "<span class=\"json-bracket\">" << c << "</span>";
            continue;
        }
        
        highlighted << c;
    }
    
    return highlighted.str();
}

std::vector<ComparisonRow> HtmlFormatter::generateComparisonRows(
    const network::AnalysisResult& result
) {
    std::set<std::string> all_paths;
    
    nlohmann::json target_attrs = nlohmann::json::object();
    if (result.static_attributes_json && !result.static_attributes_json->empty()) {
        try {
            target_attrs = nlohmann::json::parse(*result.static_attributes_json);
        } catch (...) {
            target_attrs = nlohmann::json::object();
        }
    }
    
    auto target_flat = flattenAttributes(target_attrs);
    for (const auto& [path, _] : target_flat) {
        all_paths.insert(path);
    }
    
    std::vector<std::map<std::string, FlattenedAttribute>> sample_flats;
    for (const auto& sample : result.intelligence.similar_samples) {
        nlohmann::json sample_attrs = nlohmann::json::object();
        if (sample.static_attributes_json && !sample.static_attributes_json->empty()) {
            try {
                sample_attrs = nlohmann::json::parse(*sample.static_attributes_json);
            } catch (...) {
                sample_attrs = nlohmann::json::object();
            }
        }
        auto sample_flat = flattenAttributes(sample_attrs);
        sample_flats.push_back(sample_flat);
        
        for (const auto& [path, _] : sample_flat) {
            all_paths.insert(path);
        }
    }
    
    std::vector<std::string> sorted_paths(all_paths.begin(), all_paths.end());
    
    std::sort(sorted_paths.begin(), sorted_paths.end(), [](const std::string& a, const std::string& b) {
        auto get_category = [](const std::string& path) -> std::string {
            size_t pos = path.find('.');
            return pos != std::string::npos ? path.substr(0, pos) : path;
        };
        
        std::string cat_a = get_category(a);
        std::string cat_b = get_category(b);
        
        if (cat_a != cat_b) {
            return cat_a < cat_b;
        }
        return a < b;
    });
    
    std::vector<ComparisonRow> rows;
    
    for (const auto& path : sorted_paths) {
        ComparisonRow row;
        row.attribute_path = path;
        row.is_complex = false;
        
        int non_na_count = 0;
        int total_count = 1 + static_cast<int>(sample_flats.size());
        
        auto target_it = target_flat.find(path);
        if (target_it != target_flat.end()) {
            row.target_value = target_it->second.display_value;
            row.is_complex = target_it->second.is_complex;
            row.target_json = target_it->second.raw_value;
            non_na_count++;
        } else {
            row.target_value = "N/A";
            row.target_json = nlohmann::json(nullptr);
        }
        
        for (const auto& sample_flat : sample_flats) {
            auto sample_it = sample_flat.find(path);
            if (sample_it != sample_flat.end()) {
                row.sample_values.push_back(sample_it->second.display_value);
                row.sample_jsons.push_back(sample_it->second.raw_value);
                if (sample_it->second.is_complex) {
                    row.is_complex = true;
                }
                non_na_count++;
            } else {
                row.sample_values.push_back("N/A");
                row.sample_jsons.push_back(nlohmann::json(nullptr));
            }
        }
        
        float coverage = static_cast<float>(non_na_count) / total_count;
        
        if (coverage >= 0.5f) {
            rows.push_back(row);
        }
    }
    
    return rows;
}

std::string getLabelClass(const std::string& label) {
    std::string label_lower = label;
    std::transform(label_lower.begin(), label_lower.end(), label_lower.begin(), ::tolower);
    
    if (label_lower == "malicious") return "label-malicious";
    if (label_lower == "suspicious") return "label-suspicious";
    if (label_lower == "clean") return "label-clean";
    if (label_lower == "unknown") return "label-unknown";
    return "label-unknown";
}

nlohmann::json HtmlFormatter::prepareTemplateData(const network::AnalysisResult& result) {
    nlohmann::json data;
    
    bool target_confirmed = hasGroundTruthLabel(result.tags);
    
    data["target_confirmed"] = target_confirmed;
    data["verdict"] = result.verdict;
    
    std::string verdict_for_class = result.verdict;
    data["verdict_class"] = "verdict-" + verdict_for_class;
    
    data["confidence_percent"] = formatPercentage(result.confidence);
    
    std::string verdict_display = result.verdict + " (" + formatPercentage(result.confidence) + "%)";
    data["verdict_with_confidence"] = verdict_display;
    data["file_type"] = result.file_type;
    data["analysis_timestamp"] = result.analysis_timestamp;
    
    data["file_hashes"]["md5"] = result.file_hashes.count("md5") ? result.file_hashes.at("md5") : "N/A";
    data["file_hashes"]["sha1"] = result.file_hashes.count("sha1") ? result.file_hashes.at("sha1") : "N/A";
    data["file_hashes"]["sha256"] = result.file_hashes.count("sha256") ? result.file_hashes.at("sha256") : "N/A";
    
    std::string target_label = result.verdict;
    data["target_label"] = target_label;
    data["target_label_class"] = getLabelClass(target_label);
    data["target_label_upper"] = target_label;
    std::transform(data["target_label_upper"].get_ref<std::string&>().begin(), 
                  data["target_label_upper"].get_ref<std::string&>().end(),
                  data["target_label_upper"].get_ref<std::string&>().begin(), ::toupper);
    
    std::string target_header_text;
    if (target_confirmed) {
        target_header_text = data["target_label_upper"].get<std::string>() + "†";
    } else {
        target_header_text = data["target_label_upper"].get<std::string>() + "* " + 
                            data["confidence_percent"].get<std::string>() + "%";
    }
    data["target_header_text"] = target_header_text;
    
    data["tags"] = nlohmann::json::array();
    bool has_tags = false;
    for (const auto& tag : result.tags) {
        if (tag.find("label:") != 0) {
            nlohmann::json tag_obj;
            tag_obj["name"] = tag;
            data["tags"].push_back(tag_obj);
            has_tags = true;
        }
    }
    data["has_tags"] = has_tags;
    
    data["signature"] = result.signature ? *result.signature : "N/A";
    
    data["similar_samples"] = nlohmann::json::array();
    for (size_t i = 0; i < result.intelligence.similar_samples.size(); ++i) {
        const auto& sample = result.intelligence.similar_samples[i];
        nlohmann::json sample_data;
        
        sample_data["index"] = i + 1;
        sample_data["md5"] = sample.file_hashes.count("md5") ? sample.file_hashes.at("md5") : "N/A";
        sample_data["sha1"] = sample.file_hashes.count("sha1") ? sample.file_hashes.at("sha1") : "N/A";
        sample_data["sha256"] = sample.file_hashes.count("sha256") ? sample.file_hashes.at("sha256") : "N/A";
        sample_data["similarity_percent"] = formatPercentage(sample.similarity_score);
        sample_data["signature"] = sample.signature ? *sample.signature : "N/A";
        
        std::string label = extractLabelFromTags(sample.tags);
        sample_data["label"] = label;
        sample_data["label_class"] = getLabelClass(label);
        sample_data["label_upper"] = label;
        std::transform(sample_data["label_upper"].get_ref<std::string&>().begin(), 
                      sample_data["label_upper"].get_ref<std::string&>().end(),
                      sample_data["label_upper"].get_ref<std::string&>().begin(), ::toupper);
        
        sample_data["tags"] = nlohmann::json::array();
        for (const auto& tag : sample.tags) {
            if (tag.find("label:") != 0) {
                nlohmann::json tag_obj;
                tag_obj["name"] = tag;
                sample_data["tags"].push_back(tag_obj);
            }
        }
        
        data["similar_samples"].push_back(sample_data);
    }
    
    data["show_confirmed_legend"] = target_confirmed;
    data["show_predicted_legend"] = !target_confirmed;
    
    auto comparison_rows = generateComparisonRows(result);
    data["comparison_rows"] = nlohmann::json::array();
    for (const auto& row : comparison_rows) {
        nlohmann::json row_data;
        row_data["attribute"] = row.attribute_path;
        row_data["target"] = row.target_value;
        row_data["is_complex"] = row.is_complex;
        
        if (row.is_complex) {
            row_data["target_json"] = formatJsonForDisplay(row.target_json);
            row_data["sample_jsons"] = nlohmann::json::array();
            for (const auto& json_val : row.sample_jsons) {
                row_data["sample_jsons"].push_back(formatJsonForDisplay(json_val));
            }
        }
        
        row_data["samples"] = nlohmann::json::array();
        for (size_t i = 0; i < row.sample_values.size(); ++i) {
            nlohmann::json sample_cell;
            sample_cell["value"] = row.sample_values[i];
            
            bool target_is_na = (row.target_value == "N/A");
            bool sample_is_na = (row.sample_values[i] == "N/A");
            
            bool exact_match = false;
            bool mismatch = false;
            
            if (target_is_na && sample_is_na) {
                exact_match = true;
            } else if (!target_is_na && !sample_is_na) {
                if (row.is_complex) {
                    exact_match = (row.target_json == row.sample_jsons[i]);
                } else {
                    exact_match = (row.target_value == row.sample_values[i]);
                }
                mismatch = !exact_match;
            } else {
                mismatch = true;
            }
            
            sample_cell["matches_target"] = exact_match;
            sample_cell["mismatches_target"] = mismatch;
            row_data["samples"].push_back(sample_cell);
        }
        
        data["comparison_rows"].push_back(row_data);
    }
    
    auto format_label_stat = [](const network::LabelStatistics& stats) -> nlohmann::json {
        nlohmann::json json;
        json["count"] = stats.count;
        json["max_similarity"] = stats.max_similarity ? formatPercentage(*stats.max_similarity) : "N/A";
        json["avg_similarity"] = stats.avg_similarity ? formatPercentage(*stats.avg_similarity) : "N/A";
        return json;
    };
    
    data["statistics"]["processed_samples"] = result.intelligence.statistics.processed_samples;
    data["statistics"]["malicious_count"] = result.intelligence.statistics.malicious.count;
    data["statistics"]["suspicious_count"] = result.intelligence.statistics.suspicious.count;
    data["statistics"]["clean_count"] = result.intelligence.statistics.clean.count;
    data["statistics"]["unknown_count"] = result.intelligence.statistics.unknown.count;
    
    auto mal_stats = format_label_stat(result.intelligence.statistics.malicious);
    data["statistics"]["malicious_max_similarity"] = mal_stats["max_similarity"];
    data["statistics"]["malicious_avg_similarity"] = mal_stats["avg_similarity"];
    
    auto sus_stats = format_label_stat(result.intelligence.statistics.suspicious);
    data["statistics"]["suspicious_max_similarity"] = sus_stats["max_similarity"];
    data["statistics"]["suspicious_avg_similarity"] = sus_stats["avg_similarity"];
    
    auto cln_stats = format_label_stat(result.intelligence.statistics.clean);
    data["statistics"]["clean_max_similarity"] = cln_stats["max_similarity"];
    data["statistics"]["clean_avg_similarity"] = cln_stats["avg_similarity"];
    
    auto unk_stats = format_label_stat(result.intelligence.statistics.unknown);
    data["statistics"]["unknown_max_similarity"] = unk_stats["max_similarity"];
    data["statistics"]["unknown_avg_similarity"] = unk_stats["avg_similarity"];
    
    std::vector<std::pair<std::string, network::SignatureStatistics>> sig_vec;
    for (const auto& [sig_name, sig_stat] : result.intelligence.statistics.by_signature) {
        sig_vec.push_back({sig_name, sig_stat});
    }
    
    std::sort(sig_vec.begin(), sig_vec.end(), 
        [](const auto& a, const auto& b) {
            return a.second.max_similarity > b.second.max_similarity;
        });
    
    data["signatures"] = nlohmann::json::array();
    for (const auto& [sig_name, sig_stat] : sig_vec) {
        nlohmann::json sig_data;
        sig_data["name"] = sig_name;
        sig_data["count"] = sig_stat.count;
        sig_data["max_similarity"] = formatPercentage(sig_stat.max_similarity);
        sig_data["avg_similarity"] = formatPercentage(sig_stat.avg_similarity);
        data["signatures"].push_back(sig_data);
    }
    
    data["has_natural_language_report"] = !result.natural_language_report.empty();
    if (!result.natural_language_report.empty()) {
        MarkdownRenderer renderer;
        data["report_html"] = renderer.render(result.natural_language_report);
        data["report_text_raw"] = escapeHtml(result.natural_language_report);
    } else {
        data["report_html"] = "";
        data["report_text_raw"] = "";
    }
    
    return data;
}

const char* HtmlFormatter::getHtmlTemplate() const {
    return R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SemanticsAV Intelligence Report - {{ file_hashes.md5 }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #212121;
            background: #fafafa;
            padding: 20px;
        }
        
        .container {
            max-width: 1800px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        header {
            background: #1976d2;
            color: white;
            padding: 30px 40px;
        }
        
        header h1 {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 10px;
        }
        
        header .timestamp {
            opacity: 0.85;
            font-size: 13px;
        }
        
        section {
            padding: 30px 40px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        section:last-child {
            border-bottom: none;
        }
        
        h2 {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 20px;
            color: #1976d2;
        }
        
        h3 {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 15px;
            margin-top: 30px;
            color: #424242;
        }
        
        .legend {
            background: #f5f9ff;
            border-left: 4px solid #1976d2;
            padding: 12px 15px;
            margin-bottom: 20px;
            font-size: 13px;
            color: #424242;
        }
        
        .legend-title {
            font-weight: 600;
            margin-bottom: 5px;
        }
        
        .hash-section {
            margin-bottom: 25px;
            border: 2px solid #1976d2;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .hash-header {
            background: #1976d2;
            color: white;
            padding: 10px 15px;
            font-weight: 600;
            font-size: 13px;
        }
        
        .hash-rows {
            background: white;
        }
        
        .hash-row {
            display: flex;
            padding: 10px 15px;
            border-bottom: 1px solid #f5f5f5;
        }
        
        .hash-row:last-child {
            border-bottom: none;
        }
        
        .hash-label {
            font-weight: 600;
            color: #757575;
            min-width: 70px;
            font-size: 12px;
        }
        
        .hash-value {
            font-family: 'Courier New', Consolas, Monaco, monospace;
            color: #424242;
            font-size: 12px;
            word-break: break-all;
            flex: 1;
            cursor: pointer;
        }
        
        .hash-value:hover {
            background: #f5f5f5;
            padding: 2px 4px;
            margin: -2px -4px;
            border-radius: 2px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
        }
        
        .summary-item {
            padding: 15px;
            background: #f5f5f5;
            border-radius: 4px;
        }
        
        .summary-label {
            font-size: 12px;
            text-transform: uppercase;
            color: #757575;
            margin-bottom: 5px;
            font-weight: 500;
        }
        
        .summary-value {
            font-size: 16px;
            font-weight: 500;
        }
        
        .summary-value.verdict-value {
            font-size: 14px;
        }
        
        .verdict-malicious {
            color: #c62828;
            font-weight: 700;
            text-transform: uppercase;
        }
        
        .verdict-clean {
            color: #00897b;
            font-weight: 700;
            text-transform: uppercase;
        }
        
        .verdict-suspicious {
            color: #e65100;
            font-weight: 700;
            text-transform: uppercase;
        }
        
        .verdict-unknown {
            color: #616161;
            font-weight: 700;
            text-transform: uppercase;
        }
        
        .tags-in-summary {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }
        
        .tag {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
            background: #f5f5f5;
            color: #616161;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        
        .stat-box {
            padding: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            background: #fafafa;
        }
        
        .stat-label {
            font-size: 13px;
            color: #757575;
            margin-bottom: 8px;
            font-weight: 500;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: 700;
            line-height: 1;
        }
        
        .stat-details {
            font-size: 12px;
            color: #757575;
            margin-top: 8px;
        }
        
        .signature-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        
        .signature-item {
            display: flex;
            align-items: center;
            padding: 16px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            background: white;
            transition: all 0.2s;
        }
        
        .signature-item:hover {
            border-color: #1976d2;
            box-shadow: 0 2px 8px rgba(25, 118, 210, 0.15);
        }
        
        .signature-count {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-width: 100px;
            padding: 12px;
            background: #1976d2;
            color: white;
            border-radius: 4px;
            margin-right: 20px;
        }
        
        .signature-count-number {
            font-size: 32px;
            font-weight: 700;
            line-height: 1;
        }
        
        .signature-count-label {
            font-size: 11px;
            text-transform: uppercase;
            margin-top: 4px;
            opacity: 0.9;
        }
        
        .signature-info {
            flex: 1;
        }
        
        .signature-name {
            font-size: 16px;
            font-weight: 700;
            color: #212121;
            margin-bottom: 8px;
        }
        
        .signature-metrics {
            display: flex;
            gap: 20px;
            align-items: center;
        }
        
        .signature-metric {
            display: flex;
            flex-direction: column;
        }
        
        .signature-metric-label {
            font-size: 11px;
            color: #757575;
            text-transform: uppercase;
            margin-bottom: 2px;
        }
        
        .signature-metric-value {
            font-size: 16px;
            font-weight: 600;
            color: #1976d2;
        }
        
        .comparison-wrapper {
            overflow-x: auto;
            margin-top: 20px;
        }
        
        .comparison-table {
            width: 100%;
            border-collapse: collapse;
            min-width: 1350px;
            table-layout: fixed;
        }
        
        .comparison-table th,
        .comparison-table td {
            padding: 9px;
            text-align: left;
            border: 1px solid #e0e0e0;
            font-size: 13px;
            word-wrap: break-word;
            overflow-wrap: break-word;
            word-break: break-word;
        }
        
        .comparison-table th {
            background: #f5f5f5;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
            box-shadow: 0 2px 2px rgba(0,0,0,0.05);
        }
        
        .comparison-table th:first-child,
        .comparison-table td:first-child {
            position: sticky;
            left: 0;
            background: white;
            z-index: 5;
            font-weight: 500;
            max-width: 200px;
        }
        
        .comparison-table th:first-child {
            z-index: 11;
            background: #f5f5f5;
        }
        
        .comparison-table th:nth-child(2),
        .comparison-table td:nth-child(2) {
            border-left: 3px solid #1976d2;
            border-right: 3px solid #1976d2;
        }
        
        .comparison-table td:nth-child(2) {
            font-weight: 500;
        }
        
        .sample-header-cell {
            padding: 9px !important;
            vertical-align: top;
            min-width: 215px;
            max-width: 230px;
            cursor: pointer;
            position: relative;
        }
        
        .sample-header-cell:hover {
            background: #f9f9f9 !important;
        }
        
        .sample-header-cell.label-malicious {
            background: #ffebee !important;
            border-top: 3px solid #c62828;
        }
        
        .sample-header-cell.label-suspicious {
            background: #fff3e0 !important;
            border-top: 3px solid #e65100;
        }
        
        .sample-header-cell.label-clean {
            background: #e0f2f1 !important;
            border-top: 3px solid #00897b;
        }
        
        .sample-header-cell.label-unknown {
            background: #f5f5f5 !important;
            border-top: 3px solid #616161;
        }
        
        .sample-header-stack {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        
        .header-sample-number {
            font-size: 13px;
            font-weight: 700;
            color: #212121;
        }
        
        .header-similarity {
            font-size: 17px;
            font-weight: 700;
            color: #1976d2;
        }
        
        .header-label-badge {
            display: inline-block;
            padding: 4px 9px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            align-self: flex-start;
        }
        
        .header-label-badge.label-malicious {
            background: #c62828;
            color: white;
        }
        
        .header-label-badge.label-suspicious {
            background: #e65100;
            color: white;
        }
        
        .header-label-badge.label-clean {
            background: #00897b;
            color: white;
        }
        
        .header-label-badge.label-unknown {
            background: #616161;
            color: white;
        }
        
        .header-signature {
            font-size: 12px;
            font-weight: 600;
            color: #424242;
            padding: 5px 0;
        }
        
        .header-signature::before {
            content: "\25A0 ";
            font-size: 10px;
            margin-right: 4px;
            color: #757575;
        }
        
        .header-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            margin-top: 4px;
        }
        
        .header-tags .tag {
            padding: 2px 7px;
            font-size: 10px;
        }
        
        .comparison-table tr:hover {
            background: #f9f9f9;
        }
        
        .comparison-table tr.expandable {
            cursor: pointer;
        }
        
        .comparison-table tr.expandable td:first-child::before {
            content: '\25B6';
            display: inline-block;
            margin-right: 8px;
            font-size: 10px;
            transition: transform 0.2s;
            color: #1976d2;
        }
        
        .comparison-table tr.expandable.expanded td:first-child::before {
            transform: rotate(90deg);
        }
        
        .comparison-table td span[title] {
            cursor: help;
            border-bottom: 1px dotted #999;
        }
        
        .comparison-table td.match-highlight {
            background: #e8f5e9;
            border-left: 2px solid #4caf50;
        }
        
        .comparison-table td.mismatch-highlight {
            background: #fffde7;
            border-left: 2px solid #f9a825;
        }
        
        .detail-row {
            display: none;
        }
        
        .detail-row.visible {
            display: table-row;
        }
        
        .detail-row td {
            background: #fafafa;
            padding: 0;
            border-top: none;
        }
        
        .detail-content {
            padding: 20px;
        }
        
        .json-comparison-table {
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
        }
        
        .json-comparison-table th {
            background: #f5f5f5 !important;
            padding: 11px;
            text-align: left;
            font-weight: 600;
            border: 1px solid #e0e0e0 !important;
            font-size: 13px;
            color: #424242 !important;
            width: 16.66%;
        }
        
        .json-comparison-table th.target-header {
            background: #1976d2 !important;
            color: white !important;
            border: 1px solid #1565c0 !important;
        }
        
        .json-comparison-table td {
            padding: 0;
            border: 1px solid #e0e0e0 !important;
            vertical-align: top;
            width: 16.66%;
        }
        
        .json-viewer {
            background: #263238;
            color: #aed581;
            padding: 15px;
            overflow-x: auto;
            font-family: 'Courier New', Consolas, Monaco, monospace;
            font-size: 12px;
            line-height: 1.5;
            max-height: 400px;
            overflow-y: auto;
            box-sizing: border-box;
            width: 100%;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        
        .json-viewer pre {
            margin: 0;
            white-space: pre-wrap;
            word-break: break-word;
            overflow-wrap: break-word;
        }
        
        .json-viewer.json-viewer-target {
            background: #f5f5f5;
            color: #212121;
            border: 3px solid #1976d2;
            box-shadow: 0 0 0 4px rgba(25, 118, 210, 0.1);
        }
        
        .json-viewer.json-viewer-target .json-string { color: #1565c0; }
        .json-viewer.json-viewer-target .json-number { color: #c62828; }
        .json-viewer.json-viewer-target .json-boolean { color: #6a1b9a; }
        .json-viewer.json-viewer-target .json-null { color: #424242; }
        .json-viewer.json-viewer-target .json-bracket { color: #00695c; font-weight: bold; }
        
        .json-string { color: #c3e88d; }
        .json-number { color: #f78c6c; }
        .json-boolean { color: #c792ea; }
        .json-null { color: #82aaff; }
        .json-bracket { color: #89ddff; font-weight: bold; }
        
        .hash-modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
            animation: fadeIn 0.2s;
        }
        
        .hash-modal.active {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .hash-modal-content {
            background: white;
            padding: 30px;
            border-radius: 8px;
            max-width: 700px;
            width: 90%;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            animation: slideIn 0.3s;
        }
        
        @keyframes slideIn {
            from {
                transform: translateY(-50px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }
        
        .hash-modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #1976d2;
        }
        
        .hash-modal-title {
            font-size: 18px;
            font-weight: 700;
            color: #1976d2;
        }
        
        .hash-modal-close {
            font-size: 28px;
            font-weight: bold;
            color: #757575;
            cursor: pointer;
            line-height: 1;
            border: none;
            background: none;
            padding: 0;
            width: 30px;
            height: 30px;
        }
        
        .hash-modal-close:hover {
            color: #212121;
        }
        
        .hash-modal-row {
            display: flex;
            align-items: center;
            padding: 12px 0;
            border-bottom: 1px solid #f5f5f5;
        }
        
        .hash-modal-row:last-child {
            border-bottom: none;
        }
        
        .hash-modal-label {
            font-weight: 600;
            color: #757575;
            min-width: 80px;
            font-size: 13px;
        }
        
        .hash-modal-value {
            font-family: 'Courier New', Consolas, Monaco, monospace;
            color: #424242;
            font-size: 13px;
            word-break: break-all;
            flex: 1;
            margin-right: 10px;
        }
        
        .hash-copy-btn {
            padding: 6px 12px;
            background: #1976d2;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: background 0.2s;
            white-space: nowrap;
        }
        
        .hash-copy-btn:hover {
            background: #1565c0;
        }
        
        .hash-copy-btn.copied {
            background: #4caf50;
        }
        
        .report-divider {
            text-align: center;
            margin: 40px 0 0 0;
            padding: 0 40px;
            position: relative;
        }
        
        .divider-label {
            display: inline-block;
            position: relative;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #1976d2;
            padding: 0 20px;
            background: white;
            z-index: 1;
        }
        
        .divider-label::before,
        .divider-label::after {
            content: '';
            position: absolute;
            top: 50%;
            height: 1px;
            background: #e0e0e0;
            width: 500px;
        }
        
        .divider-label::before {
            right: 100%;
            margin-right: 20px;
        }
        
        .divider-label::after {
            left: 100%;
            margin-left: 20px;
        }
        
        .natural-language-section {
            padding: 40px;
            background: #fafafa;
            border-bottom: none;
            position: relative;
        }
        
        .copy-report-btn {
            position: absolute;
            top: 40px;
            right: 40px;
            padding: 8px 16px;
            background: #1976d2;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.2s;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .copy-report-btn:hover {
            background: #1565c0;
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        
        .copy-report-btn:active {
            transform: translateY(1px);
        }
        
        .copy-report-btn.copied {
            background: #4caf50;
        }
        
        .report-content {
            margin-top: 20px;
        }
        
        .report-content > h1:first-child,
        .report-content > h2:first-child {
            margin-top: 0;
            font-size: 24px;
            color: #1976d2;
            padding-bottom: 15px;
            margin-bottom: 25px;
        }
        
        .report-content > h3:first-child {
            margin-top: 0;
            font-size: 20px;
            color: #424242;
            padding-bottom: 12px;
            margin-bottom: 20px;
        }
        
        .report-content h2 {
            font-size: 20px;
            margin-top: 30px;
            margin-bottom: 15px;
            color: #1976d2;
        }
        
        .report-content h3 {
            font-size: 18px;
            margin-top: 20px;
            margin-bottom: 10px;
            color: #424242;
        }
        
        .report-content p {
            margin-bottom: 15px;
            line-height: 1.8;
        }
        
        .report-content ul,
        .report-content ol {
            margin-left: 25px;
            margin-bottom: 15px;
            line-height: 1.8;
        }
        
        .report-content li {
            margin-bottom: 8px;
            padding-left: 5px;
        }
        
        .report-content li > ul,
        .report-content li > ol {
            margin-top: 8px;
            margin-bottom: 8px;
        }
        
        .report-content strong {
            font-weight: 600;
            color: #212121;
        }
        
        .report-content code {
            font-family: 'Courier New', Consolas, Monaco, monospace;
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 13px;
        }
        
        .report-content blockquote {
            border-left: 4px solid #1976d2;
            padding-left: 15px;
            margin: 15px 0;
            color: #616161;
        }
        
        .report-content table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 14px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            background: white;
        }
        
        .report-content thead {
            background: #1976d2;
            color: white;
        }
        
        .report-content th {
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
            border: 1px solid #1565c0;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .report-content td {
            padding: 10px 15px;
            border: 1px solid #e0e0e0;
            text-align: left;
            line-height: 1.6;
            word-wrap: break-word;
            overflow-wrap: break-word;
            max-width: 400px;
        }
        
        .report-content tbody tr:nth-child(even) {
            background: #f9f9f9;
        }
        
        .report-content tbody tr:hover {
            background: #e3f2fd;
            transition: background 0.2s;
        }
        
        .report-content table code {
            background: #263238;
            color: #aed581;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
        }
        
        @media (max-width: 1200px) {
            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .copy-report-btn {
                position: static;
                display: block;
                margin: 0 auto 20px auto;
            }
            
            .report-content table {
                display: block;
                overflow-x: auto;
                white-space: nowrap;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SemanticsAV Intelligence Report</h1>
            <div class="timestamp">Generated on {{ analysis_timestamp }}</div>
        </header>
        
        <section>
            <h2>Detection Summary</h2>
            
            <div class="hash-section">
                <div class="hash-header">File Hashes</div>
                <div class="hash-rows">
                    <div class="hash-row">
                        <div class="hash-label">MD5</div>
                        <div class="hash-value" title="Click to copy">{{ file_hashes.md5 }}</div>
                    </div>
                    <div class="hash-row">
                        <div class="hash-label">SHA1</div>
                        <div class="hash-value" title="Click to copy">{{ file_hashes.sha1 }}</div>
                    </div>
                    <div class="hash-row">
                        <div class="hash-label">SHA256</div>
                        <div class="hash-value" title="Click to copy">{{ file_hashes.sha256 }}</div>
                    </div>
                </div>
            </div>
            
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-label">Verdict (Confidence)</div>
                    <div class="summary-value verdict-value {{ verdict_class }}">{{ verdict_with_confidence }}</div>
                </div>
                <div class="summary-item">
                    <div class="summary-label">File Type</div>
                    <div class="summary-value">{{ file_type }}</div>
                </div>
                <div class="summary-item">
                    <div class="summary-label">Signature</div>
                    <div class="summary-value">{{ signature }}</div>
                </div>
                <div class="summary-item">
                    <div class="summary-label">Tags</div>
                    {% if has_tags %}
                    <div class="tags-in-summary">
                        {% for tag in tags %}
                        <span class="tag">{{ tag.name }}</span>
                        {% endfor %}
                    </div>
                    {% else %}
                    <div class="summary-value">N/A</div>
                    {% endif %}
                </div>
            </div>
        </section>
        
        <section>
            <h2>Intelligence Statistics</h2>
            
            <h3>Label Distribution</h3>
            
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-label">Total Samples</div>
                    <div class="stat-value" style="color: #1976d2;">{{ statistics.processed_samples }}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Malicious</div>
                    <div class="stat-value" style="color: #c62828;">{{ statistics.malicious_count }}</div>
                    {% if statistics.malicious_max_similarity != "N/A" %}
                    <div class="stat-details">
                        Max: {{ statistics.malicious_max_similarity }}% | Avg: {{ statistics.malicious_avg_similarity }}%
                    </div>
                    {% endif %}
                </div>
                <div class="stat-box">
                    <div class="stat-label">Suspicious</div>
                    <div class="stat-value" style="color: #e65100;">{{ statistics.suspicious_count }}</div>
                    {% if statistics.suspicious_max_similarity != "N/A" %}
                    <div class="stat-details">
                        Max: {{ statistics.suspicious_max_similarity }}% | Avg: {{ statistics.suspicious_avg_similarity }}%
                    </div>
                    {% endif %}
                </div>
                <div class="stat-box">
                    <div class="stat-label">Clean</div>
                    <div class="stat-value" style="color: #00897b;">{{ statistics.clean_count }}</div>
                    {% if statistics.clean_max_similarity != "N/A" %}
                    <div class="stat-details">
                        Max: {{ statistics.clean_max_similarity }}% | Avg: {{ statistics.clean_avg_similarity }}%
                    </div>
                    {% endif %}
                </div>
                <div class="stat-box">
                    <div class="stat-label">Unknown</div>
                    <div class="stat-value" style="color: #616161;">{{ statistics.unknown_count }}</div>
                    {% if statistics.unknown_max_similarity != "N/A" %}
                    <div class="stat-details">
                        Max: {{ statistics.unknown_max_similarity }}% | Avg: {{ statistics.unknown_avg_similarity }}%
                    </div>
                    {% endif %}
                </div>
            </div>
            
            {% if length(signatures) > 0 %}
            <h3>Top Signatures</h3>
            <div class="signature-list">
                {% for sig in signatures %}
                <div class="signature-item">
                    <div class="signature-count">
                        <div class="signature-count-number">{{ sig.count }}</div>
                        <div class="signature-count-label">Samples</div>
                    </div>
                    <div class="signature-info">
                        <div class="signature-name">{{ sig.name }}</div>
                        <div class="signature-metrics">
                            <div class="signature-metric">
                                <div class="signature-metric-label">Max Similarity</div>
                                <div class="signature-metric-value">{{ sig.max_similarity }}%</div>
                            </div>
                            <div class="signature-metric">
                                <div class="signature-metric-label">Avg Similarity</div>
                                <div class="signature-metric-value">{{ sig.avg_similarity }}%</div>
                            </div>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
        </section>
        
        {% if length(similar_samples) > 0 %}
        <section>
            <h2>Attribute Comparison Matrix</h2>
            <p style="color: #424242; font-size: 14px; margin-bottom: 10px; line-height: 1.6;">
                Compare static attributes between the target file and {{ length(similar_samples) }} similar samples from our threat intelligence database.
            </p>
            
            {% if show_confirmed_legend or show_predicted_legend %}
            <div class="legend">
                <div class="legend-title">Legend:</div>
                {% if show_confirmed_legend %}
                <div>† = Confirmed label (verified malicious/clean from intelligence)</div>
                {% endif %}
                {% if show_predicted_legend %}
                <div>* = Predicted label (suspicious/unknown or not in intelligence database)</div>
                {% endif %}
            </div>
            {% endif %}
            
            <div class="comparison-wrapper">
                <table class="comparison-table">
                    <thead>
                        <tr>
                            <th>Attribute</th>
                            <th class="sample-header-cell {{ target_label_class }}" data-sample-type="target">
                                <div class="sample-header-stack">
                                    <div class="header-sample-number">Target</div>
                                    <div class="header-similarity">Baseline</div>
                                    <div class="header-label-badge {{ target_label_class }}">{{ target_header_text }}</div>
                                    <div class="header-signature">{{ signature }}</div>
                                    {% if has_tags %}
                                    <div class="header-tags">
                                        {% for tag in tags %}
                                        <span class="tag">{{ tag.name }}</span>
                                        {% endfor %}
                                    </div>
                                    {% endif %}
                                </div>
                            </th>
                            {% for sample in similar_samples %}
                            <th class="sample-header-cell {{ sample.label_class }}" data-sample-index="{{ sample.index }}">
                                <div class="sample-header-stack">
                                    <div class="header-sample-number">Sample #{{ sample.index }}</div>
                                    <div class="header-similarity">{{ sample.similarity_percent }}%</div>
                                    <div class="header-label-badge {{ sample.label_class }}">{{ sample.label_upper }}</div>
                                    <div class="header-signature">{{ sample.signature }}</div>
                                    {% if length(sample.tags) > 0 %}
                                    <div class="header-tags">
                                        {% for tag in sample.tags %}
                                        <span class="tag">{{ tag.name }}</span>
                                        {% endfor %}
                                    </div>
                                    {% endif %}
                                </div>
                            </th>
                            {% endfor %}
                        </tr>
                    </thead>
                    <tbody>
                        {% for row in comparison_rows %}
                        <tr class="{% if row.is_complex %}expandable{% endif %}" data-row-id="row-{{ loop.index }}">
                            <td>{{ row.attribute }}</td>
                            <td>{{ row.target }}</td>
                            {% for sample_cell in row.samples %}
                            <td
                            {% if sample_cell.matches_target %}
                            class="match-highlight"
                            {% else %}
                            {% if sample_cell.mismatches_target %}
                            class="mismatch-highlight"
                            {% endif %}
                            {% endif %}
                            >{{ sample_cell.value }}</td>
                            {% endfor %}
                        </tr>
                        {% if row.is_complex %}
                        <tr class="detail-row" id="detail-row-{{ loop.index }}">
                            <td colspan="{{ 2 + length(similar_samples) }}">
                                <div class="detail-content">
                                    <table class="json-comparison-table">
                                        <thead>
                                            <tr>
                                                <th class="target-header">Target</th>
                                                {% for sample in similar_samples %}
                                                <th>Sample #{{ sample.index }} ({{ sample.similarity_percent }}%)</th>
                                                {% endfor %}
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr>
                                                <td>
                                                    <div class="json-viewer json-viewer-target">
                                                        <pre>{{ row.target_json }}</pre>
                                                    </div>
                                                </td>
                                                {% for sample_json in row.sample_jsons %}
                                                <td>
                                                    <div class="json-viewer">
                                                        <pre>{{ sample_json }}</pre>
                                                    </div>
                                                </td>
                                                {% endfor %}
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </td>
                        </tr>
                        {% endif %}
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>
        {% endif %}
        
        {% if has_natural_language_report %}
        <div class="report-divider">
            <span class="divider-label">Natural Language Report</span>
        </div>
        <section class="natural-language-section">
            <button class="copy-report-btn" id="copyReportBtn">Copy Report</button>
            <div class="report-content">
                {{ report_html }}
            </div>
            <textarea id="reportTextRaw" style="position: absolute; left: -9999px;">{{ report_text_raw }}</textarea>
        </section>
        {% endif %}
    </div>
    
    <div id="hashModal" class="hash-modal">
        <div class="hash-modal-content">
            <div class="hash-modal-header">
                <h3 class="hash-modal-title" id="hashModalTitle">File Hashes</h3>
                <button class="hash-modal-close" id="hashModalClose">&times;</button>
            </div>
            <div id="hashModalBody"></div>
        </div>
    </div>
    
    <script>
        var hashData = {
            target: {
                md5: "{{ file_hashes.md5 }}",
                sha1: "{{ file_hashes.sha1 }}",
                sha256: "{{ file_hashes.sha256 }}"
            },
            samples: {
                {% for sample in similar_samples %}
                "{{ sample.index }}": {
                    md5: "{{ sample.md5 }}",
                    sha1: "{{ sample.sha1 }}",
                    sha256: "{{ sample.sha256 }}"
                }{% if not loop.is_last %},{% endif %}
                {% endfor %}
            }
        };
        
        document.addEventListener('DOMContentLoaded', function() {
            var expandableRows = document.querySelectorAll('tr.expandable');
            
            expandableRows.forEach(function(row) {
                row.addEventListener('click', function() {
                    var rowId = this.getAttribute('data-row-id');
                    var detailRowId = 'detail-' + rowId;
                    var detailRow = document.getElementById(detailRowId);
                    
                    if (detailRow) {
                        var isExpanded = this.classList.contains('expanded');
                        
                        if (isExpanded) {
                            this.classList.remove('expanded');
                            detailRow.classList.remove('visible');
                        } else {
                            this.classList.add('expanded');
                            detailRow.classList.add('visible');
                        }
                    }
                });
            });
            
            var sampleHeaders = document.querySelectorAll('.sample-header-cell');
            var modal = document.getElementById('hashModal');
            var modalTitle = document.getElementById('hashModalTitle');
            var modalBody = document.getElementById('hashModalBody');
            var modalClose = document.getElementById('hashModalClose');
            
            sampleHeaders.forEach(function(header) {
                header.addEventListener('click', function(e) {
                    e.stopPropagation();
                    
                    var sampleType = this.getAttribute('data-sample-type');
                    var sampleIndex = this.getAttribute('data-sample-index');
                    
                    var hashes, title;
                    if (sampleType === 'target') {
                        hashes = hashData.target;
                        title = 'Target - File Hashes';
                    } else {
                        hashes = hashData.samples[sampleIndex];
                        title = 'Sample #' + sampleIndex + ' - File Hashes';
                    }
                    
                    modalTitle.textContent = title;
                    
                    var hashesHtml = '<div class="hash-modal-row"><div class="hash-modal-label">MD5</div><div class="hash-modal-value">' + hashes.md5 + '</div><button class="hash-copy-btn" data-hash="' + hashes.md5 + '">Copy</button></div>';
                    hashesHtml += '<div class="hash-modal-row"><div class="hash-modal-label">SHA1</div><div class="hash-modal-value">' + hashes.sha1 + '</div><button class="hash-copy-btn" data-hash="' + hashes.sha1 + '">Copy</button></div>';
                    hashesHtml += '<div class="hash-modal-row"><div class="hash-modal-label">SHA256</div><div class="hash-modal-value">' + hashes.sha256 + '</div><button class="hash-copy-btn" data-hash="' + hashes.sha256 + '">Copy</button></div>';
                    
                    modalBody.innerHTML = hashesHtml;
                    
                    var copyButtons = modalBody.querySelectorAll('.hash-copy-btn');
                    copyButtons.forEach(function(btn) {
                        btn.addEventListener('click', function() {
                            var hash = this.getAttribute('data-hash');
                            navigator.clipboard.writeText(hash).then(function() {
                                btn.textContent = 'Copied!';
                                btn.classList.add('copied');
                                setTimeout(function() {
                                    btn.textContent = 'Copy';
                                    btn.classList.remove('copied');
                                }, 2000);
                            });
                        });
                    });
                    
                    modal.classList.add('active');
                });
            });
            
            modalClose.addEventListener('click', function() {
                modal.classList.remove('active');
            });
            
            modal.addEventListener('click', function(e) {
                if (e.target === modal) {
                    modal.classList.remove('active');
                }
            });
            
            var hashValues = document.querySelectorAll('.hash-value');
            hashValues.forEach(function(hashValue) {
                hashValue.addEventListener('click', function() {
                    var text = this.textContent;
                    navigator.clipboard.writeText(text).then(function() {
                        var original = hashValue.style.background;
                        hashValue.style.background = '#4caf50';
                        hashValue.style.color = 'white';
                        setTimeout(function() {
                            hashValue.style.background = original;
                            hashValue.style.color = '';
                        }, 500);
                    });
                });
            });
            
            var copyReportBtn = document.getElementById('copyReportBtn');
            if (copyReportBtn) {
                copyReportBtn.addEventListener('click', function() {
                    var textarea = document.getElementById('reportTextRaw');
                    if (textarea) {
                        var textToCopy = textarea.value;
                        
                        navigator.clipboard.writeText(textToCopy).then(function() {
                            var originalText = copyReportBtn.textContent;
                            copyReportBtn.textContent = 'Copied!';
                            copyReportBtn.classList.add('copied');
                            
                            setTimeout(function() {
                                copyReportBtn.textContent = originalText;
                                copyReportBtn.classList.remove('copied');
                            }, 2000);
                        }).catch(function(err) {
                            console.error('Failed to copy report:', err);
                            alert('Failed to copy report to clipboard');
                        });
                    }
                });
            }
        });
    </script>
</body>
</html>)HTML";
}

}
}