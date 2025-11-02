#include "semantics_av/format/markdown_formatter.hpp"
#include "semantics_av/format/format_utils.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace semantics_av {
namespace format {

MarkdownFormatter::MarkdownFormatter() {}

std::string MarkdownFormatter::format(const network::AnalysisResult& result) {
    std::ostringstream md;
    
    md << "# SemanticsAV Intelligence Report\n\n";
    md << formatDetectionSummary(result);
    
    if (result.intelligence.statistics.processed_samples > 0) {
        md << "\n" << formatIntelligenceStatistics(result);
    }
    
    if (!result.intelligence.similar_samples.empty()) {
        md << "\n" << formatAttributeComparison(result);
    }
    
    if (!result.natural_language_report.empty()) {
        md << "\n" << formatNaturalLanguageReport(result);
    }
    
    return md.str();
}

std::string MarkdownFormatter::formatLegend(const network::AnalysisResult& result) {
    std::ostringstream md;
    
    bool is_confirmed = hasGroundTruthLabel(result.tags);
    
    bool show_confirmed_legend = is_confirmed;
    bool show_predicted_legend = !is_confirmed;
    bool show_legend = show_confirmed_legend || show_predicted_legend;
    
    if (show_legend) {
        md << "**Legend:**\n";
        
        if (show_confirmed_legend) {
            md << "- `†` = Confirmed label (verified malicious/clean from intelligence)\n";
        }
        
        if (show_predicted_legend) {
            md << "- `*` = Predicted label (suspicious/unknown or not in intelligence database)\n";
        }
    }
    
    return md.str();
}

std::string MarkdownFormatter::formatDetectionSummary(const network::AnalysisResult& result) {
    std::ostringstream md;
    
    md << "## Detection Summary\n\n";
    
    std::string verdict = result.verdict;
    std::transform(verdict.begin(), verdict.end(), verdict.begin(), ::toupper);
    
    md << "- **Verdict**: " << verdict << " (" << formatPercentage(result.confidence) << "%)\n";
    md << "- **File Type**: " << result.file_type << "\n";
    md << "- **MD5**: `" << (result.file_hashes.count("md5") ? result.file_hashes.at("md5") : "N/A") << "`\n";
    md << "- **SHA1**: `" << (result.file_hashes.count("sha1") ? result.file_hashes.at("sha1") : "N/A") << "`\n";
    md << "- **SHA256**: `" << (result.file_hashes.count("sha256") ? result.file_hashes.at("sha256") : "N/A") << "`\n";
    md << "- **Signature**: " << (result.signature ? *result.signature : "N/A") << "\n";
    
    std::vector<std::string> non_label_tags;
    for (const auto& tag : result.tags) {
        if (tag.find("label:") != 0) {
            non_label_tags.push_back(tag);
        }
    }
    
    if (!non_label_tags.empty()) {
        md << "- **Tags**: ";
        for (size_t i = 0; i < non_label_tags.size(); ++i) {
            if (i > 0) md << ", ";
            md << "`" << non_label_tags[i] << "`";
        }
        md << "\n";
    } else {
        md << "- **Tags**: N/A\n";
    }
    
    return md.str();
}

std::string MarkdownFormatter::formatIntelligenceStatistics(const network::AnalysisResult& result) {
    std::ostringstream md;
    const auto& stats = result.intelligence.statistics;
    
    md << "## Intelligence Statistics\n\n";
    
    md << "**Total Samples Processed**: " << stats.processed_samples << "\n\n";
    
    md << "### Label Distribution\n\n";
    
    std::vector<std::vector<std::string>> label_rows;
    label_rows.push_back({"Classification", "Count", "Max Similarity", "Avg Similarity"});
    
    auto format_sim = [](const std::optional<float>& sim) -> std::string {
        if (!sim) return "N/A";
        return formatPercentage(*sim) + "%";
    };
    
    label_rows.push_back({
        "Malicious",
        std::to_string(stats.malicious.count),
        format_sim(stats.malicious.max_similarity),
        format_sim(stats.malicious.avg_similarity)
    });
    
    label_rows.push_back({
        "Suspicious",
        std::to_string(stats.suspicious.count),
        format_sim(stats.suspicious.max_similarity),
        format_sim(stats.suspicious.avg_similarity)
    });
    
    label_rows.push_back({
        "Clean",
        std::to_string(stats.clean.count),
        format_sim(stats.clean.max_similarity),
        format_sim(stats.clean.avg_similarity)
    });
    
    label_rows.push_back({
        "Unknown",
        std::to_string(stats.unknown.count),
        format_sim(stats.unknown.max_similarity),
        format_sim(stats.unknown.avg_similarity)
    });
    
    md << makeTable(label_rows);
    
    if (!stats.by_signature.empty()) {
        md << "\n### Top Signatures\n\n";
        
        std::vector<std::pair<std::string, network::SignatureStatistics>> sig_vec(
            stats.by_signature.begin(), stats.by_signature.end()
        );
        
        std::sort(sig_vec.begin(), sig_vec.end(),
            [](const auto& a, const auto& b) {
                return a.second.max_similarity > b.second.max_similarity;
            });
        
        std::vector<std::vector<std::string>> sig_rows;
        sig_rows.push_back({"Signature", "Count", "Max Similarity", "Avg Similarity"});
        
        for (size_t i = 0; i < std::min(sig_vec.size(), size_t(5)); ++i) {
            const auto& [name, sig_stat] = sig_vec[i];
            sig_rows.push_back({
                name,
                std::to_string(sig_stat.count),
                formatPercentage(sig_stat.max_similarity) + "%",
                formatPercentage(sig_stat.avg_similarity) + "%"
            });
        }
        
        md << makeTable(sig_rows);
    }
    
    return md.str();
}

std::string MarkdownFormatter::formatAttributeComparison(const network::AnalysisResult& result) {
    std::ostringstream md;
    const auto& similar_samples = result.intelligence.similar_samples;
    
    bool target_confirmed = hasGroundTruthLabel(result.tags);
    
    md << "## Attribute Comparison Matrix\n\n";
    md << "Comparing static attributes between target file and " 
       << similar_samples.size() << " similar samples.\n\n";
    
    md << formatLegend(result);
    md << "\n";
    
    std::vector<std::vector<std::string>> rows;
    
    std::string verdict_upper = result.verdict;
    std::transform(verdict_upper.begin(), verdict_upper.end(), verdict_upper.begin(), ::toupper);
    
    std::string target_header;
    if (target_confirmed) {
        target_header = "Target (" + verdict_upper + "†)";
    } else {
        target_header = "Target (" + verdict_upper + "* " + formatPercentage(result.confidence) + "%)";
    }
    
    std::vector<std::string> header;
    header.push_back("Attribute");
    header.push_back(target_header);
    
    for (size_t i = 0; i < similar_samples.size(); ++i) {
        header.push_back("Sample #" + std::to_string(i + 1));
    }
    rows.push_back(header);
    
    std::vector<std::string> hash_row;
    hash_row.push_back("MD5 Hash");
    hash_row.push_back(result.file_hashes.count("md5") ? 
                      "`" + result.file_hashes.at("md5") + "`" : "N/A");
    for (const auto& sample : similar_samples) {
        hash_row.push_back(sample.file_hashes.count("md5") ? 
                          "`" + sample.file_hashes.at("md5") + "`" : "N/A");
    }
    rows.push_back(hash_row);
    
    std::vector<std::string> sim_row;
    sim_row.push_back("Similarity");
    sim_row.push_back("Baseline");
    for (const auto& sample : similar_samples) {
        sim_row.push_back(formatPercentage(sample.similarity_score) + "%");
    }
    rows.push_back(sim_row);
    
    std::vector<std::string> label_row;
    label_row.push_back("Label");
    label_row.push_back(extractLabelFromTags(result.tags));
    for (const auto& sample : similar_samples) {
        label_row.push_back(extractLabelFromTags(sample.tags));
    }
    rows.push_back(label_row);
    
    std::vector<std::string> sig_row;
    sig_row.push_back("Signature");
    sig_row.push_back(result.signature ? *result.signature : "N/A");
    for (const auto& sample : similar_samples) {
        sig_row.push_back(sample.signature ? *sample.signature : "N/A");
    }
    rows.push_back(sig_row);
    
    std::vector<std::string> tags_row;
    tags_row.push_back("Tags");
    
    std::ostringstream target_tags;
    bool first = true;
    for (const auto& tag : result.tags) {
        if (tag.find("label:") != 0) {
            if (!first) target_tags << ", ";
            target_tags << "`" << tag << "`";
            first = false;
        }
    }
    tags_row.push_back(target_tags.str().empty() ? "N/A" : target_tags.str());
    
    for (const auto& sample : similar_samples) {
        std::ostringstream sample_tags;
        bool first_tag = true;
        for (const auto& tag : sample.tags) {
            if (tag.find("label:") != 0) {
                if (!first_tag) sample_tags << ", ";
                sample_tags << "`" << tag << "`";
                first_tag = false;
            }
        }
        tags_row.push_back(sample_tags.str().empty() ? "N/A" : sample_tags.str());
    }
    rows.push_back(tags_row);
    
    auto all_keys = collectAllAttributeKeys(result);
    auto meaningful_keys = filterMeaningfulAttributes(all_keys, result);
    
    for (const auto& key : meaningful_keys) {
        std::vector<std::string> attr_row;
        attr_row.push_back(formatAttributeKey(key));
        
        auto target_attr = getFlattenedAttribute(
            result.static_attributes_json && !result.static_attributes_json->empty() 
                ? nlohmann::json::parse(*result.static_attributes_json) 
                : nlohmann::json(),
            key
        );
        attr_row.push_back(formatAttributeValue(target_attr.raw_value));
        
        for (const auto& sample : similar_samples) {
            auto sample_attr = getFlattenedAttribute(
                sample.static_attributes_json && !sample.static_attributes_json->empty()
                    ? nlohmann::json::parse(*sample.static_attributes_json)
                    : nlohmann::json(),
                key
            );
            attr_row.push_back(formatAttributeValue(sample_attr.raw_value));
        }
        
        rows.push_back(attr_row);
    }
    
    md << makeTable(rows);
    
    return md.str();
}

std::string MarkdownFormatter::formatNaturalLanguageReport(const network::AnalysisResult& result) {
    std::ostringstream md;
    
    md << "# Natural Language Report\n\n";
    md << result.natural_language_report << "\n";
    
    return md.str();
}

std::string MarkdownFormatter::makeTable(const std::vector<std::vector<std::string>>& rows,
                                         const std::vector<std::string>& alignments) {
    if (rows.empty()) return "";
    
    std::ostringstream table;
    
    for (size_t col = 0; col < rows[0].size(); ++col) {
        table << "| " << rows[0][col] << " ";
    }
    table << "|\n";
    
    for (size_t col = 0; col < rows[0].size(); ++col) {
        table << "|";
        std::string align = col < alignments.size() ? alignments[col] : "left";
        if (align == "right") {
            table << "---:";
        } else if (align == "center") {
            table << ":---:";
        } else {
            table << "------";
        }
    }
    table << "|\n";
    
    for (size_t row = 1; row < rows.size(); ++row) {
        for (size_t col = 0; col < rows[row].size(); ++col) {
            table << "| " << rows[row][col] << " ";
        }
        table << "|\n";
    }
    
    return table.str();
}

std::set<std::string> MarkdownFormatter::collectAllAttributeKeys(
    const network::AnalysisResult& result
) {
    std::set<std::string> all_keys;
    
    if (result.static_attributes_json && !result.static_attributes_json->empty()) {
        try {
            auto target_attrs = nlohmann::json::parse(*result.static_attributes_json);
            auto flattened = flattenAttributes(target_attrs);
            for (const auto& [key, _] : flattened) {
                all_keys.insert(key);
            }
        } catch (...) {}
    }
    
    for (const auto& sample : result.intelligence.similar_samples) {
        if (sample.static_attributes_json && !sample.static_attributes_json->empty()) {
            try {
                auto sample_attrs = nlohmann::json::parse(*sample.static_attributes_json);
                auto flattened = flattenAttributes(sample_attrs);
                for (const auto& [key, _] : flattened) {
                    all_keys.insert(key);
                }
            } catch (...) {}
        }
    }
    
    return all_keys;
}

std::vector<std::string> MarkdownFormatter::filterMeaningfulAttributes(
    const std::set<std::string>& all_keys,
    const network::AnalysisResult& result
) {
    std::vector<std::string> meaningful;
    
    for (const auto& key : all_keys) {
        int non_null_count = 0;
        int total_count = 1 + static_cast<int>(result.intelligence.similar_samples.size());
        
        auto target_attr = getFlattenedAttribute(
            result.static_attributes_json && !result.static_attributes_json->empty()
                ? nlohmann::json::parse(*result.static_attributes_json)
                : nlohmann::json(),
            key
        );
        if (!target_attr.raw_value.is_null()) non_null_count++;
        
        for (const auto& sample : result.intelligence.similar_samples) {
            auto sample_attr = getFlattenedAttribute(
                sample.static_attributes_json && !sample.static_attributes_json->empty()
                    ? nlohmann::json::parse(*sample.static_attributes_json)
                    : nlohmann::json(),
                key
            );
            if (!sample_attr.raw_value.is_null()) non_null_count++;
        }
        
        float coverage = static_cast<float>(non_null_count) / total_count;
        if (coverage >= 0.5f) {
            meaningful.push_back(key);
        }
    }
    
    return meaningful;
}

std::string MarkdownFormatter::escapeMarkdown(const std::string& text) {
    std::string result;
    result.reserve(text.size() * 1.2);
    
    for (char c : text) {
        if (c == '|' || c == '*' || c == '_' || c == '`' || c == '[' || c == ']') {
            result += '\\';
        }
        result += c;
    }
    
    return result;
}

std::string MarkdownFormatter::formatAttributeKey(const std::string& key) {
    std::vector<std::string> parts;
    std::stringstream ss(key);
    std::string part;
    
    while (std::getline(ss, part, '.')) {
        std::replace(part.begin(), part.end(), '_', ' ');
        
        if (!part.empty()) {
            part[0] = std::toupper(part[0]);
            for (size_t i = 1; i < part.length(); ++i) {
                if (part[i-1] == ' ' && i < part.length()) {
                    part[i] = std::toupper(part[i]);
                }
            }
        }
        parts.push_back(part);
    }
    
    if (parts.size() > 1) {
        std::string result;
        for (size_t i = 0; i < parts.size(); ++i) {
            if (i > 0) result += " → ";
            result += parts[i];
        }
        return result;
    }
    
    return parts.empty() ? "" : parts[0];
}

std::string MarkdownFormatter::formatAttributeValue(const nlohmann::json& value) {
    if (value.is_null()) return "N/A";
    
    std::string basic_value = formatBasicValue(value);
    
    if (basic_value.length() > 50) {
        return "`" + basic_value.substr(0, 47) + "...`";
    }
    
    if (value.is_string() || value.is_number() || value.is_boolean()) {
        return "`" + basic_value + "`";
    }
    
    return basic_value;
}

FlattenedAttribute MarkdownFormatter::getFlattenedAttribute(
    const nlohmann::json& attrs, 
    const std::string& key
) {
    FlattenedAttribute result;
    result.path = key;
    result.is_present = false;
    result.is_complex = false;
    result.raw_value = nlohmann::json();
    result.display_value = "N/A";
    
    if (attrs.is_null()) return result;
    
    auto flattened = flattenAttributes(attrs);
    auto it = flattened.find(key);
    if (it != flattened.end()) {
        return it->second;
    }
    
    return result;
}

}
}