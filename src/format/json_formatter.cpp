#include "semantics_av/format/json_formatter.hpp"

namespace semantics_av {
namespace format {

nlohmann::json JsonFormatter::format(const network::AnalysisResult& result,
                                     const std::string& report_id) {
    nlohmann::json json;
    
    if (!report_id.empty()) {
        json["metadata"]["report_id"] = report_id;
    }
    
    json["file_type"] = result.file_type;
    json["file_hashes"] = result.file_hashes;
    json["analysis_timestamp"] = result.analysis_timestamp;
    
    nlohmann::json detection;
    detection["verdict"] = result.verdict;
    detection["confidence"] = result.confidence;
    detection["tags"] = result.tags;
    
    if (result.signature) {
        detection["signature"] = *result.signature;
    } else {
        detection["signature"] = nullptr;
    }
    
    if (result.static_attributes_json && !result.static_attributes_json->empty()) {
        try {
            detection["static_attributes"] = nlohmann::json::parse(*result.static_attributes_json);
        } catch (...) {
            detection["static_attributes"] = nullptr;
        }
    } else {
        detection["static_attributes"] = nullptr;
    }
    
    json["detection"] = detection;
    json["intelligence"] = formatIntelligence(result.intelligence);
    
    if (!result.natural_language_report.empty()) {
        json["natural_language_report"] = result.natural_language_report;
    } else {
        json["natural_language_report"] = nullptr;
    }
    
    if (!result.sdk_version.empty()) {
        json["sdk_version"] = result.sdk_version;
    }
    
    return json;
}

nlohmann::json JsonFormatter::formatLabelStatistics(const network::LabelStatistics& stats) {
    nlohmann::json json;
    json["count"] = stats.count;
    
    if (stats.max_similarity) {
        json["max_similarity"] = *stats.max_similarity;
    } else {
        json["max_similarity"] = nullptr;
    }
    
    if (stats.avg_similarity) {
        json["avg_similarity"] = *stats.avg_similarity;
    } else {
        json["avg_similarity"] = nullptr;
    }
    
    return json;
}

nlohmann::json JsonFormatter::formatSignatureStatistics(const network::SignatureStatistics& stats) {
    nlohmann::json json;
    json["count"] = stats.count;
    json["max_similarity"] = stats.max_similarity;
    json["avg_similarity"] = stats.avg_similarity;
    return json;
}

nlohmann::json JsonFormatter::formatSimilarSample(const network::SimilarSample& sample) {
    nlohmann::json json;
    json["file_hashes"] = sample.file_hashes;
    json["similarity_score"] = sample.similarity_score;
    json["tags"] = sample.tags;
    
    if (sample.signature) {
        json["signature"] = *sample.signature;
    } else {
        json["signature"] = nullptr;
    }
    
    if (sample.static_attributes_json) {
        try {
            json["static_attributes"] = nlohmann::json::parse(*sample.static_attributes_json);
        } catch (...) {
            json["static_attributes"] = nullptr;
        }
    } else {
        json["static_attributes"] = nullptr;
    }
    
    return json;
}

nlohmann::json JsonFormatter::formatIntelligence(const network::Intelligence& intelligence) {
    nlohmann::json json;
    
    nlohmann::json samples_array = nlohmann::json::array();
    for (const auto& sample : intelligence.similar_samples) {
        samples_array.push_back(formatSimilarSample(sample));
    }
    json["similar_samples"] = samples_array;
    
    nlohmann::json stats;
    stats["processed_samples"] = intelligence.statistics.processed_samples;
    
    nlohmann::json by_label;
    by_label["malicious"] = formatLabelStatistics(intelligence.statistics.malicious);
    by_label["suspicious"] = formatLabelStatistics(intelligence.statistics.suspicious);
    by_label["clean"] = formatLabelStatistics(intelligence.statistics.clean);
    by_label["unknown"] = formatLabelStatistics(intelligence.statistics.unknown);
    stats["by_label"] = by_label;
    
    nlohmann::json by_signature;
    for (const auto& [sig_name, sig_stat] : intelligence.statistics.by_signature) {
        by_signature[sig_name] = formatSignatureStatistics(sig_stat);
    }
    stats["by_signature"] = by_signature;
    
    json["statistics"] = stats;
    
    return json;
}

}}