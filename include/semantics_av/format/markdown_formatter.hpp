#pragma once

#include "../network/client.hpp"
#include "common_types.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <set>

namespace semantics_av {
namespace format {

class MarkdownFormatter {
public:
    MarkdownFormatter();
    
    std::string format(const network::AnalysisResult& result);

private:
    std::string formatLegend(const network::AnalysisResult& result);
    std::string formatDetectionSummary(const network::AnalysisResult& result);
    std::string formatIntelligenceStatistics(const network::AnalysisResult& result);
    std::string formatAttributeComparison(const network::AnalysisResult& result);
    std::string formatNaturalLanguageReport(const network::AnalysisResult& result);
    
    std::string makeTable(const std::vector<std::vector<std::string>>& rows, 
                         const std::vector<std::string>& alignments = {});
    
    std::set<std::string> collectAllAttributeKeys(const network::AnalysisResult& result);
    std::vector<std::string> filterMeaningfulAttributes(
        const std::set<std::string>& all_keys,
        const network::AnalysisResult& result);
    
    std::string escapeMarkdown(const std::string& text);
    std::string formatAttributeKey(const std::string& key);
    std::string formatAttributeValue(const nlohmann::json& value);
    FlattenedAttribute getFlattenedAttribute(const nlohmann::json& attrs, 
                                             const std::string& key);
};

}
}