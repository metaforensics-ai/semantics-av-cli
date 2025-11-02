#pragma once

#include "../network/client.hpp"
#include "common_types.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>

namespace semantics_av {
namespace format {

struct ComparisonRow {
    std::string attribute_path;
    std::string target_value;
    std::vector<std::string> sample_values;
    bool is_complex;
    nlohmann::json target_json;
    std::vector<nlohmann::json> sample_jsons;
};

class HtmlFormatter {
public:
    HtmlFormatter();
    
    std::string format(const network::AnalysisResult& result);

private:
    std::vector<ComparisonRow> generateComparisonRows(
        const network::AnalysisResult& result
    );
    
    nlohmann::json prepareTemplateData(const network::AnalysisResult& result);
    
    std::string formatValue(const nlohmann::json& value);
    std::string escapeHtml(const std::string& text);
    std::string formatJsonForDisplay(const nlohmann::json& value);
    
    const char* getHtmlTemplate() const;
};

}
}