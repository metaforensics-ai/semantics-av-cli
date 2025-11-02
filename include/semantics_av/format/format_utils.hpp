#pragma once

#include "common_types.hpp"
#include <map>
#include <vector>
#include <string>

namespace semantics_av {
namespace format {

std::map<std::string, FlattenedAttribute> flattenAttributes(
    const nlohmann::json& attrs, 
    const std::string& prefix = "",
    int max_depth = 3,
    int current_depth = 0
);

std::string extractLabelFromTags(const std::vector<std::string>& tags);

bool hasGroundTruthLabel(const std::vector<std::string>& tags);

std::string formatPercentage(float value, int precision = 1);

std::string formatBasicValue(const nlohmann::json& value);

std::string formatSmartArray(const nlohmann::json& arr);

}
}