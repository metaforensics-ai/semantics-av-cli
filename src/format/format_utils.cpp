#include "semantics_av/format/format_utils.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace semantics_av {
namespace format {

std::string sanitizeControlCharacters(const std::string& text) {
    std::ostringstream result;
    
    for (size_t i = 0; i < text.length(); ++i) {
        unsigned char c = static_cast<unsigned char>(text[i]);
        
        if (isControlCharacter(c)) {
            result << getControlCharReplacement(c);
        } else if ((c & 0x80) != 0) {
            size_t utf8_len = 0;
            if ((c & 0xE0) == 0xC0) utf8_len = 2;
            else if ((c & 0xF0) == 0xE0) utf8_len = 3;
            else if ((c & 0xF8) == 0xF0) utf8_len = 4;
            
            if (utf8_len > 0 && i + utf8_len <= text.length()) {
                bool valid = true;
                for (size_t j = 1; j < utf8_len; ++j) {
                    if ((static_cast<unsigned char>(text[i + j]) & 0xC0) != 0x80) {
                        valid = false;
                        break;
                    }
                }
                
                if (valid) {
                    for (size_t j = 0; j < utf8_len; ++j) {
                        result << text[i + j];
                    }
                    i += utf8_len - 1;
                } else {
                    result << "\uFFFD";
                }
            } else {
                result << "\uFFFD";
            }
        } else {
            result << c;
        }
    }
    
    return result.str();
}

bool isControlCharacter(unsigned char c) {
    return (c < 0x20 && c != 0x09 && c != 0x0A && c != 0x0D) || c == 0x7F;
}

std::string getControlCharReplacement(unsigned char c) {
    std::ostringstream oss;
    oss << "<" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') 
        << static_cast<int>(c) << ">";
    return oss.str();
}

std::string formatSmartArray(const nlohmann::json& arr) {
    if (arr.empty()) {
        return "[]";
    }
    
    size_t size = arr.size();
    
    bool all_strings = std::all_of(arr.begin(), arr.end(), 
        [](const nlohmann::json& item) { return item.is_string(); });
    
    bool all_numbers = std::all_of(arr.begin(), arr.end(),
        [](const nlohmann::json& item) { return item.is_number(); });
    
    bool all_booleans = std::all_of(arr.begin(), arr.end(),
        [](const nlohmann::json& item) { return item.is_boolean(); });
    
    if (!all_strings && !all_numbers && !all_booleans) {
        return "[Array: " + std::to_string(size) + " items]";
    }
    
    if (all_booleans) {
        int true_count = 0;
        int false_count = 0;
        for (const auto& item : arr) {
            if (item.get<bool>()) true_count++;
            else false_count++;
        }
        return "true(" + std::to_string(true_count) + "), false(" + std::to_string(false_count) + ")";
    }
    
    const size_t MAX_DISPLAY = 3;
    const size_t MAX_ITEM_LENGTH = 20;
    
    std::ostringstream oss;
    
    for (size_t i = 0; i < std::min(size, MAX_DISPLAY); ++i) {
        if (i > 0) oss << ", ";
        
        std::string item_str;
        if (arr[i].is_string()) {
            item_str = sanitizeControlCharacters(arr[i].get<std::string>());
        } else if (arr[i].is_number_integer()) {
            item_str = std::to_string(arr[i].get<int64_t>());
        } else if (arr[i].is_number_float()) {
            std::ostringstream tmp;
            tmp << std::fixed << std::setprecision(2) << arr[i].get<double>();
            item_str = tmp.str();
        } else {
            item_str = arr[i].dump();
        }
        
        if (item_str.length() > MAX_ITEM_LENGTH) {
            item_str = item_str.substr(0, MAX_ITEM_LENGTH - 3) + "...";
        }
        
        oss << item_str;
    }
    
    if (size > MAX_DISPLAY) {
        oss << ", ... (" << size << " total)";
    }
    
    return oss.str();
}

std::map<std::string, FlattenedAttribute> flattenAttributes(
    const nlohmann::json& attrs, 
    const std::string& prefix,
    int max_depth,
    int current_depth
) {
    std::map<std::string, FlattenedAttribute> result;
    
    if (attrs.is_null() || !attrs.is_object()) {
        return result;
    }
    
    if (current_depth >= max_depth) {
        return result;
    }
    
    for (auto& [key, val] : attrs.items()) {
        std::string new_path = prefix.empty() ? key : prefix + "." + key;
        
        if (val.is_object() && current_depth < max_depth - 1) {
            auto nested = flattenAttributes(val, new_path, max_depth, current_depth + 1);
            result.insert(nested.begin(), nested.end());
        } else if (val.is_array()) {
            FlattenedAttribute flat;
            flat.path = new_path;
            flat.is_present = true;
            flat.is_complex = true;
            flat.raw_value = val;
            flat.display_value = formatSmartArray(val);
            result[new_path] = flat;
        } else if (val.is_object()) {
            FlattenedAttribute flat;
            flat.path = new_path;
            flat.is_present = true;
            flat.is_complex = true;
            flat.raw_value = val;
            flat.display_value = "{Object: " + std::to_string(val.size()) + " keys}";
            result[new_path] = flat;
        } else {
            FlattenedAttribute flat;
            flat.path = new_path;
            flat.is_present = true;
            flat.is_complex = false;
            flat.raw_value = val;
            flat.display_value = formatBasicValue(val);
            result[new_path] = flat;
        }
    }
    
    return result;
}

std::string extractLabelFromTags(const std::vector<std::string>& tags) {
    for (const auto& tag : tags) {
        if (tag.find("label:") == 0) {
            std::string label = tag.substr(6);
            std::transform(label.begin(), label.end(), label.begin(), ::toupper);
            return label;
        }
    }
    return "N/A";
}

bool hasGroundTruthLabel(const std::vector<std::string>& tags) {
    std::string label = extractLabelFromTags(tags);
    std::transform(label.begin(), label.end(), label.begin(), ::tolower);
    return label == "malicious" || label == "clean";
}

std::string formatPercentage(float value, int precision) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(precision) << (value * 100.0f);
    return oss.str();
}

std::string formatBasicValue(const nlohmann::json& value) {
    if (value.is_null()) return "N/A";
    
    if (value.is_boolean()) {
        return value.get<bool>() ? "Yes" : "No";
    } else if (value.is_number_integer()) {
        return std::to_string(value.get<int64_t>());
    } else if (value.is_number_float()) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << value.get<double>();
        return oss.str();
    } else if (value.is_string()) {
        return sanitizeControlCharacters(value.get<std::string>());
    } else if (value.is_array()) {
        return formatSmartArray(value);
    } else if (value.is_object()) {
        return "{Object: " + std::to_string(value.size()) + " keys}";
    }
    
    return "N/A";
}

}
}