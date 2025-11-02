#pragma once

#include <string>
#include <map>
#include <unordered_map>
#include <optional>
#include <chrono>

namespace semantics_av {
namespace common {

template<typename EnumType>
struct ErrorInfo {
    EnumType code;
    const char* code_str;
    const char* default_message;
};

struct ErrorContext {
    std::string component;
    std::map<std::string, std::string> details;
    std::optional<std::chrono::system_clock::time_point> when;
};

template<typename EnumType>
class ErrorRegistry {
public:
    static const ErrorInfo<EnumType>& getInfo(EnumType code) {
        const auto& map = getInfoMap();
        auto it = map.find(code);
        if (it != map.end()) {
            return it->second;
        }
        static ErrorInfo<EnumType> fallback{};
        return fallback;
    }
    
    static const char* toString(EnumType code) {
        return getInfo(code).code_str;
    }
    
    static const char* getMessage(EnumType code) {
        return getInfo(code).default_message;
    }
    
protected:
    static const std::unordered_map<EnumType, ErrorInfo<EnumType>>& getInfoMap();
};

inline std::string formatContext(const ErrorContext& ctx) {
    std::string result;
    for (const auto& [key, value] : ctx.details) {
        if (!result.empty()) {
            result += " | ";
        }
        result += key + "=" + value;
    }
    return result;
}

}}