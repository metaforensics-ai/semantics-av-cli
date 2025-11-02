#pragma once

#include "../common/config.hpp"
#include <string>
#include <vector>
#include <map>
#include <set>

namespace semantics_av {
namespace config {

struct ValidationResult {
    bool is_valid = true;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

class ConfigValidator {
public:
    ValidationResult validate(const common::GlobalConfig& config);
    ValidationResult validateFile(const std::string& path);
    
    static bool validatePath(const std::string& path);
    static bool validatePort(uint16_t port);
    static bool validateUrl(const std::string& url);
    static bool validateApiKey(const std::string& key);
    static bool canCreateDirectory(const std::string& path);
};

class ConfigMasker {
public:
    static std::string mask(const std::string& key, const std::string& value);
    static std::string smartDisplay(const std::string& key, 
                                    const std::optional<std::string>& value,
                                    bool file_exists);
    static bool isSensitive(const std::string& key);

private:
    static const std::set<std::string> SENSITIVE_KEYS;
};

}}