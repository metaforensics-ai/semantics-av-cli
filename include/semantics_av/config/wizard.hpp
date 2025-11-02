#pragma once

#include "semantics_av/common/config.hpp"
#include <string>
#include <vector>

namespace semantics_av {
namespace config {

class ConfigWizard {
public:
    ConfigWizard();
    
    int run(bool use_defaults = false);
    
    common::GlobalConfig& getConfig() { return config_; }

private:
    common::GlobalConfig config_;
    std::string install_mode_str_;
    
    void initializeDefaults();
    void loadExistingConfig();
    std::string promptString(const std::string& prompt, const std::string& default_value);
    int promptChoice(const std::string& prompt, const std::vector<std::string>& options, int default_idx);
    void printHeader();
    void printSummary();
    bool validateRequiredDirectories();
    bool saveUserCredentials(const std::string& api_key);
    bool saveSystemSecrets(const std::string& api_key);
    void triggerDaemonReloadIfRunning();
};

}}