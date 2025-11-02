#pragma once

#include "main_command.hpp"
#include <CLI/CLI.hpp>
#include <string>
#include <set>

namespace semantics_av {
namespace cli {

class ConfigCommand : public MainCommand {
public:
    ConfigCommand();
    
    void setup(CLI::App* subcommand);
    bool wasCalled() const;
    int execute();

private:
    bool was_called_;
    
    CLI::App* init_cmd_;
    bool init_defaults_ = false;
    
    CLI::App* set_cmd_;
    std::string set_key_;
    std::string set_value_;
    
    CLI::App* get_cmd_;
    std::string get_key_;
    bool reveal_secrets_ = false;
    
    CLI::App* show_cmd_;
    
    CLI::App* validate_cmd_;
    
    int executeInit();
    int executeSet();
    int executeGet();
    int executeGetThroughDaemon();
    int executeGetDirect();
    int executeShow();
    int executeValidate();
    
    void triggerDaemonReloadIfNeeded(const std::string& key);
    bool canWriteConfig(const std::string& config_path);
    bool canRevealSecrets();
    bool checkApiKeyFileExists();
};

}}