#pragma once

#include "main_command.hpp"
#include <CLI/CLI.hpp>
#include <string>
#include <vector>
#include <cstdint>

namespace semantics_av {
namespace cli {

class UpdateCommand : public MainCommand {
public:
    UpdateCommand();
    
    void setup(CLI::App* subcommand);
    bool wasCalled() const;
    int execute();

private:
    bool was_called_;
    std::vector<std::string> model_types_;
    bool check_only_ = false;
    bool force_update_ = false;
    bool quiet_ = false;
    
    int executeThroughDaemon();
    int executeDirect();
    
    std::string formatTimestamp(int64_t unix_timestamp) const;
};

}}