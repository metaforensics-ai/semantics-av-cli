#pragma once

#include <CLI/CLI.hpp>
#include <string>

namespace semantics_av {
namespace cli {

class MainCommand {
public:
    MainCommand();
    virtual ~MainCommand();
    
    virtual bool validateArguments() const;
    void printHelp() const;
    void printVersion() const;

protected:
    CLI::App* subcommand_ = nullptr;
};

}}