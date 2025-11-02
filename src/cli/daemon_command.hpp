#pragma once

#include "main_command.hpp"
#include <CLI/CLI.hpp>
#include <string>
#include <csignal>

namespace semantics_av {
namespace cli {

class DaemonCommand : public MainCommand {
public:
    DaemonCommand();
    
    void setup(CLI::App* subcommand);
    bool wasCalled() const;
    int execute();

private:
    bool was_called_;
    
    CLI::App* run_cmd_;
    std::string socket_path_;
    uint16_t http_port_ = 0;
    std::string http_host_;
    std::string daemon_user_;
    bool no_drop_privileges_ = false;
    bool check_config_ = false;
    
    CLI::App* start_cmd_;
    CLI::App* stop_cmd_;
    CLI::App* reload_cmd_;
    CLI::App* status_cmd_;
    CLI::App* restart_cmd_;
    
    int executeRun();
    int executeStart();
    int executeStop();
    int executeReload();
    int executeStatus();
    int executeRestart();
    
    int startWithSystemd();
    int startManually();
    int stopWithSystemd();
    int stopManually();
    int statusWithSystemd();
    int statusManually();
    
    int daemonize();
    bool isSystemdAvailable();
    bool isSystemMode();
    std::string getSystemdCommand();
};

}}