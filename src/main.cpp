#include <CLI/CLI.hpp>
#include <iostream>
#include <memory>
#include <cstdlib>
#include <unistd.h>

#include "semantics_av/common/config.hpp"
#include "semantics_av/common/constants.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/paths.hpp"
#include "semantics_av/config/wizard.hpp"
#include "cli/main_command.hpp"
#include "cli/daemon_command.hpp"
#include "cli/scan_command.hpp"
#include "cli/update_command.hpp"
#include "cli/analyze_command.hpp"
#include "cli/config_command.hpp"
#include "cli/report_command.hpp"

bool requires_configuration(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "config" || arg == "report" || arg == "--version" || arg == "-v" || 
            arg == "--help" || arg == "-h") {
            return false;
        }
    }
    return argc > 1;
}

void print_config_missing_message(const std::string& config_path) {
    std::cerr << "\nConfiguration file not found.\n\n";
    std::cerr << "Expected location: " << config_path << "\n\n";
    std::cerr << "To create configuration:\n";
    std::cerr << "  Interactive:  semantics-av config init\n";
    std::cerr << "  Automated:    semantics-av config init --defaults\n\n";
}

bool is_interactive_terminal() {
    return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
}

bool is_daemon_run_command(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "daemon" && i + 1 < argc) {
            std::string subarg = argv[i + 1];
            return subarg == "run";
        }
    }
    return false;
}

int main(int argc, char** argv) {
    try {
        CLI::App app{semantics_av::constants::system::APPLICATION_NAME, "semantics-av"};
        app.set_version_flag("--version,-v", semantics_av::constants::version::getFullVersion());
        app.require_subcommand(0, 1);
        
        auto& path_manager = semantics_av::common::PathManager::instance();
        auto& config = semantics_av::common::Config::instance();
        
        bool needs_config = requires_configuration(argc, argv);
        bool config_exists = config.exists();
        
        if (needs_config && !config_exists) {
            print_config_missing_message(path_manager.getConfigFile());
            
            if (is_interactive_terminal()) {
                std::cout << "Run configuration wizard now? [Y/n]: ";
                std::string response;
                std::getline(std::cin, response);
                
                if (response.empty() || response[0] == 'Y' || response[0] == 'y') {
                    semantics_av::config::ConfigWizard wizard;
                    return wizard.run(false);
                }
            }
            
            return 1;
        }
        
        config.load();
        
        bool is_daemon_run = is_daemon_run_command(argc, argv);
        
        if (is_daemon_run) {
            semantics_av::common::Logger::instance().initialize(
                semantics_av::common::LogMode::FILE_ONLY,
                config.global().log_file,
                config.global().log_level,
                config.global().logging
            );
        } else {
            semantics_av::common::Logger::instance().initialize(
                semantics_av::common::LogMode::CONSOLE_ONLY,
                "",
                config.global().log_level,
                config.global().logging
            );
        }
        
        auto config_cmd = std::make_unique<semantics_av::cli::ConfigCommand>();
        auto daemon_cmd = std::make_unique<semantics_av::cli::DaemonCommand>();
        auto scan_cmd = std::make_unique<semantics_av::cli::ScanCommand>();
        auto update_cmd = std::make_unique<semantics_av::cli::UpdateCommand>();
        auto analyze_cmd = std::make_unique<semantics_av::cli::AnalyzeCommand>();
        auto report_cmd = std::make_unique<semantics_av::cli::ReportCommand>();
        
        config_cmd->setup(app.add_subcommand("config", "Manage configuration"));
        daemon_cmd->setup(app.add_subcommand("daemon", "Run as daemon service"));
        scan_cmd->setup(app.add_subcommand("scan", "Scan files or directories"));
        update_cmd->setup(app.add_subcommand("update", "Update detection models"));
        analyze_cmd->setup(app.add_subcommand("analyze", "Cloud analysis with detailed report"));
        report_cmd->setup(app.add_subcommand("report", "Manage analysis reports"));
        
        CLI11_PARSE(app, argc, argv);
        
        if (config_cmd->wasCalled()) {
            return config_cmd->execute();
        } else if (daemon_cmd->wasCalled()) {
            return daemon_cmd->execute();
        } else if (scan_cmd->wasCalled()) {
            return scan_cmd->execute();
        } else if (update_cmd->wasCalled()) {
            return update_cmd->execute();
        } else if (analyze_cmd->wasCalled()) {
            return analyze_cmd->execute();
        } else if (report_cmd->wasCalled()) {
            return report_cmd->execute();
        } else {
            std::cout << app.help() << std::endl;
            return 0;
        }
        
    } catch (const CLI::ParseError& e) {
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}