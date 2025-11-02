#include "main_command.hpp"
#include "semantics_av/common/config.hpp"
#include "semantics_av/common/constants.hpp"
#include "semantics_av/common/logger.hpp"

namespace semantics_av {
namespace cli {

MainCommand::MainCommand() = default;
MainCommand::~MainCommand() = default;

bool MainCommand::validateArguments() const {
    return true;
}

void MainCommand::printHelp() const {
    std::cout << constants::system::APPLICATION_NAME << " - Advanced Malware Detection\n\n";
    std::cout << "Usage: semantics-av [OPTIONS] COMMAND [ARGS]...\n\n";
    std::cout << "Options:\n";
    std::cout << "  -c, --config PATH    Configuration file path\n";
    std::cout << "  -h, --help          Show this help message\n";
    std::cout << "  -v, --version       Show version information\n\n";
    std::cout << "Commands:\n";
    std::cout << "  daemon              Run as daemon service\n";
    std::cout << "  scan                Scan files or directories\n";
    std::cout << "  update              Update detection models\n\n";
    std::cout << "Examples:\n";
    std::cout << "  semantics-av scan /path/to/file\n";
    std::cout << "  semantics-av daemon --config /etc/semantics-av/semantics-av.conf\n";
    std::cout << "  semantics-av update\n";
}

void MainCommand::printVersion() const {
    std::cout << constants::version::getFullVersion() << "\n";
    std::cout << "Built with SemanticsAV Core Library\n";
    std::cout << "Copyright (c) 2025 " << constants::system::APPLICATION_NAME << "\n";
}

}}