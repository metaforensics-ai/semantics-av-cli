#define _DEFAULT_SOURCE
#define _BSD_SOURCE

#include "daemon_command.hpp"
#include "semantics_av/common/config.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/security.hpp"
#include "semantics_av/common/paths.hpp"
#include "semantics_av/config/validator.hpp"
#include "semantics_av/daemon/server.hpp"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <fstream>

namespace semantics_av {
namespace cli {

DaemonCommand::DaemonCommand() : was_called_(false) {}

void DaemonCommand::setup(CLI::App* subcommand) {
    subcommand_ = subcommand;
    
    run_cmd_ = subcommand->add_subcommand("run", "Run daemon in foreground (for systemd/Docker)");
    run_cmd_->add_option("-s,--socket", socket_path_, 
                          "Unix socket path");
    run_cmd_->add_option("-p,--http-port", http_port_, 
                          "HTTP API port number");
    run_cmd_->add_option("-a,--http-host", http_host_, 
                          "HTTP API bind address (default: 127.0.0.1)");
    run_cmd_->add_option("-u,--user", daemon_user_, 
                          "User to run daemon as");
    run_cmd_->add_flag("-n,--no-drop-privileges", no_drop_privileges_, 
                         "Don't drop root privileges");
    run_cmd_->add_flag("-c,--check-config", check_config_, 
                         "Validate configuration and exit");
    run_cmd_->callback([this]() { was_called_ = true; });
    
    start_cmd_ = subcommand->add_subcommand("start", "Start daemon service");
    start_cmd_->callback([this]() { was_called_ = true; });
    
    stop_cmd_ = subcommand->add_subcommand("stop", "Stop daemon service");
    stop_cmd_->callback([this]() { was_called_ = true; });
    
    reload_cmd_ = subcommand->add_subcommand("reload", "Reload daemon configuration");
    reload_cmd_->callback([this]() { was_called_ = true; });
    
    status_cmd_ = subcommand->add_subcommand("status", "Show daemon status");
    status_cmd_->callback([this]() { was_called_ = true; });
    
    restart_cmd_ = subcommand->add_subcommand("restart", "Restart daemon service");
    restart_cmd_->callback([this]() { was_called_ = true; });
}

bool DaemonCommand::wasCalled() const {
    return was_called_;
}

int DaemonCommand::execute() {
    if (run_cmd_->parsed()) {
        return executeRun();
    }
    
    if (start_cmd_->parsed()) {
        return executeStart();
    } else if (stop_cmd_->parsed()) {
        return executeStop();
    } else if (reload_cmd_->parsed()) {
        return executeReload();
    } else if (status_cmd_->parsed()) {
        return executeStatus();
    } else if (restart_cmd_->parsed()) {
        return executeRestart();
    }
    
    std::cout << subcommand_->help() << std::endl;
    return 0;
}

bool DaemonCommand::isSystemdAvailable() {
    return std::filesystem::exists("/run/systemd/system") || 
           std::filesystem::exists("/usr/bin/systemctl");
}

bool DaemonCommand::isSystemMode() {
    return common::PathManager::instance().isSystemMode();
}

std::string DaemonCommand::getSystemdCommand() {
    if (isSystemMode()) {
        return "sudo systemctl";
    } else {
        return "systemctl --user";
    }
}

int DaemonCommand::executeStart() {
    if (isSystemdAvailable()) {
        return startWithSystemd();
    } else {
        return startManually();
    }
}

int DaemonCommand::startWithSystemd() {
    std::string cmd = getSystemdCommand() + " start semantics-av";
    std::cout << "Starting daemon via systemd..." << std::endl;
    std::cout << "Running: " << cmd << std::endl;
    
    int result = system(cmd.c_str());
    if (result == 0) {
        std::cout << "Daemon started successfully" << std::endl;
        std::cout << "Check status with: semantics-av daemon status" << std::endl;
        return 0;
    } else {
        std::cerr << "Failed to start daemon via systemd" << std::endl;
        return 1;
    }
}

int DaemonCommand::startManually() {
    std::cout << "systemd not available, starting daemon manually..." << std::endl;
    
    if (daemon::DaemonServer::isDaemonRunning()) {
        std::cerr << "Daemon is already running (PID: " 
                  << daemon::DaemonServer::getDaemonPid() << ")" << std::endl;
        return 1;
    }
    
    common::Logger::instance().flush();
    
    pid_t pid = fork();
    
    if (pid < 0) {
        std::cerr << "Failed to fork: " << strerror(errno) << std::endl;
        return 1;
    }
    
    if (pid > 0) {
        std::cout << "Daemon started with PID: " << pid << std::endl;
        std::cout << "Check status with: semantics-av daemon status" << std::endl;
        return 0;
    }
    
    if (daemonize() != 0) {
        std::cerr << "Failed to daemonize: " << strerror(errno) << std::endl;
        exit(1);
    }
    
    try {
        auto& global_config = common::Config::instance().global();
        
        common::Logger::instance().shutdown();
        
        common::Logger::instance().initialize(
            common::LogMode::FILE_ONLY,
            global_config.log_file,
            global_config.log_level,
            global_config.logging
        );
        common::Logger::instance().info("Starting SemanticsAV daemon in background mode");
        
        daemon::DaemonServer server(global_config.daemon);
        
        if (!server.bindSockets()) {
            common::Logger::instance().error("Failed to bind daemon sockets");
            exit(1);
        }
        
        if (!server.startService()) {
            common::Logger::instance().error("Failed to start daemon service");
            exit(1);
        }
        
        common::Logger::instance().info("SemanticsAV daemon started successfully");
        
        server.run();
        
        common::Logger::instance().info("Shutting down daemon");
        server.stopService();
        common::Logger::instance().info("Daemon shutdown complete");
        
        exit(0);
        
    } catch (const std::exception& e) {
        common::Logger::instance().error("Daemon error: {}", e.what());
        exit(1);
    }
}

int DaemonCommand::executeStop() {
    if (isSystemdAvailable()) {
        return stopWithSystemd();
    } else {
        return stopManually();
    }
}

int DaemonCommand::stopWithSystemd() {
    std::string cmd = getSystemdCommand() + " stop semantics-av";
    std::cout << "Stopping daemon via systemd..." << std::endl;
    std::cout << "Running: " << cmd << std::endl;
    
    int result = system(cmd.c_str());
    if (result == 0) {
        std::cout << "Daemon stopped successfully" << std::endl;
        return 0;
    } else {
        std::cerr << "Failed to stop daemon via systemd" << std::endl;
        return 1;
    }
}

int DaemonCommand::stopManually() {
    std::cout << "systemd not available, stopping daemon manually..." << std::endl;
    
    if (!daemon::DaemonServer::isDaemonRunning()) {
        std::cerr << "Daemon is not running" << std::endl;
        return 1;
    }
    
    if (daemon::DaemonServer::sendSignalToDaemon(SIGTERM)) {
        std::cout << "Stop signal sent to daemon" << std::endl;
        
        for (int i = 0; i < 30; ++i) {
            if (!daemon::DaemonServer::isDaemonRunning()) {
                std::cout << "Daemon stopped successfully" << std::endl;
                return 0;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        std::cerr << "Daemon did not stop within timeout" << std::endl;
        return 1;
    } else {
        std::cerr << "Failed to send stop signal to daemon" << std::endl;
        return 1;
    }
}

int DaemonCommand::executeReload() {
    if (!daemon::DaemonServer::isDaemonRunning()) {
        std::cerr << "Daemon is not running" << std::endl;
        return 1;
    }
    
    std::cout << "Sending reload signal to daemon..." << std::endl;
    
    if (daemon::DaemonServer::sendSignalToDaemon(SIGHUP)) {
        std::cout << "✓ Reload signal sent successfully" << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::cout << "Configuration reloaded" << std::endl;
        return 0;
    } else {
        std::cerr << "Failed to send reload signal" << std::endl;
        return 1;
    }
}

int DaemonCommand::executeStatus() {
    if (isSystemdAvailable()) {
        return statusWithSystemd();
    } else {
        return statusManually();
    }
}

int DaemonCommand::statusWithSystemd() {
    std::string cmd = getSystemdCommand() + " status semantics-av";
    return system(cmd.c_str());
}

int DaemonCommand::statusManually() {
    std::cout << "systemd not available, checking daemon status manually..." << std::endl;
    
    if (daemon::DaemonServer::isDaemonRunning()) {
        int pid = daemon::DaemonServer::getDaemonPid();
        std::cout << "● semantics-av - SemanticsAV Daemon" << std::endl;
        std::cout << "   Loaded: manual (non-systemd mode)" << std::endl;
        std::cout << "   Active: active (running)" << std::endl;
        std::cout << "   PID: " << pid << std::endl;
        
        auto& config = common::Config::instance().global();
        std::cout << "   Socket: " << config.daemon.socket_path << std::endl;
        std::cout << "   HTTP API: " << config.daemon.http_host 
                  << ":" << config.daemon.http_port << std::endl;
        
        return 0;
    } else {
        std::cout << "● semantics-av - SemanticsAV Daemon" << std::endl;
        std::cout << "   Loaded: manual (non-systemd mode)" << std::endl;
        std::cout << "   Active: inactive (dead)" << std::endl;
        return 3;
    }
}

int DaemonCommand::executeRestart() {
    if (isSystemdAvailable()) {
        std::string cmd = getSystemdCommand() + " restart semantics-av";
        std::cout << "Restarting daemon via systemd..." << std::endl;
        std::cout << "Running: " << cmd << std::endl;
        
        int result = system(cmd.c_str());
        if (result == 0) {
            std::cout << "Daemon restarted successfully" << std::endl;
            return 0;
        } else {
            std::cerr << "Failed to restart daemon via systemd" << std::endl;
            return 1;
        }
    } else {
        std::cout << "systemd not available, restarting daemon manually..." << std::endl;
        std::cout << "Stopping daemon..." << std::endl;
        
        int stop_result = stopManually();
        if (stop_result != 0 && daemon::DaemonServer::isDaemonRunning()) {
            std::cerr << "Failed to stop daemon" << std::endl;
            return 1;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        std::cout << "Starting daemon..." << std::endl;
        return startManually();
    }
}

int DaemonCommand::executeRun() {
    try {
        auto& global_config = common::Config::instance().global();
        
        if (check_config_) {
            semantics_av::config::ConfigValidator validator;
            auto result = validator.validate(global_config);
            
            if (!result.is_valid) {
                std::cerr << "Configuration validation failed:" << std::endl;
                for (const auto& error : result.errors) {
                    std::cerr << "  ERROR: " << error << std::endl;
                }
                return 1;
            }
            
            std::cout << "Configuration is valid" << std::endl;
            return 0;
        }
        
        if (!socket_path_.empty()) {
            global_config.daemon.socket_path = socket_path_;
        }
        if (http_port_ > 0) {
            global_config.daemon.http_port = http_port_;
        }
        if (!http_host_.empty()) {
            global_config.daemon.http_host = http_host_;
        }
        if (!daemon_user_.empty()) {
            global_config.daemon.user = daemon_user_;
        }
        
        common::Logger::instance().info("Starting SemanticsAV daemon in foreground mode");
        common::Logger::instance().info("Socket path: {}", global_config.daemon.socket_path);
        common::Logger::instance().info("HTTP API: {}:{}", 
                                         global_config.daemon.http_host, 
                                         global_config.daemon.http_port);
        
        daemon::DaemonServer server(global_config.daemon);
        
        if (!server.bindSockets()) {
            common::Logger::instance().error("Failed to bind daemon sockets");
            return 1;
        }
        
        if (!server.createPidFileBeforePrivilegeDrop()) {
            common::Logger::instance().error("Failed to create PID file");
            return 1;
        }
        
        if (!no_drop_privileges_ && getuid() == 0 && !global_config.daemon.user.empty()) {
            common::PrivilegeManager privilege_manager;
            
            if (!privilege_manager.createUser(global_config.daemon.user)) {
                common::Logger::instance().warn("Could not create daemon user: {}", 
                                                 global_config.daemon.user);
            }
            
            if (!privilege_manager.dropPrivileges(global_config.daemon.user)) {
                common::Logger::instance().error("Failed to drop privileges to user: {}", 
                                                  global_config.daemon.user);
                return 1;
            }
        }
        
        if (!server.startServiceWithoutPidFile()) {
            common::Logger::instance().error("Failed to start daemon service");
            return 1;
        }
        
        common::Logger::instance().info("SemanticsAV daemon started successfully");
        
        server.run();
        
        common::Logger::instance().info("Shutting down daemon");
        server.stopService();
        common::Logger::instance().info("Daemon shutdown complete");
        
        return 0;
        
    } catch (const std::exception& e) {
        common::Logger::instance().error("Daemon error: {}", e.what());
        return 1;
    }
}

int DaemonCommand::daemonize() {
    pid_t pid = fork();
    
    if (pid < 0) {
        return -1;
    }
    
    if (pid > 0) {
        exit(0);
    }
    
    if (setsid() < 0) {
        return -1;
    }
    
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    pid = fork();
    
    if (pid < 0) {
        return -1;
    }
    
    if (pid > 0) {
        exit(0);
    }
    
    umask(0);
    
    if (chdir("/") < 0) {
        return -1;
    }
    
    for (int fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--) {
        close(fd);
    }
    
    if (open("/dev/null", O_RDWR) < 0) return -1;
    if (dup(0) < 0) return -1;
    if (dup(0) < 0) return -1;
    
    return 0;
}

}}