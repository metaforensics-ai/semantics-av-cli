#include "update_command.hpp"
#include "semantics_av/common/config.hpp"
#include "semantics_av/common/constants.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/paths.hpp"
#include "semantics_av/common/progress_bar.hpp"
#include "semantics_av/core/engine.hpp"
#include "semantics_av/network/downloader.hpp"
#include "semantics_av/update/updater.hpp"
#include "semantics_av/daemon/client.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <map>
#include <pwd.h>

namespace semantics_av {
namespace cli {

UpdateCommand::UpdateCommand() : was_called_(false) {}

void UpdateCommand::setup(CLI::App* subcommand) {
    subcommand_ = subcommand;
    
    subcommand->add_option("-m,--model-types", model_types_, 
                          "Model types to update (default: pe,elf)")
                          ->delimiter(',');
    subcommand->add_flag("-c,--check-only", check_only_, 
                        "Only check for updates, don't download");
    subcommand->add_flag("-f,--force", force_update_, 
                        "Force update even if models are current");
    subcommand->add_flag("-q,--quiet", quiet_, 
                        "Quiet mode - minimal output");
    
    if (model_types_.empty()) {
        model_types_ = constants::file_types::getSupported();
    }
    
    subcommand->callback([this]() { was_called_ = true; });
}

bool UpdateCommand::wasCalled() const {
    return was_called_;
}

int UpdateCommand::execute() {
    auto& path_manager = common::PathManager::instance();
    auto& config = common::Config::instance().global();
    
    bool use_daemon = daemon::DaemonClient::isDaemonRunning();
    
    if (use_daemon) {
        return executeThroughDaemon();
    }
    
    if (path_manager.isSystemMode()) {
        std::string models_path = config.models_path;
        
        if (access(models_path.c_str(), W_OK) != 0) {
            std::cerr << "\033[31mError: Cannot write to model directory\033[0m\n\n";
            std::cerr << "Model directory: " << models_path << "\n\n";
            std::cerr << "\033[1mOptions:\033[0m\n\n";
            std::cerr << "  \033[1m1. Start daemon (recommended):\033[0m\n";
            std::cerr << "     sudo systemctl start semantics-av\n";
            std::cerr << "     semantics-av update\n\n";
            std::cerr << "  \033[1m2. Run with sudo:\033[0m\n";
            std::cerr << "     sudo semantics-av update\n\n";
            std::cerr << "  Daemon handles permissions automatically.\n";
            return 1;
        }
    }
    
    return executeDirect();
}

int UpdateCommand::executeThroughDaemon() {
    if (!quiet_) {
        std::cout << "SemanticsAV Model Updater (via daemon)\n";
        
        if (!check_only_) {
            std::cout << "Checking for updates...\n\n";
        }
    }
    
    daemon::DaemonClient client;
    if (!client.connect()) {
        std::cerr << "Failed to connect to daemon\n\n";
        std::cerr << "\033[1mTroubleshooting:\033[0m\n";
        std::cerr << "  1. Check daemon status:\n";
        std::cerr << "     systemctl status semantics-av\n\n";
        std::cerr << "  2. Start daemon:\n";
        std::cerr << "     sudo systemctl start semantics-av\n\n";
        std::cerr << "  3. View daemon logs:\n";
        std::cerr << "     tail -f " << common::Config::instance().global().log_file << "\n\n";
        std::cerr << "Falling back to direct update...\n";
        return executeDirect();
    }
    
    auto response = client.updateModels(model_types_, force_update_, check_only_);
    
    if (!response) {
        std::cerr << "Error: Daemon update request failed\n";
        std::cerr << "Falling back to direct update\n";
        return executeDirect();
    }
    
    if (!quiet_) {
        bool use_colors = isatty(STDOUT_FILENO);
        
        if (!response->version_updates.empty()) {
            for (const auto& ver_update : response->version_updates) {
                std::string type_prefix = "  " + ver_update.model_type + ": ";
                
                bool failed = std::find(response->failed_types.begin(),
                                      response->failed_types.end(),
                                      ver_update.model_type) != response->failed_types.end();
                
                if (ver_update.was_updated) {
                    std::cout << type_prefix;
                    
                    if (use_colors) {
                        std::cout << "\033[32m✓\033[0m ";
                    } else {
                        std::cout << "✓ ";
                    }
                    
                    if (ver_update.had_previous_version && ver_update.old_timestamp > 0) {
                        std::cout << formatTimestamp(ver_update.old_timestamp);
                        std::cout << " → ";
                    }
                    
                    std::cout << formatTimestamp(ver_update.new_timestamp);
                    std::cout << " (updated)\n";
                    
                } else if (failed) {
                    std::cout << type_prefix;
                    
                    if (use_colors) {
                        std::cout << "\033[31m✗\033[0m ";
                    } else {
                        std::cout << "✗ ";
                    }
                    
                    std::cout << "update failed\n";
                    
                } else {
                    std::cout << type_prefix;
                    
                    if (use_colors) {
                        std::cout << "\033[32m✓\033[0m ";
                    } else {
                        std::cout << "✓ ";
                    }
                    
                    std::cout << formatTimestamp(ver_update.new_timestamp);
                    std::cout << " (up-to-date)\n";
                }
            }
            
            std::cout << "\n";
        }
        
        std::cout << "Update Summary:\n";
        std::cout << "Total models: " << response->total_models << "\n";
        std::cout << "Updated: " << response->updated_models << "\n";
        std::cout << "Failed: " << response->failed_models << "\n";
        std::cout << "Total time: " << response->total_time_ms << "ms\n";
        
        if (response->updated_models > 0) {
            std::cout << "\nModels have been updated and loaded into the daemon.\n";
        }
    }
    
    return (response->failed_models > 0) ? 1 : 0;
}

int UpdateCommand::executeDirect() {
    try {
        auto& config = common::Config::instance().global();
        auto& path_manager = common::PathManager::instance();
        
        if (!quiet_) {
            std::cout << "SemanticsAV Model Updater\n";
            
            if (!check_only_) {
                std::cout << "Checking for updates...\n";
            }
        }
        
        core::SemanticsAVEngine engine;
        if (!engine.initialize(config.base_path, config.api_key)) {
            std::cerr << "Error: Failed to initialize scan engine\n";
            return 1;
        }
        
        network::ModelDownloader downloader(config.network_timeout);
        update::ModelUpdater updater(&engine, &downloader);
        
        bool use_colors = !quiet_ && isatty(STDOUT_FILENO);
        std::map<std::string, std::unique_ptr<common::ProgressBarRenderer>> progress_bars;
        
        if (!quiet_ && !check_only_) {
            updater.setProgressCallback([&](const std::string& model_type, size_t current, size_t total) {
                auto it = progress_bars.find(model_type);
                if (it == progress_bars.end()) {
                    auto renderer = std::make_unique<common::ProgressBarRenderer>(
                        "Downloading " + model_type, use_colors);
                    renderer->update(current, total);
                    renderer->render(std::cout);
                    progress_bars[model_type] = std::move(renderer);
                } else {
                    it->second->update(current, total);
                    it->second->render(std::cout);
                }
            });
        }
        
        update::UpdateOptions options;
        options.model_types = model_types_;
        options.force_update = force_update_;
        options.check_only = check_only_;
        options.quiet = quiet_;
        
        if (check_only_) {
            std::cout << "\nModel Status:\n";
            
            for (const auto& type : model_types_) {
                auto info = engine.getModelInfo(type);
                
                std::cout << "  " << type << ": ";
                
                if (info.etag.empty()) {
                    std::cout << "not installed\n";
                } else {
                    std::string timestamp_str = formatTimestamp(
                        std::chrono::system_clock::to_time_t(info.last_updated));
                    std::cout << timestamp_str << "\n";
                }
            }
            
            std::cout << "\n";
            return 0;
        }
        
        auto summary = updater.updateModelsSync(options);
        
        for (auto& [type, renderer] : progress_bars) {
            renderer->complete();
            renderer->clear();
        }
        
        if (path_manager.isSystemMode() && getuid() == 0 && summary.updated_models > 0) {
            fixModelFilesOwnership(config.models_path);
        }
        
        if (!quiet_) {
            std::cout << "\n";
            
            if (!summary.version_info.empty()) {
                for (const auto& ver_info : summary.version_info) {
                    std::string type_prefix = "  " + ver_info.model_type + ": ";
                    
                    bool was_updated = std::find(summary.updated_types.begin(), 
                                                summary.updated_types.end(), 
                                                ver_info.model_type) != summary.updated_types.end();
                    
                    bool failed = std::find(summary.failed_types.begin(),
                                          summary.failed_types.end(),
                                          ver_info.model_type) != summary.failed_types.end();
                    
                    if (was_updated) {
                        std::cout << type_prefix;
                        
                        if (use_colors) {
                            std::cout << "\033[32m✓\033[0m ";
                        } else {
                            std::cout << "✓ ";
                        }
                        
                        if (ver_info.has_local_version && ver_info.current_timestamp > 0) {
                            std::cout << formatTimestamp(ver_info.current_timestamp);
                            std::cout << " → ";
                        }
                        
                        std::cout << formatTimestamp(ver_info.server_timestamp);
                        std::cout << " (updated)\n";
                        
                    } else if (failed) {
                        std::cout << type_prefix;
                        
                        if (use_colors) {
                            std::cout << "\033[31m✗\033[0m ";
                        } else {
                            std::cout << "✗ ";
                        }
                        
                        std::cout << "update failed\n";
                        
                    } else {
                        std::cout << type_prefix;
                        
                        if (use_colors) {
                            std::cout << "\033[32m✓\033[0m ";
                        } else {
                            std::cout << "✓ ";
                        }
                        
                        std::cout << formatTimestamp(ver_info.current_timestamp);
                        std::cout << " (up-to-date)\n";
                    }
                }
                
                std::cout << "\n";
            }
            
            std::cout << "Update Summary:\n";
            std::cout << "Total models: " << summary.total_models << "\n";
            std::cout << "Updated: " << summary.updated_models << "\n";
            std::cout << "Failed: " << summary.failed_models << "\n";
            
            auto duration_ms = summary.total_time.count();
            std::cout << "Total time: " << duration_ms << "ms\n";
        }
        
        return (summary.failed_models > 0) ? 1 : 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Update error: " << e.what() << "\n";
        return 1;
    }
}

void UpdateCommand::fixModelFilesOwnership(const std::string& models_path) {
    struct passwd* pw = getpwnam(constants::system::DAEMON_USER);
    if (!pw) {
        common::Logger::instance().warn(
            "[Update] Daemon user '{}' not found, skipping ownership fix",
            constants::system::DAEMON_USER);
        return;
    }
    
    std::error_code ec;
    for (auto& entry : std::filesystem::recursive_directory_iterator(models_path, ec)) {
        if (std::filesystem::is_regular_file(entry, ec)) {
            if (chown(entry.path().c_str(), pw->pw_uid, pw->pw_gid) == 0) {
                common::Logger::instance().debug(
                    "[Update] Ownership fixed | file={}", entry.path().string());
            } else {
                common::Logger::instance().warn(
                    "[Update] Failed to chown | file={} | error={}", 
                    entry.path().string(), strerror(errno));
            }
        }
    }
}

std::string UpdateCommand::formatTimestamp(int64_t unix_timestamp) const {
    if (unix_timestamp <= 0) {
        return "unknown";
    }
    
    std::time_t time = static_cast<std::time_t>(unix_timestamp);
    std::tm tm = *std::gmtime(&time);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M UTC");
    return oss.str();
}

}}