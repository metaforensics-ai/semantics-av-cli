#include "analyze_command.hpp"
#include "semantics_av/common/config.hpp"
#include "semantics_av/common/constants.hpp"
#include "semantics_av/common/logger.hpp"
#include "semantics_av/common/paths.hpp"
#include "semantics_av/common/diagnostics.hpp"
#include "semantics_av/core/engine.hpp"
#include "semantics_av/network/analysis_service.hpp"
#include "semantics_av/daemon/client.hpp"
#include "semantics_av/format/html_formatter.hpp"
#include "semantics_av/format/console_formatter.hpp"
#include "semantics_av/format/markdown_formatter.hpp"
#include "semantics_av/format/json_formatter.hpp"
#include "semantics_av/report/storage.hpp"
#include "semantics_av/config/wizard.hpp"
#include <iostream>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <pwd.h>

namespace semantics_av {
namespace cli {

AnalyzeCommand::AnalyzeCommand() 
    : was_called_(false), 
      language_(constants::languages::DEFAULT), 
      format_(OutputFormat::CONSOLE),
      no_report_(false),
      no_daemon_(false),
      no_save_(false) {}

void AnalyzeCommand::setup(CLI::App* subcommand) {
    subcommand_ = subcommand;
    
    subcommand->add_option("target", target_path_, "File to analyze")
               ->required()
               ->check(CLI::ExistingFile);
    
    auto supported_languages = constants::languages::SUPPORTED;
    std::set<std::string> language_set(supported_languages.begin(), supported_languages.end());
    
    subcommand->add_option("-l,--language", language_, 
                          "Report language: en, ko, ja, zh, es, fr, de, it, pt, ru, ar (default: en)")
               ->check(CLI::IsMember(language_set));
    
    std::map<std::string, OutputFormat> format_map{
        {"console", OutputFormat::CONSOLE},
        {"json", OutputFormat::JSON},
        {"html", OutputFormat::HTML},
        {"markdown", OutputFormat::MARKDOWN}
    };
    
    subcommand->add_option("-f,--format", format_, 
                          "Output format: console, json, html, markdown (default: console)")
               ->transform(CLI::CheckedTransformer(format_map, CLI::ignore_case));
    
    subcommand->add_option("-o,--output", output_path_, 
                          "Output file path (optional, defaults vary by format)");
    
    subcommand->add_flag("-r,--no-report", no_report_, 
                        "Skip natural language report generation");
    
    subcommand->add_flag("-d,--no-daemon", no_daemon_,
                        "Don't use daemon even if running");
    
    subcommand->add_flag("-s,--no-save", no_save_,
                        "Don't save report to storage");
    
    subcommand->add_option("--report-dir", report_dir_,
                          "Custom report directory");
    
    subcommand->callback([this]() { was_called_ = true; });
}

bool AnalyzeCommand::wasCalled() const {
    return was_called_;
}

bool AnalyzeCommand::canAccessPath(const std::filesystem::path& path) {
    return access(path.c_str(), R_OK) == 0;
}

int AnalyzeCommand::execute() {
    auto& config = common::Config::instance().global();
    auto& path_manager = common::PathManager::instance();
    
    if (!isLanguageSupported(language_)) {
        std::cerr << "Error: Unsupported language '" << language_ << "'" << std::endl;
        std::cerr << "Supported languages: en, ko, ja, zh, es, fr, de, it, pt, ru, ar" << std::endl;
        return 1;
    }
    
    target_path_ = std::filesystem::absolute(target_path_).string();
    
    if (!canAccessPath(target_path_)) {
        std::cerr << "Error: Permission denied: " << target_path_ << std::endl;
        std::cerr << "Try running with sudo: sudo semantics-av analyze " << target_path_ << std::endl;
        return 1;
    }
    
    bool use_daemon = !no_daemon_ && daemon::DaemonClient::isDaemonRunning();
    
    if (use_daemon) {
        return executeThroughDaemon();
    }
    
    if (config.api_key.empty()) {
        if (!diagnostics::canAccessApiKey()) {
            diagnostics::printApiKeyGuide(path_manager.isSystemMode());
            return 1;
        }
        
        std::cerr << "\n\033[31mAPI key required for cloud analysis\033[0m\n\n";
        
        std::string credentials_path = path_manager.getUserCredentialsFile();
        if (!credentials_path.empty() && !std::filesystem::exists(credentials_path)) {
            std::cerr << "\033[1mConfiguration methods:\033[0m\n\n";
            std::cerr << "  \033[1m1. Interactive wizard:\033[0m\n";
            std::cerr << "     semantics-av config init\n\n";
            
            std::cerr << "  \033[1m2. Quick setup with defaults:\033[0m\n";
            std::cerr << "     semantics-av config init --defaults\n\n";
            
            std::cerr << "  \033[1m3. Direct configuration:\033[0m\n";
            std::cerr << "     semantics-av config set api_key \"YOUR_KEY\"\n\n";
            
            std::cerr << "\033[36mGet API key:\033[0m " << constants::network::CONSOLE_URL << "\n\n";
            
            if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
                std::cout << "Run setup wizard now? [Y/n]: ";
                std::string response;
                std::getline(std::cin, response);
                
                if (response.empty() || response[0] == 'Y' || response[0] == 'y') {
                    config::ConfigWizard wizard;
                    return wizard.run(false);
                }
            }
        } else {
            std::cerr << "Configure API key:\n";
            std::cerr << "  semantics-av config set api_key \"YOUR_KEY\"\n\n";
            std::cerr << "Get API key: " << constants::network::CONSOLE_URL << "\n";
        }
        
        return 1;
    }
    
    return executeDirect();
}

int AnalyzeCommand::executeThroughDaemon() {
    daemon::DaemonClient client;
    if (!client.connect()) {
        std::cerr << "Error: Failed to connect to daemon, falling back to direct analysis" << std::endl;
        return executeDirect();
    }
    
    std::string analysis_language = no_report_ ? "" : language_;
    auto result = client.analyze(target_path_, analysis_language);
    
    if (!result) {
        std::cerr << "\n\033[31mError: Analysis request failed\033[0m\n\n";
        std::cerr << "Failed to communicate with daemon.\n\n";
        std::cerr << "\033[1mTroubleshooting:\033[0m\n";
        std::cerr << "  1. Check daemon status:\n";
        std::cerr << "     systemctl status semantics-av\n\n";
        std::cerr << "  2. View daemon logs:\n";
        std::cerr << "     tail -f " << common::Config::instance().global().log_file << "\n";
        return 1;
    }
    
    if (result->verdict == "error") {
        if (result->file_type.empty() || result->file_type == "unknown") {
            std::cerr << "\n\033[31mError: File format identification failed\033[0m\n\n";
            std::cerr << "This file cannot be analyzed. Possible reasons:\n";
            std::cerr << "  - File is corrupted or incomplete\n";
            std::cerr << "  - Unsupported file format\n\n";
            std::cerr << "Supported formats: pe, elf\n\n";
            std::cerr << "\033[1mFor detailed error information:\033[0m\n";
            std::cerr << "  tail -f " << common::Config::instance().global().log_file << "\n";
        } else {
            auto& config = common::Config::instance().global();
            if (config.api_key.empty()) {
                std::cerr << "\n\033[31mAPI key required for cloud analysis\033[0m\n\n";
                std::cerr << "The daemon needs an API key to perform cloud analysis.\n\n";
                std::cerr << "\033[1mConfigure daemon API key:\033[0m\n";
                std::cerr << "  sudo semantics-av config set api_key \"YOUR_KEY\"\n\n";
                std::cerr << "\033[36mGet API key:\033[0m " << constants::network::CONSOLE_URL << "\n";
            } else {
                std::cerr << "\n\033[31mError: Cloud analysis failed\033[0m\n\n";
                std::cerr << "Possible reasons:\n";
                std::cerr << "  - Network connectivity issue\n";
                std::cerr << "  - Service temporarily unavailable\n";
                std::cerr << "  - API key invalid or expired\n\n";
                std::cerr << "\033[1mCheck daemon logs for details:\033[0m\n";
                std::cerr << "  tail -f " << common::Config::instance().global().log_file << "\n";
            }
        }
        return 1;
    }
    
    return executeWithFormat(*result, 0, true);
}

int AnalyzeCommand::executeDirect() {
    try {
        auto& config = common::Config::instance().global();
        auto& path_manager = common::PathManager::instance();
        
        if (!diagnostics::hasModelFiles(config.models_path)) {
            diagnostics::printUpdateGuide(path_manager.isSystemMode(), config.models_path);
            return 1;
        }
        
        core::SemanticsAVEngine engine;
        if (!engine.initialize(config.base_path, config.api_key)) {
            std::cerr << "Error: Failed to initialize scan engine" << std::endl;
            
            if (!diagnostics::hasModelFiles(config.models_path)) {
                diagnostics::printUpdateGuide(path_manager.isSystemMode(), config.models_path);
            }
            
            return 1;
        }
        
        std::filesystem::path file_path(target_path_);
        
        std::error_code ec;
        size_t file_size = std::filesystem::file_size(file_path, ec);
        if (ec) {
            std::cerr << "Error: Cannot determine file size" << std::endl;
            return 1;
        }
        
        std::string analysis_language = no_report_ ? "" : language_;
        auto analysis_payload = engine.extractAnalysisPayload(file_path, analysis_language);
        
        if (analysis_payload.file_type.empty() || analysis_payload.file_type == "unknown") {
            std::cerr << "\n\033[31mError: File format identification failed\033[0m\n\n";
            std::cerr << "This file cannot be analyzed. Possible reasons:\n";
            std::cerr << "  - File is corrupted or incomplete\n";
            std::cerr << "  - Unsupported file format\n\n";
            std::cerr << "Supported formats: pe, elf\n";
            return 1;
        }
        
        std::cerr << "\nFile: " << file_path.filename().string() << "\n";
        std::cerr << "  Size: " << formatBytes(file_size) << "\n";
        std::cerr << "  Type: " << analysis_payload.file_type << "\n";
        std::cerr << "  Payload: " << formatBytes(analysis_payload.analysis_blob.size());
        
        double compression_ratio = (analysis_payload.analysis_blob.size() * 100.0) / file_size;
        std::cerr << " (" << std::fixed << std::setprecision(1) << compression_ratio << "% of original)\n\n";
        
        network::AnalysisService cloud_service(
            &engine, config.api_key, config.network_timeout);
        
        auto result = cloud_service.analyze(analysis_payload);
        
        if (result.verdict == "error") {
            std::cerr << "\n\033[31mError: Cloud analysis failed\033[0m\n\n";
            std::cerr << "Possible reasons:\n";
            std::cerr << "  - Network connectivity issue\n";
            std::cerr << "  - Service temporarily unavailable\n";
            std::cerr << "  - API key invalid or expired\n";
            return 1;
        }
        
        return executeWithFormat(result, file_size, false);
        
    } catch (const std::exception& e) {
        std::cerr << "Analysis error: " << e.what() << std::endl;
        return 1;
    }
}

int AnalyzeCommand::executeWithFormat(const network::AnalysisResult& result, size_t file_size, bool skip_save) {
    try {
        auto& config = common::Config::instance().global();
        
        if (!skip_save && config.report.enable_storage && !no_save_) {
            std::string custom_dir = report_dir_.empty() ? "" : report_dir_;
            report::ReportStorage storage(custom_dir);
            std::string report_id = storage.save(result, target_path_, language_, file_size);
            
            if (!report_id.empty()) {
                std::cout << "Report ID: " << report_id << std::endl;
                
                if (getuid() == 0) {
                    fixReportOwnership(report_id, custom_dir);
                }
            }
        }
        
        switch (format_) {
            case OutputFormat::CONSOLE: {
                if (output_path_.empty()) {
                    writeTextResult(result, std::cout);
                } else {
                    std::ofstream file_stream(output_path_);
                    if (!file_stream) {
                        std::cerr << "Error: Failed to create output file: " << output_path_ << std::endl;
                        return 1;
                    }
                    writeTextResult(result, file_stream);
                    file_stream.close();
                    std::cerr << "Output written to: " << std::filesystem::absolute(output_path_).string() << std::endl;
                }
                break;
            }
            
            case OutputFormat::JSON: {
                if (output_path_.empty()) {
                    writeJsonResult(result, std::cout);
                } else {
                    std::ofstream file_stream(output_path_);
                    if (!file_stream) {
                        std::cerr << "Error: Failed to create output file: " << output_path_ << std::endl;
                        return 1;
                    }
                    writeJsonResult(result, file_stream);
                    file_stream.close();
                    std::cerr << "Output written to: " << std::filesystem::absolute(output_path_).string() << std::endl;
                }
                break;
            }
            
            case OutputFormat::HTML: {
                std::string html_content = generateHtmlResult(result);
                
                std::string effective_output_path;
                if (output_path_.empty()) {
                    std::filesystem::path base_path(target_path_);
                    std::string basename = base_path.stem().string();
                    effective_output_path = basename + ".html";
                } else {
                    effective_output_path = output_path_;
                }
                
                std::filesystem::path output_file_path(effective_output_path);
                if (output_file_path.has_parent_path()) {
                    std::filesystem::create_directories(output_file_path.parent_path());
                }
                
                std::ofstream file_stream(effective_output_path);
                if (!file_stream) {
                    std::cerr << "Error: Failed to create output file: " << effective_output_path << std::endl;
                    return 1;
                }
                
                file_stream << html_content;
                file_stream.close();
                
                std::string abs_path = std::filesystem::absolute(effective_output_path).string();
                std::cerr << "HTML report saved to: " << abs_path << std::endl;
                std::cerr << "Open in browser: file://" << abs_path << std::endl;
                break;
            }
            
            case OutputFormat::MARKDOWN: {
                std::string markdown_content = generateMarkdownResult(result);
                
                std::string effective_output_path;
                if (output_path_.empty()) {
                    std::filesystem::path base_path(target_path_);
                    std::string basename = base_path.stem().string();
                    effective_output_path = basename + ".md";
                } else {
                    effective_output_path = output_path_;
                }
                
                std::filesystem::path output_file_path(effective_output_path);
                if (output_file_path.has_parent_path()) {
                    std::filesystem::create_directories(output_file_path.parent_path());
                }
                
                std::ofstream file_stream(effective_output_path);
                if (!file_stream) {
                    std::cerr << "Error: Failed to create output file: " << effective_output_path << std::endl;
                    return 1;
                }
                
                file_stream << markdown_content;
                file_stream.close();
                
                std::string abs_path = std::filesystem::absolute(effective_output_path).string();
                std::cerr << "Markdown report saved to: " << abs_path << std::endl;
                break;
            }
        }
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error writing output: " << e.what() << std::endl;
        return 1;
    }
}

void AnalyzeCommand::writeJsonResult(const network::AnalysisResult& result, std::ostream& out) {
    auto json = format::JsonFormatter::format(result);
    out << json.dump(2) << std::endl;
}

void AnalyzeCommand::writeTextResult(const network::AnalysisResult& result, std::ostream& out) {
    format::ConsoleFormatter formatter(isatty(STDOUT_FILENO));
    formatter.format(result, out);
}

std::string AnalyzeCommand::generateHtmlResult(const network::AnalysisResult& result) {
    format::HtmlFormatter formatter;
    return formatter.format(result);
}

std::string AnalyzeCommand::generateMarkdownResult(const network::AnalysisResult& result) {
    format::MarkdownFormatter formatter;
    return formatter.format(result);
}

std::string AnalyzeCommand::generateAutoFilename(const std::string& target, const std::string& extension) {
    std::filesystem::path path(target);
    std::string basename = path.stem().string();
    return basename + extension;
}

bool AnalyzeCommand::isLanguageSupported(const std::string& lang) const {
    return constants::languages::isSupported(lang);
}

std::string AnalyzeCommand::formatBytes(size_t bytes) const {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit < 3) {
        size /= 1024.0;
        unit++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << size << units[unit];
    return oss.str();
}

void AnalyzeCommand::fixReportOwnership(const std::string& report_id, const std::string& report_dir) {
    auto& path_manager = common::PathManager::instance();
    
    report::ReportStorage storage(report_dir);
    std::string reports_dir = storage.getReportsDir();
    std::string report_file = reports_dir + "/" + report_id + ".json";
    
    if (!std::filesystem::exists(report_file)) {
        return;
    }
    
    if (path_manager.isSystemMode()) {
        struct passwd* pw = getpwnam(constants::system::DAEMON_USER);
        if (!pw) {
            common::Logger::instance().warn(
                "[AnalyzeCommand] Daemon user not found | user={}", 
                constants::system::DAEMON_USER);
            return;
        }
        
        if (chown(report_file.c_str(), pw->pw_uid, pw->pw_gid) == 0) {
            common::Logger::instance().debug(
                "[AnalyzeCommand] Report ownership fixed | file={}", report_file);
        } else {
            common::Logger::instance().warn(
                "[AnalyzeCommand] Failed to chown report | file={} | error={}", 
                report_file, strerror(errno));
        }
    }
}

}}