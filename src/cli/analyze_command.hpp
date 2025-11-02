#pragma once

#include "main_command.hpp"
#include "semantics_av/network/client.hpp"
#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>
#include <string>

namespace semantics_av {
namespace cli {

class AnalyzeCommand : public MainCommand {
public:
    enum class OutputFormat {
        CONSOLE,
        JSON,
        HTML,
        MARKDOWN
    };

    AnalyzeCommand();
    
    void setup(CLI::App* subcommand);
    bool wasCalled() const;
    int execute();

private:
    bool was_called_;
    std::string target_path_;
    std::string language_;
    OutputFormat format_;
    std::string output_path_;
    bool no_report_;
    bool no_daemon_;
    bool no_save_;
    std::string report_dir_;
    
    CLI::App* subcommand_;
    
    int executeThroughDaemon();
    int executeDirect();
    int executeWithFormat(const network::AnalysisResult& result, size_t file_size = 0, bool skip_save = false);
    
    bool canAccessPath(const std::filesystem::path& path);
    void writeJsonResult(const network::AnalysisResult& result, std::ostream& out);
    void writeTextResult(const network::AnalysisResult& result, std::ostream& out);
    std::string generateHtmlResult(const network::AnalysisResult& result);
    std::string generateMarkdownResult(const network::AnalysisResult& result);
    
    std::string generateAutoFilename(const std::string& target, const std::string& extension);
    bool isLanguageSupported(const std::string& lang) const;
    
    std::string formatBytes(size_t bytes) const;
};

}}