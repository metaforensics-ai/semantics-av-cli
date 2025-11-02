#pragma once

#include "../common/types.hpp"
#include "scanner.hpp"
#include <string>
#include <ostream>

namespace semantics_av {
namespace scan {

enum class OutputFormat {
    TEXT,
    JSON
};

class ResultFormatter {
public:
    explicit ResultFormatter(OutputFormat format = OutputFormat::TEXT);
    
    void formatScanResult(const common::ScanMetadata& result, std::ostream& out);
    void formatScanSummary(const ScanSummary& summary, std::ostream& out);
    
    void setColorsEnabled(bool enabled) { colors_enabled_ = enabled; }
    void setVerbose(bool verbose) { verbose_ = verbose; }

private:
    OutputFormat format_;
    bool colors_enabled_ = true;
    bool verbose_ = false;
    
    void formatTextResult(const common::ScanMetadata& result, std::ostream& out);
    void formatJsonResult(const common::ScanMetadata& result, std::ostream& out);
    void formatTextSummary(const ScanSummary& summary, std::ostream& out);
    void formatJsonSummary(const ScanSummary& summary, std::ostream& out);
    
    std::string colorize(const std::string& text, const std::string& color);
    std::string formatFileSize(size_t bytes);
    std::string formatDuration(std::chrono::milliseconds ms);
};

}}