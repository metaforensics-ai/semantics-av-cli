#include "semantics_av/report/converter.hpp"
#include "semantics_av/report/storage.hpp"
#include "semantics_av/format/console_formatter.hpp"
#include "semantics_av/format/html_formatter.hpp"
#include "semantics_av/format/markdown_formatter.hpp"
#include "semantics_av/format/json_formatter.hpp"
#include "semantics_av/common/logger.hpp"
#include <fstream>

namespace semantics_av {
namespace report {

ReportConverter::ReportConverter() = default;

bool ReportConverter::convert(const network::AnalysisResult& result,
                              ConvertFormat format,
                              std::ostream& out) {
    try {
        switch (format) {
            case ConvertFormat::CONSOLE: {
                semantics_av::format::ConsoleFormatter formatter(true);
                formatter.format(result, out);
                return true;
            }
            
            case ConvertFormat::JSON: {
                auto json = format::JsonFormatter::format(result);
                out << json.dump(2) << std::endl;
                return true;
            }
            
            case ConvertFormat::HTML: {
                semantics_av::format::HtmlFormatter formatter;
                std::string html = formatter.format(result);
                out << html;
                return true;
            }
            
            case ConvertFormat::MARKDOWN: {
                semantics_av::format::MarkdownFormatter formatter;
                std::string md = formatter.format(result);
                out << md;
                return true;
            }
        }
        
        return false;
        
    } catch (const std::exception& e) {
        common::Logger::instance().error("[ReportConverter] Conversion failed | error={}", e.what());
        return false;
    }
}

bool ReportConverter::convertFile(const std::string& report_id,
                                  ConvertFormat format,
                                  const std::string& output_path) {
    ReportStorage storage;
    auto result = storage.load(report_id);
    
    if (!result) {
        common::Logger::instance().error("[ReportConverter] Report not found | id={}", report_id);
        return false;
    }
    
    std::ofstream file(output_path);
    if (!file) {
        common::Logger::instance().error("[ReportConverter] Failed to create output file | path={}", 
                                        output_path);
        return false;
    }
    
    bool success = convert(*result, format, file);
    file.close();
    
    if (success) {
        common::Logger::instance().info("[ReportConverter] Converted | id={} | format={} | output={}", 
                                       report_id, formatToString(format), output_path);
    }
    
    return success;
}

std::string ReportConverter::formatToString(ConvertFormat format) {
    switch (format) {
        case ConvertFormat::CONSOLE: return "console";
        case ConvertFormat::JSON: return "json";
        case ConvertFormat::HTML: return "html";
        case ConvertFormat::MARKDOWN: return "markdown";
    }
    return "unknown";
}

}}