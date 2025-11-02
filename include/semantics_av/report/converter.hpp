#pragma once

#include "../network/client.hpp"
#include <string>
#include <ostream>

namespace semantics_av {
namespace report {

enum class ConvertFormat {
    CONSOLE,
    JSON,
    HTML,
    MARKDOWN
};

class ReportConverter {
public:
    ReportConverter();
    
    bool convert(const network::AnalysisResult& result,
                 ConvertFormat format,
                 std::ostream& out);
    
    bool convertFile(const std::string& report_id,
                     ConvertFormat format,
                     const std::string& output_path);

private:
    std::string formatToString(ConvertFormat format);
};

}}