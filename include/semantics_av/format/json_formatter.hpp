#pragma once

#include "../network/client.hpp"
#include <nlohmann/json.hpp>

namespace semantics_av {
namespace format {

class JsonFormatter {
public:
    static nlohmann::json format(const network::AnalysisResult& result);

private:
    static nlohmann::json formatLabelStatistics(const network::LabelStatistics& stats);
    static nlohmann::json formatSignatureStatistics(const network::SignatureStatistics& stats);
    static nlohmann::json formatIntelligence(const network::Intelligence& intelligence);
    static nlohmann::json formatSimilarSample(const network::SimilarSample& sample);
};

}}