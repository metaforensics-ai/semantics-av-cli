#pragma once

#include "../common/config.hpp"

namespace semantics_av {
namespace daemon {

struct ReloadableConfig {
    std::string api_key;
    int network_timeout;
    common::LogLevel log_level;
    bool auto_update;
    
    bool networkConfigChanged(const ReloadableConfig& other) const {
        return api_key != other.api_key ||
               network_timeout != other.network_timeout;
    }
};

}}