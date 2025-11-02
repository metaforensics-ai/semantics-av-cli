#pragma once

#include <semantics_av/semantics_av.hpp>
#include <string>

namespace semantics_av {
namespace common {

inline std::string getSDKVersion() {
    return semantics_av::SemanticsAV::getVersion();
}

}
}