#include "semantics_av/common/types.hpp"
#include <sstream>

namespace semantics_av {
namespace common {

std::string to_string(ScanResult result) {
    switch (result) {
        case ScanResult::CLEAN: return "CLEAN";
        case ScanResult::MALICIOUS: return "MALICIOUS";
        case ScanResult::UNSUPPORTED: return "UNSUPPORTED";
        case ScanResult::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

std::string to_string(SecurityLevel level) {
    switch (level) {
        case SecurityLevel::ROOT: return "ROOT";
        case SecurityLevel::PRIVILEGED: return "PRIVILEGED";
        case SecurityLevel::USER: return "USER";
        case SecurityLevel::RESTRICTED: return "RESTRICTED";
        default: return "UNKNOWN";
    }
}

}}