#pragma once

#include <nlohmann/json.hpp>
#include <string>

namespace semantics_av {
namespace format {

struct FlattenedAttribute {
    std::string path;
    std::string display_value;
    bool is_present;
    bool is_complex;
    nlohmann::json raw_value;
};

}
}