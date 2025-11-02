#pragma once

#include "error_codes.hpp"
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <string>

namespace semantics_av {
namespace http {

class HttpResponse {
public:
    static void sendSuccess(httplib::Response& res, const nlohmann::json& data);
    
    static void sendError(httplib::Response& res, ErrorCode code);
    
    static void sendError(httplib::Response& res, 
                         ErrorCode code,
                         const nlohmann::json& details);
    
    static void sendError(httplib::Response& res, 
                         ErrorCode code,
                         const std::string& custom_message,
                         const nlohmann::json& details = nlohmann::json());
};

}}