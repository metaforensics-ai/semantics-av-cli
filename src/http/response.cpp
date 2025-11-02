#include "semantics_av/http/response.hpp"

namespace semantics_av {
namespace http {

void HttpResponse::sendSuccess(httplib::Response& res, const nlohmann::json& data) {
    nlohmann::json response;
    response["success"] = true;
    response["data"] = data;
    res.status = 200;
    res.set_content(response.dump(2), "application/json");
}

void HttpResponse::sendError(httplib::Response& res, ErrorCode code) {
    const auto& info = ErrorCodeHelper::getInfo(code);
    nlohmann::json response;
    response["success"] = false;
    response["error"]["code"] = info.code_str;
    response["error"]["message"] = info.default_message;
    res.status = info.http_status;
    res.set_content(response.dump(2), "application/json");
}

void HttpResponse::sendError(httplib::Response& res, ErrorCode code, const nlohmann::json& details) {
    const auto& info = ErrorCodeHelper::getInfo(code);
    nlohmann::json response;
    response["success"] = false;
    response["error"]["code"] = info.code_str;
    response["error"]["message"] = info.default_message;
    response["error"]["details"] = details;
    res.status = info.http_status;
    res.set_content(response.dump(2), "application/json");
}

void HttpResponse::sendError(httplib::Response& res, ErrorCode code, const std::string& custom_message, const nlohmann::json& details) {
    const auto& info = ErrorCodeHelper::getInfo(code);
    nlohmann::json response;
    response["success"] = false;
    response["error"]["code"] = info.code_str;
    response["error"]["message"] = custom_message;
    if (!details.is_null()) {
        response["error"]["details"] = details;
    }
    res.status = info.http_status;
    res.set_content(response.dump(2), "application/json");
}

}}