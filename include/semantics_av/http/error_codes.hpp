#pragma once

#include <semantics_av/semantics_av.hpp>
#include <string>
#include <unordered_map>

namespace semantics_av {

namespace core {
enum class CoreErrorCode;
}

namespace http {

enum class ErrorCode {
    REQUEST_INVALID_ENDPOINT,
    REQUEST_METHOD_NOT_ALLOWED,
    REQUEST_MISSING_PARAMETER,
    REQUEST_INVALID_PARAMETER,
    
    FILE_NOT_PROVIDED,
    FILE_TOO_LARGE,
    FILE_SAVE_FAILED,
    FILE_NOT_FOUND,
    FILE_NOT_ACCESSIBLE,
    FILE_EMPTY,
    
    SCAN_ENGINE_NOT_INITIALIZED,
    SCAN_FAILED,
    SCAN_TIMEOUT,
    SCAN_UNSUPPORTED_FORMAT,
    SCAN_FILE_TOO_LARGE,
    
    ANALYSIS_API_KEY_REQUIRED,
    ANALYSIS_UNSUPPORTED_FILE_TYPE,
    ANALYSIS_PAYLOAD_EMPTY,
    ANALYSIS_PAYLOAD_INVALID,
    ANALYSIS_PAYLOAD_EXTRACTION_FAILED,
    ANALYSIS_CLOUD_FAILED,
    ANALYSIS_INVALID_LANGUAGE,
    ANALYSIS_NETWORK_TIMEOUT,
    ANALYSIS_NETWORK_CONNECTION_FAILED,
    ANALYSIS_API_RATE_LIMIT,
    ANALYSIS_API_INVALID_RESPONSE,
    
    MODEL_NOT_FOUND,
    MODEL_LOAD_FAILED,
    MODEL_CORRUPTED,
    MODEL_SIGNATURE_INVALID,
    MODEL_INCOMPATIBLE_VERSION,
    
    ENGINE_INITIALIZATION_FAILED,
    ENGINE_ALREADY_INITIALIZED,
    
    SDK_INTERNAL_ERROR,
    SDK_INFERENCE_FAILED,
    SDK_MEMORY_ERROR,
    
    SYSTEM_INTERNAL_ERROR,
    SYSTEM_SERVICE_UNAVAILABLE
};

struct ErrorInfo {
    ErrorCode code;
    const char* code_str;
    int http_status;
    const char* default_message;
};

class ErrorCodeHelper {
public:
    static const ErrorInfo& getInfo(ErrorCode code);
    static const char* toString(ErrorCode code);
    static int getHttpStatus(ErrorCode code);
    static const char* getDefaultMessage(ErrorCode code);
    
    static ErrorCode mapSdkResult(semantics_av::Result result);
    static ErrorCode mapCoreErrorCode(core::CoreErrorCode core_code);
};

}}