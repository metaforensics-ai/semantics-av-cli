#include "semantics_av/http/error_codes.hpp"
#include "semantics_av/core/error_codes.hpp"

namespace semantics_av {
namespace http {

static const std::unordered_map<ErrorCode, ErrorInfo> ERROR_INFO_MAP = {
    {ErrorCode::REQUEST_INVALID_ENDPOINT, {
        ErrorCode::REQUEST_INVALID_ENDPOINT,
        "REQUEST_INVALID_ENDPOINT",
        404,
        "The requested endpoint does not exist"
    }},
    {ErrorCode::REQUEST_METHOD_NOT_ALLOWED, {
        ErrorCode::REQUEST_METHOD_NOT_ALLOWED,
        "REQUEST_METHOD_NOT_ALLOWED",
        405,
        "HTTP method not allowed for this endpoint"
    }},
    {ErrorCode::REQUEST_MISSING_PARAMETER, {
        ErrorCode::REQUEST_MISSING_PARAMETER,
        "REQUEST_MISSING_PARAMETER",
        400,
        "Required parameter is missing"
    }},
    {ErrorCode::REQUEST_INVALID_PARAMETER, {
        ErrorCode::REQUEST_INVALID_PARAMETER,
        "REQUEST_INVALID_PARAMETER",
        400,
        "Invalid parameter value"
    }},
    {ErrorCode::FILE_NOT_PROVIDED, {
        ErrorCode::FILE_NOT_PROVIDED,
        "FILE_NOT_PROVIDED",
        400,
        "No file provided in request"
    }},
    {ErrorCode::FILE_TOO_LARGE, {
        ErrorCode::FILE_TOO_LARGE,
        "FILE_TOO_LARGE",
        413,
        "File exceeds maximum size limit"
    }},
    {ErrorCode::FILE_SAVE_FAILED, {
        ErrorCode::FILE_SAVE_FAILED,
        "FILE_SAVE_FAILED",
        500,
        "Failed to save uploaded file"
    }},
    {ErrorCode::FILE_NOT_FOUND, {
        ErrorCode::FILE_NOT_FOUND,
        "FILE_NOT_FOUND",
        404,
        "File not found"
    }},
    {ErrorCode::FILE_NOT_ACCESSIBLE, {
        ErrorCode::FILE_NOT_ACCESSIBLE,
        "FILE_NOT_ACCESSIBLE",
        403,
        "File not accessible"
    }},
    {ErrorCode::FILE_EMPTY, {
        ErrorCode::FILE_EMPTY,
        "FILE_EMPTY",
        400,
        "File is empty"
    }},
    {ErrorCode::SCAN_ENGINE_NOT_INITIALIZED, {
        ErrorCode::SCAN_ENGINE_NOT_INITIALIZED,
        "SCAN_ENGINE_NOT_INITIALIZED",
        500,
        "Scan engine is not initialized"
    }},
    {ErrorCode::SCAN_FAILED, {
        ErrorCode::SCAN_FAILED,
        "SCAN_FAILED",
        500,
        "File scan operation failed"
    }},
    {ErrorCode::SCAN_TIMEOUT, {
        ErrorCode::SCAN_TIMEOUT,
        "SCAN_TIMEOUT",
        500,
        "Scan operation timed out"
    }},
    {ErrorCode::SCAN_UNSUPPORTED_FORMAT, {
        ErrorCode::SCAN_UNSUPPORTED_FORMAT,
        "SCAN_UNSUPPORTED_FORMAT",
        400,
        "Unsupported file format"
    }},
    {ErrorCode::SCAN_FILE_TOO_LARGE, {
        ErrorCode::SCAN_FILE_TOO_LARGE,
        "SCAN_FILE_TOO_LARGE",
        413,
        "File too large for scanning"
    }},
    {ErrorCode::ANALYSIS_API_KEY_REQUIRED, {
        ErrorCode::ANALYSIS_API_KEY_REQUIRED,
        "ANALYSIS_API_KEY_REQUIRED",
        400,
        "API key required for cloud analysis"
    }},
    {ErrorCode::ANALYSIS_UNSUPPORTED_FILE_TYPE, {
        ErrorCode::ANALYSIS_UNSUPPORTED_FILE_TYPE,
        "ANALYSIS_UNSUPPORTED_FILE_TYPE",
        400,
        "File type is not supported for analysis"
    }},
    {ErrorCode::ANALYSIS_PAYLOAD_EMPTY, {
        ErrorCode::ANALYSIS_PAYLOAD_EMPTY,
        "ANALYSIS_PAYLOAD_EMPTY",
        500,
        "Analysis payload extraction returned empty result"
    }},
    {ErrorCode::ANALYSIS_PAYLOAD_INVALID, {
        ErrorCode::ANALYSIS_PAYLOAD_INVALID,
        "ANALYSIS_PAYLOAD_INVALID",
        500,
        "Analysis payload has invalid format"
    }},
    {ErrorCode::ANALYSIS_PAYLOAD_EXTRACTION_FAILED, {
        ErrorCode::ANALYSIS_PAYLOAD_EXTRACTION_FAILED,
        "ANALYSIS_PAYLOAD_EXTRACTION_FAILED",
        500,
        "Failed to extract analysis payload from file"
    }},
    {ErrorCode::ANALYSIS_CLOUD_FAILED, {
        ErrorCode::ANALYSIS_CLOUD_FAILED,
        "ANALYSIS_CLOUD_FAILED",
        500,
        "Cloud analysis request failed"
    }},
    {ErrorCode::ANALYSIS_INVALID_LANGUAGE, {
        ErrorCode::ANALYSIS_INVALID_LANGUAGE,
        "ANALYSIS_INVALID_LANGUAGE",
        400,
        "Invalid language code specified"
    }},
    {ErrorCode::ANALYSIS_NETWORK_TIMEOUT, {
        ErrorCode::ANALYSIS_NETWORK_TIMEOUT,
        "ANALYSIS_NETWORK_TIMEOUT",
        504,
        "Network request timed out"
    }},
    {ErrorCode::ANALYSIS_NETWORK_CONNECTION_FAILED, {
        ErrorCode::ANALYSIS_NETWORK_CONNECTION_FAILED,
        "ANALYSIS_NETWORK_CONNECTION_FAILED",
        503,
        "Failed to connect to analysis service"
    }},
    {ErrorCode::ANALYSIS_API_RATE_LIMIT, {
        ErrorCode::ANALYSIS_API_RATE_LIMIT,
        "ANALYSIS_API_RATE_LIMIT",
        429,
        "API rate limit exceeded"
    }},
    {ErrorCode::ANALYSIS_API_INVALID_RESPONSE, {
        ErrorCode::ANALYSIS_API_INVALID_RESPONSE,
        "ANALYSIS_API_INVALID_RESPONSE",
        502,
        "Received invalid response from analysis service"
    }},
    {ErrorCode::MODEL_NOT_FOUND, {
        ErrorCode::MODEL_NOT_FOUND,
        "MODEL_NOT_FOUND",
        500,
        "Required model not found"
    }},
    {ErrorCode::MODEL_LOAD_FAILED, {
        ErrorCode::MODEL_LOAD_FAILED,
        "MODEL_LOAD_FAILED",
        500,
        "Model loading failed"
    }},
    {ErrorCode::MODEL_CORRUPTED, {
        ErrorCode::MODEL_CORRUPTED,
        "MODEL_CORRUPTED",
        500,
        "Model file corrupted"
    }},
    {ErrorCode::MODEL_SIGNATURE_INVALID, {
        ErrorCode::MODEL_SIGNATURE_INVALID,
        "MODEL_SIGNATURE_INVALID",
        500,
        "Model signature validation failed"
    }},
    {ErrorCode::MODEL_INCOMPATIBLE_VERSION, {
        ErrorCode::MODEL_INCOMPATIBLE_VERSION,
        "MODEL_INCOMPATIBLE_VERSION",
        500,
        "Model version incompatible with engine"
    }},
    {ErrorCode::ENGINE_INITIALIZATION_FAILED, {
        ErrorCode::ENGINE_INITIALIZATION_FAILED,
        "ENGINE_INITIALIZATION_FAILED",
        500,
        "Engine initialization failed"
    }},
    {ErrorCode::ENGINE_ALREADY_INITIALIZED, {
        ErrorCode::ENGINE_ALREADY_INITIALIZED,
        "ENGINE_ALREADY_INITIALIZED",
        500,
        "Engine already initialized"
    }},
    {ErrorCode::SDK_INTERNAL_ERROR, {
        ErrorCode::SDK_INTERNAL_ERROR,
        "SDK_INTERNAL_ERROR",
        500,
        "Internal SDK error"
    }},
    {ErrorCode::SDK_INFERENCE_FAILED, {
        ErrorCode::SDK_INFERENCE_FAILED,
        "SDK_INFERENCE_FAILED",
        500,
        "SDK inference operation failed"
    }},
    {ErrorCode::SDK_MEMORY_ERROR, {
        ErrorCode::SDK_MEMORY_ERROR,
        "SDK_MEMORY_ERROR",
        500,
        "SDK memory allocation error"
    }},
    {ErrorCode::SYSTEM_INTERNAL_ERROR, {
        ErrorCode::SYSTEM_INTERNAL_ERROR,
        "SYSTEM_INTERNAL_ERROR",
        500,
        "Internal server error"
    }},
    {ErrorCode::SYSTEM_SERVICE_UNAVAILABLE, {
        ErrorCode::SYSTEM_SERVICE_UNAVAILABLE,
        "SYSTEM_SERVICE_UNAVAILABLE",
        503,
        "Service temporarily unavailable"
    }}
};

const ErrorInfo& ErrorCodeHelper::getInfo(ErrorCode code) {
    auto it = ERROR_INFO_MAP.find(code);
    if (it != ERROR_INFO_MAP.end()) {
        return it->second;
    }
    static const ErrorInfo fallback = {
        ErrorCode::SYSTEM_INTERNAL_ERROR,
        "SYSTEM_INTERNAL_ERROR",
        500,
        "Internal server error"
    };
    return fallback;
}

const char* ErrorCodeHelper::toString(ErrorCode code) {
    return getInfo(code).code_str;
}

int ErrorCodeHelper::getHttpStatus(ErrorCode code) {
    return getInfo(code).http_status;
}

const char* ErrorCodeHelper::getDefaultMessage(ErrorCode code) {
    return getInfo(code).default_message;
}

ErrorCode ErrorCodeHelper::mapSdkResult(semantics_av::Result result) {
    using R = semantics_av::Result;
    
    switch (result) {
        case R::UNSUPPORTED_FORMAT:
            return ErrorCode::ANALYSIS_UNSUPPORTED_FILE_TYPE;
            
        case R::CORRUPTED_DATA:
        case R::INVALID_FORMAT:
            return ErrorCode::ANALYSIS_PAYLOAD_INVALID;
            
        case R::FILE_NOT_FOUND:
            return ErrorCode::FILE_NOT_FOUND;
            
        case R::FILE_READ_ERROR:
            return ErrorCode::FILE_NOT_ACCESSIBLE;
            
        case R::MODEL_NOT_FOUND:
            return ErrorCode::MODEL_NOT_FOUND;
            
        case R::MODEL_LOAD_ERROR:
            return ErrorCode::MODEL_LOAD_FAILED;
            
        case R::MODEL_CORRUPTED:
            return ErrorCode::MODEL_CORRUPTED;
            
        case R::INFERENCE_ERROR:
            return ErrorCode::SDK_INFERENCE_FAILED;
            
        default:
            return ErrorCode::SYSTEM_INTERNAL_ERROR;
    }
}

ErrorCode ErrorCodeHelper::mapCoreErrorCode(core::CoreErrorCode core_code) {
    using C = core::CoreErrorCode;
    
    switch (core_code) {
        case C::ENGINE_NOT_INITIALIZED:
            return ErrorCode::SCAN_ENGINE_NOT_INITIALIZED;
        case C::ENGINE_INITIALIZATION_FAILED:
            return ErrorCode::ENGINE_INITIALIZATION_FAILED;
        case C::ENGINE_ALREADY_INITIALIZED:
            return ErrorCode::ENGINE_ALREADY_INITIALIZED;
            
        case C::MODEL_NOT_FOUND:
            return ErrorCode::MODEL_NOT_FOUND;
        case C::MODEL_LOAD_FAILED:
            return ErrorCode::MODEL_LOAD_FAILED;
        case C::MODEL_CORRUPTED:
            return ErrorCode::MODEL_CORRUPTED;
        case C::MODEL_SIGNATURE_INVALID:
            return ErrorCode::MODEL_SIGNATURE_INVALID;
        case C::MODEL_INCOMPATIBLE_VERSION:
            return ErrorCode::MODEL_INCOMPATIBLE_VERSION;
            
        case C::SCAN_FILE_NOT_FOUND:
            return ErrorCode::FILE_NOT_FOUND;
        case C::SCAN_FILE_NOT_ACCESSIBLE:
            return ErrorCode::FILE_NOT_ACCESSIBLE;
        case C::SCAN_FILE_TOO_LARGE:
            return ErrorCode::SCAN_FILE_TOO_LARGE;
        case C::SCAN_FILE_EMPTY:
            return ErrorCode::FILE_EMPTY;
        case C::SCAN_TIMEOUT:
            return ErrorCode::SCAN_TIMEOUT;
        case C::SCAN_UNSUPPORTED_FORMAT:
            return ErrorCode::SCAN_UNSUPPORTED_FORMAT;
            
        case C::ANALYSIS_EXTRACTION_FAILED:
            return ErrorCode::ANALYSIS_PAYLOAD_EXTRACTION_FAILED;
        case C::ANALYSIS_PAYLOAD_EMPTY:
            return ErrorCode::ANALYSIS_PAYLOAD_EMPTY;
        case C::ANALYSIS_PAYLOAD_INVALID:
            return ErrorCode::ANALYSIS_PAYLOAD_INVALID;
            
        case C::SDK_INTERNAL_ERROR:
            return ErrorCode::SDK_INTERNAL_ERROR;
        case C::SDK_INFERENCE_FAILED:
            return ErrorCode::SDK_INFERENCE_FAILED;
        case C::SDK_MEMORY_ERROR:
            return ErrorCode::SDK_MEMORY_ERROR;
            
        default:
            return ErrorCode::SYSTEM_INTERNAL_ERROR;
    }
}

}}