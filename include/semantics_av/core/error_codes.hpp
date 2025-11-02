#pragma once

#include "../common/error_framework.hpp"
#include <semantics_av/semantics_av.hpp>
#include <unordered_map>

namespace semantics_av {
namespace core {

enum class CoreErrorCode {
    ENGINE_NOT_INITIALIZED = 100,
    ENGINE_INITIALIZATION_FAILED = 101,
    ENGINE_ALREADY_INITIALIZED = 102,
    
    MODEL_NOT_FOUND = 200,
    MODEL_LOAD_FAILED = 201,
    MODEL_CORRUPTED = 202,
    MODEL_SIGNATURE_INVALID = 203,
    MODEL_INCOMPATIBLE_VERSION = 204,
    
    SCAN_FILE_NOT_FOUND = 300,
    SCAN_FILE_NOT_ACCESSIBLE = 301,
    SCAN_FILE_TOO_LARGE = 302,
    SCAN_FILE_EMPTY = 303,
    SCAN_TIMEOUT = 304,
    SCAN_UNSUPPORTED_FORMAT = 305,
    
    ANALYSIS_EXTRACTION_FAILED = 400,
    ANALYSIS_PAYLOAD_EMPTY = 401,
    ANALYSIS_PAYLOAD_INVALID = 402,
    
    SDK_INTERNAL_ERROR = 500,
    SDK_INFERENCE_FAILED = 501,
    SDK_MEMORY_ERROR = 502
};

CoreErrorCode mapSdkResult(semantics_av::Result sdk_result);

using CoreErrorCodeHelper = common::ErrorRegistry<CoreErrorCode>;

}
}

namespace semantics_av {
namespace common {

template<>
inline const std::unordered_map<core::CoreErrorCode, ErrorInfo<core::CoreErrorCode>>& 
ErrorRegistry<core::CoreErrorCode>::getInfoMap() {
    static const std::unordered_map<core::CoreErrorCode, ErrorInfo<core::CoreErrorCode>> map = {
        {core::CoreErrorCode::ENGINE_NOT_INITIALIZED, {
            core::CoreErrorCode::ENGINE_NOT_INITIALIZED,
            "ENGINE_NOT_INITIALIZED",
            "Engine not initialized"
        }},
        {core::CoreErrorCode::ENGINE_INITIALIZATION_FAILED, {
            core::CoreErrorCode::ENGINE_INITIALIZATION_FAILED,
            "ENGINE_INITIALIZATION_FAILED",
            "Engine initialization failed"
        }},
        {core::CoreErrorCode::ENGINE_ALREADY_INITIALIZED, {
            core::CoreErrorCode::ENGINE_ALREADY_INITIALIZED,
            "ENGINE_ALREADY_INITIALIZED",
            "Engine already initialized"
        }},
        {core::CoreErrorCode::MODEL_NOT_FOUND, {
            core::CoreErrorCode::MODEL_NOT_FOUND,
            "MODEL_NOT_FOUND",
            "Model file not found"
        }},
        {core::CoreErrorCode::MODEL_LOAD_FAILED, {
            core::CoreErrorCode::MODEL_LOAD_FAILED,
            "MODEL_LOAD_FAILED",
            "Model loading failed"
        }},
        {core::CoreErrorCode::MODEL_CORRUPTED, {
            core::CoreErrorCode::MODEL_CORRUPTED,
            "MODEL_CORRUPTED",
            "Model file corrupted"
        }},
        {core::CoreErrorCode::MODEL_SIGNATURE_INVALID, {
            core::CoreErrorCode::MODEL_SIGNATURE_INVALID,
            "MODEL_SIGNATURE_INVALID",
            "Model signature invalid"
        }},
        {core::CoreErrorCode::MODEL_INCOMPATIBLE_VERSION, {
            core::CoreErrorCode::MODEL_INCOMPATIBLE_VERSION,
            "MODEL_INCOMPATIBLE_VERSION",
            "Model version incompatible"
        }},
        {core::CoreErrorCode::SCAN_FILE_NOT_FOUND, {
            core::CoreErrorCode::SCAN_FILE_NOT_FOUND,
            "SCAN_FILE_NOT_FOUND",
            "File not found"
        }},
        {core::CoreErrorCode::SCAN_FILE_NOT_ACCESSIBLE, {
            core::CoreErrorCode::SCAN_FILE_NOT_ACCESSIBLE,
            "SCAN_FILE_NOT_ACCESSIBLE",
            "File not accessible"
        }},
        {core::CoreErrorCode::SCAN_FILE_TOO_LARGE, {
            core::CoreErrorCode::SCAN_FILE_TOO_LARGE,
            "SCAN_FILE_TOO_LARGE",
            "File too large"
        }},
        {core::CoreErrorCode::SCAN_FILE_EMPTY, {
            core::CoreErrorCode::SCAN_FILE_EMPTY,
            "SCAN_FILE_EMPTY",
            "File is empty"
        }},
        {core::CoreErrorCode::SCAN_TIMEOUT, {
            core::CoreErrorCode::SCAN_TIMEOUT,
            "SCAN_TIMEOUT",
            "Scan operation timed out"
        }},
        {core::CoreErrorCode::SCAN_UNSUPPORTED_FORMAT, {
            core::CoreErrorCode::SCAN_UNSUPPORTED_FORMAT,
            "SCAN_UNSUPPORTED_FORMAT",
            "Unsupported file format"
        }},
        {core::CoreErrorCode::ANALYSIS_EXTRACTION_FAILED, {
            core::CoreErrorCode::ANALYSIS_EXTRACTION_FAILED,
            "ANALYSIS_EXTRACTION_FAILED",
            "Analysis payload extraction failed"
        }},
        {core::CoreErrorCode::ANALYSIS_PAYLOAD_EMPTY, {
            core::CoreErrorCode::ANALYSIS_PAYLOAD_EMPTY,
            "ANALYSIS_PAYLOAD_EMPTY",
            "Analysis payload is empty"
        }},
        {core::CoreErrorCode::ANALYSIS_PAYLOAD_INVALID, {
            core::CoreErrorCode::ANALYSIS_PAYLOAD_INVALID,
            "ANALYSIS_PAYLOAD_INVALID",
            "Analysis payload is invalid"
        }},
        {core::CoreErrorCode::SDK_INTERNAL_ERROR, {
            core::CoreErrorCode::SDK_INTERNAL_ERROR,
            "SDK_INTERNAL_ERROR",
            "SDK internal error"
        }},
        {core::CoreErrorCode::SDK_INFERENCE_FAILED, {
            core::CoreErrorCode::SDK_INFERENCE_FAILED,
            "SDK_INFERENCE_FAILED",
            "SDK inference failed"
        }},
        {core::CoreErrorCode::SDK_MEMORY_ERROR, {
            core::CoreErrorCode::SDK_MEMORY_ERROR,
            "SDK_MEMORY_ERROR",
            "SDK memory error"
        }}
    };
    return map;
}

}
}