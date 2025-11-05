#pragma once

#include <string>

namespace semantics_av {
namespace diagnostics {

bool hasModelFiles(const std::string& models_path);
bool canAccessApiKey();

void printUpdateGuide(bool is_system_mode, const std::string& models_path);
void printApiKeyGuide(bool is_system_mode);
void printPermissionGuide(const std::string& resource, 
                          const std::string& command,
                          bool is_system_mode);

}}